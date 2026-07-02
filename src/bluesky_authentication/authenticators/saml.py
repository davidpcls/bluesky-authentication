import importlib
from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Request
from starlette.responses import RedirectResponse

from ..protocols import ExternalAuthenticator, UserSessionState
from ..utils import modules_available


class SAMLResponseError(RuntimeError):
    """Raised when processing a SAML response fails."""


class SAMLAuthenticator(ExternalAuthenticator):
    """Authenticate users using a SAML identity provider callback flow."""

    def __init__(
        self,
        saml_settings: Mapping[str, Any],
        attribute_name: str,
        confirmation_message: str = "",
    ):
        self.saml_settings = saml_settings
        self.attribute_name = attribute_name
        self.confirmation_message = confirmation_message
        self.authorization_endpoint = "/login"

        router = APIRouter()

        if not modules_available("onelogin"):
            msg = "This SAMLAuthenticator requires 'python3-saml' to be installed."
            raise ModuleNotFoundError(msg)

        async def saml_login(request: Request) -> RedirectResponse:
            req = await prepare_saml_from_fastapi_request(request)
            onelogin_saml2_auth = self._load_onelogin_saml_auth()
            auth = onelogin_saml2_auth(req, self.saml_settings)
            callback_url = auth.login()
            return RedirectResponse(url=callback_url)

        router.add_api_route("/login", saml_login, methods=["GET"])

        self.include_routers = [router]

    @staticmethod
    def _load_onelogin_saml_auth() -> Any:
        module = importlib.import_module("onelogin.saml2.auth")
        return module.OneLogin_Saml2_Auth

    async def authenticate(self, request: Request) -> UserSessionState | None:
        if not modules_available("onelogin"):
            msg = (
                "This SAMLAuthenticator requires the module 'onelogin' to be installed."
            )
            raise ModuleNotFoundError(msg)
        onelogin_saml2_auth = self._load_onelogin_saml_auth()

        req = await prepare_saml_from_fastapi_request(request)
        auth = onelogin_saml2_auth(req, self.saml_settings)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            reason = auth.get_last_error_reason()
            msg = f"Error when processing SAML Response: {', '.join(errors)} {reason}"
            raise SAMLResponseError(msg)
        if auth.is_authenticated():
            attribute_as_list = auth.get_attributes()[self.attribute_name]
            if len(attribute_as_list) != 1:
                msg = f"Expected exactly one value for attribute {self.attribute_name!r}, got {len(attribute_as_list)}"
                raise SAMLResponseError(msg)
            return UserSessionState(attribute_as_list[0], {})
        return None


async def prepare_saml_from_fastapi_request(request: Request) -> Mapping[str, Any]:
    form_data = await request.form()
    # request.client may be None when the server is behind a proxy or in tests.
    client_host = request.client.host if request.client is not None else ""
    rv: dict[str, Any] = {
        "http_host": client_host,
        "server_port": request.url.port,
        "script_name": request.url.path,
        "post_data": {},
        "get_data": {},
    }
    if request.query_params:
        rv["get_data"] = (request.query_params,)
    if "SAMLResponse" in form_data:
        saml_response = form_data["SAMLResponse"]
        rv["post_data"]["SAMLResponse"] = saml_response
    if "RelayState" in form_data:
        relay_state = form_data["RelayState"]
        rv["post_data"]["RelayState"] = relay_state
    return rv
