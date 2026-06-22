from typing import Mapping, Optional

from fastapi import APIRouter, Request
from starlette.responses import RedirectResponse

from ..protocols import ExternalAuthenticator, UserSessionState
from ..utils import modules_available


class SAMLAuthenticator(ExternalAuthenticator):
    def __init__(
        self,
        saml_settings,
        attribute_name: str,
        confirmation_message: str = "",
    ):
        self.saml_settings = saml_settings
        self.attribute_name = attribute_name
        self.confirmation_message = confirmation_message
        self.authorization_endpoint = "/login"

        router = APIRouter()

        if not modules_available("onelogin"):
            raise ModuleNotFoundError(
                "This SAMLAuthenticator requires 'python3-saml' to be installed."
            )

        from onelogin.saml2.auth import OneLogin_Saml2_Auth

        @router.get("/login")
        async def saml_login(request: Request) -> RedirectResponse:
            req = await prepare_saml_from_fastapi_request(request)
            auth = OneLogin_Saml2_Auth(req, self.saml_settings)
            callback_url = auth.login()
            return RedirectResponse(url=callback_url)

        self.include_routers = [router]

    async def authenticate(self, request: Request) -> Optional[UserSessionState]:
        if not modules_available("onelogin"):
            raise ModuleNotFoundError(
                "This SAMLAuthenticator requires the module 'oneline' to be installed."
            )
        from onelogin.saml2.auth import OneLogin_Saml2_Auth

        req = await prepare_saml_from_fastapi_request(request)
        auth = OneLogin_Saml2_Auth(req, self.saml_settings)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            raise Exception(
                "Error when processing SAML Response: %s %s"
                % (", ".join(errors), auth.get_last_error_reason())
            )
        if auth.is_authenticated():
            attribute_as_list = auth.get_attributes()[self.attribute_name]
            assert len(attribute_as_list) == 1
            return UserSessionState(attribute_as_list[0], {})
        else:
            return None


async def prepare_saml_from_fastapi_request(request: Request) -> Mapping[str, str]:
    form_data = await request.form()
    rv = {
        "http_host": request.client.host,
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
