import importlib
from collections.abc import Mapping

from fastapi import Request
from starlette.types import Scope


def modules_available(*module_names: str) -> bool:
    for module_name in module_names:
        if not importlib.util.find_spec(module_name):
            break
    else:
        return True
    return False


def get_root_url(request: Request) -> str:
    return f"{get_root_url_low_level(request.headers, request.scope)}"


def get_root_url_low_level(request_headers: Mapping[str, str], scope: Scope) -> str:
    host = request_headers.get("x-forwarded-host", request_headers["host"])
    scheme = request_headers.get("x-forwarded-proto", scope["scheme"])
    root_path = scope.get("root_path", "")
    if root_path.endswith("/"):
        root_path = root_path[:-1]
    return f"{scheme}://{host}{root_path}"
