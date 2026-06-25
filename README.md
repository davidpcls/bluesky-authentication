# bluesky-authentication

[![Actions Status][actions-badge]][actions-link]
[![Documentation Status][rtd-badge]][rtd-link]

[![PyPI version][pypi-version]][pypi-link]
[![Conda-Forge][conda-badge]][conda-link]
[![PyPI platforms][pypi-platforms]][pypi-link]

[![GitHub Discussion][github-discussions-badge]][github-discussions-link]

[![Coverage][coverage-badge]][coverage-link]

<!-- SPHINX-START -->

`bluesky-authentication` provides shared authenticator implementations and
protocol interfaces for Bluesky web services.

It centralizes authentication logic that was previously duplicated across
projects, including Tiled and bluesky-httpserver.

## Install

Core package:

```bash
pip install bluesky-authentication
```

Optional authenticators require optional dependencies:

- LDAP: `pip install "bluesky-authentication[ldap]"`
- PAM: `pip install "bluesky-authentication[pam]"`
- SAML: `pip install "bluesky-authentication[saml]"`

## Basic imports

Import authenticators from `bluesky_authentication.authenticators`:

```python
from bluesky_authentication.authenticators import (
    DictionaryAuthenticator,
    DummyAuthenticator,
    EntraAuthenticator,
    LDAPAuthenticator,
    OIDCAuthenticator,
    PAMAuthenticator,
    ProxiedOIDCAuthenticator,
    SAMLAuthenticator,
)
```

Import protocol types from `bluesky_authentication.protocols`:

```python
from bluesky_authentication.protocols import (
    ExternalAuthenticator,
    InternalAuthenticator,
    UserSessionState,
)
```

## Authenticator usage shape

`InternalAuthenticator` implementations authenticate username/password:

```python
state = await internal_authenticator.authenticate(username, password)
if state is None:
    # Authentication failed
    ...
```

`ExternalAuthenticator` implementations authenticate from a web callback
request:

```python
state = await external_authenticator.authenticate(request)
if state is None:
    # Authentication failed
    ...
```

On success, authenticators return `UserSessionState(user_name, state_dict)`.

## Using import paths in service configuration

When wiring authenticators through YAML config, use canonical import paths from
this package:

```yaml
authentication:
  providers:
    - provider: toy
      authenticator: bluesky_authentication.authenticators:DictionaryAuthenticator
      args:
        users_to_passwords:
          alice: ${ALICE_PASSWORD}
```

The same pattern applies to all built-in authenticators, for example:

- `bluesky_authentication.authenticators:PAMAuthenticator`
- `bluesky_authentication.authenticators:LDAPAuthenticator`
- `bluesky_authentication.authenticators:OIDCAuthenticator`
- `bluesky_authentication.authenticators:EntraAuthenticator`

## Migrating from legacy import paths

Host projects may continue to support legacy paths for backward compatibility,
such as `tiled.authenticators:*` and `bluesky_httpserver.authenticators:*`.

New configurations should use `bluesky_authentication.authenticators:*`.

<!-- prettier-ignore-start -->
[actions-badge]:            https://github.com/davidpcls/bluesky-authentication/actions/workflows/ci.yml/badge.svg
[actions-link]:             https://github.com/davidpcls/bluesky-authentication/actions
[conda-badge]:              https://img.shields.io/conda/vn/conda-forge/bluesky-authentication
[conda-link]:               https://github.com/conda-forge/bluesky-authentication-feedstock
[github-discussions-badge]: https://img.shields.io/static/v1?label=Discussions&message=Ask&color=blue&logo=github
[github-discussions-link]:  https://github.com/davidpcls/bluesky-authentication/discussions
[pypi-link]:                https://pypi.org/project/bluesky-authentication/
[pypi-platforms]:           https://img.shields.io/pypi/pyversions/bluesky-authentication
[pypi-version]:             https://img.shields.io/pypi/v/bluesky-authentication
[rtd-badge]:                https://readthedocs.org/projects/bluesky-authentication/badge/?version=latest
[rtd-link]:                 https://bluesky-authentication.readthedocs.io/en/latest/?badge=latest
[coverage-badge]:           https://codecov.io/github/davidpcls/bluesky-authentication/branch/main/graph/badge.svg
[coverage-link]:            https://codecov.io/github/davidpcls/bluesky-authentication

<!-- prettier-ignore-end -->
