# Usage

This page covers the basics of importing and configuring authenticators from
`bluesky-authentication`.

## Canonical imports

Use authenticators from:

`bluesky_authentication.authenticators`

and protocol interfaces from:

`bluesky_authentication.protocols`

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
from bluesky_authentication.protocols import (
    ExternalAuthenticator,
    InternalAuthenticator,
    UserSessionState,
)
```

## Runtime contract

Internal authenticators validate username/password credentials:

```python
state = await authenticator.authenticate(username, password)
if state is None:
    # invalid credentials
    ...
```

External authenticators validate callback requests from an identity provider:

```python
state = await authenticator.authenticate(request)
if state is None:
    # callback/token verification failed
    ...
```

On success, authenticators return `UserSessionState` with:

- `user_name`: resolved authenticated identity
- `state`: optional provider-specific session payload

## Configuration import paths

When authenticators are referenced by import string in service config, use
canonical paths from this package.

### Dictionary authenticator

```yaml
authentication:
  providers:
    - provider: toy
      authenticator: bluesky_authentication.authenticators:DictionaryAuthenticator
      args:
        users_to_passwords:
          alice: ${ALICE_PASSWORD}
          bob: ${BOB_PASSWORD}
```

### PAM authenticator

```yaml
authentication:
  providers:
    - provider: local
      authenticator: bluesky_authentication.authenticators:PAMAuthenticator
      args:
        service: login
```

### LDAP authenticator

```yaml
authentication:
  providers:
    - provider: ldap
      authenticator: bluesky_authentication.authenticators:LDAPAuthenticator
      args:
        server_address: ldap.example.org
        bind_dn_template: "uid={username},ou=people,dc=example,dc=org"
```

### OIDC authenticator

```yaml
authentication:
  providers:
    - provider: oidc
      authenticator: bluesky_authentication.authenticators:OIDCAuthenticator
      args:
        audience: tiled
        client_id: tiled_client
        client_secret: ${OIDC_CLIENT_SECRET}
        well_known_uri: https://accounts.google.com/.well-known/openid-configuration
```

### Entra authenticator

```yaml
authentication:
  providers:
    - provider: entra
      authenticator: bluesky_authentication.authenticators:EntraAuthenticator
      args:
        audience: YOUR_APP_ID_URI
        client_id: YOUR_CLIENT_ID
        client_secret: ${ENTRA_CLIENT_SECRET}
        device_flow_client_id: YOUR_CLIENT_ID
        well_known_uri: https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0/.well-known/openid-configuration
        scopes_map:
          User.Read:
            - read:metadata
```

## Legacy import-path compatibility

Host services may retain backward-compatible aliases (for example
`tiled.authenticators:*` or `bluesky_httpserver.authenticators:*`), but new
configuration should use `bluesky_authentication.authenticators:*`.

## Shared route wiring

`bluesky-authentication` includes a shared route factory that host applications
can use to avoid duplicating provider route registration.

```python
from bluesky_authentication.integration import (
    AuthProviderRegistration,
    AuthRouteAdapter,
    build_authentication_router,
)


class MyAdapter(AuthRouteAdapter):
    ...


providers = [
    AuthProviderRegistration("local", local_authenticator),
    AuthProviderRegistration("oidc", oidc_authenticator),
]

router = build_authentication_router(providers, MyAdapter())
app.include_router(router, prefix="/api/auth")
```

The adapter defines host-specific handlers and settings integration, while
`build_authentication_router()` defines the shared route topology.
