# Authenticator Reference

`bluesky-authentication` provides built-in authenticators for local credentials
and external identity providers.

## Internal authenticators

Internal authenticators directly validate username/password credentials.

- `DummyAuthenticator` - accepts any username/password (testing only)
- `DictionaryAuthenticator` - validates against an in-memory mapping
- `PAMAuthenticator` - validates with host PAM
- `LDAPAuthenticator` - validates against one or more LDAP servers

## External authenticators

External authenticators validate callback requests and tokens from identity
providers.

- `OIDCAuthenticator` - OpenID Connect authorization-code flow
- `ProxiedOIDCAuthenticator` - OIDC schema helper for proxied auth setups
- `EntraAuthenticator` - Microsoft Entra specific OIDC claim/scope mapping
- `SAMLAuthenticator` - SAML callback flow

## Choosing an authenticator

- Use `DictionaryAuthenticator` or `DummyAuthenticator` only for demos/tests.
- Use `PAMAuthenticator` when accounts are local to the host.
- Use `LDAPAuthenticator` for directory-backed enterprise auth.
- Use `OIDCAuthenticator`/`EntraAuthenticator` for modern web-based SSO.
- Use `SAMLAuthenticator` when your identity provider is SAML-based.

## Optional dependencies

Some authenticators require optional extras:

- LDAP: `pip install "bluesky-authentication[ldap]"`
- PAM: `pip install "bluesky-authentication[pam]"`
- SAML: `pip install "bluesky-authentication[saml]"`
