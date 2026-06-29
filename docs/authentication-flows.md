# Authentication Flows

This page provides high-level diagrams of how authentication works across
Bluesky applications that use `bluesky-authentication`.

## 1) High-Level Architecture

```
flowchart LR
    U[User / Client] -->|HTTP / WebSocket| APP[Application<br/>(Tiled or HTTP Server)]
    APP --> AUTH[Auth Routes + Workflow Layer<br/>(bluesky-authentication)]
    AUTH --> DB[(Auth DB<br/>principals, identities, sessions, api_keys, pending_sessions)]
    AUTH --> IDP[External Identity Provider<br/>OIDC / Entra / LDAP / SAML]
    AUTH --> POLICY[Application Policy / Authorization<br/>(kept app-specific)]
    POLICY --> APP
    APP --> RES[Protected Application Resources]
```

## 2) Request Authentication Decision

```
flowchart TD
    A[Incoming request] --> B{Has Authorization?}
    B -->|Bearer access token| C[Validate JWT + scopes]
    B -->|API key| D[Lookup API key in DB + check expiry/scopes]
    B -->|No credentials| E[401 / redirect to auth]
    C --> F{Valid + authorized?}
    D --> F
    F -->|Yes| G[Allow request]
    F -->|No| H[Reject (401/403)]
```

## 3) Username/Password Flow

```
sequenceDiagram
    participant User
    participant App
    participant Auth as Auth Workflow
    participant Provider as Authenticator (LDAP/PAM/etc)
    participant DB as Auth DB

    User->>App: POST /auth/token (username, password)
    App->>Auth: handle_credentials()
    Auth->>Provider: authenticate(username, password)
    Provider-->>Auth: user identity (or failure)
    alt success
        Auth->>DB: get_or_create principal + identity
        Auth->>DB: create session
        Auth-->>App: access_token + refresh_token
        App-->>User: 200 tokens
    else failure
        App-->>User: 401 unauthorized
    end
```

## 4) Browser OIDC Authorization Code Flow

```
sequenceDiagram
    participant Browser
    participant App
    participant Auth as Auth Workflow
    participant OIDC as OIDC Provider
    participant DB as Auth DB

    Browser->>App: GET /auth/provider/{provider}/authorize
    App->>Auth: build authorize redirect
    Auth-->>Browser: 302 to OIDC authorize endpoint
    Browser->>OIDC: login + consent
    OIDC-->>Browser: redirect with auth code
    Browser->>App: GET /auth/provider/{provider}/code?code=...
    App->>OIDC: exchange code for tokens/userinfo
    OIDC-->>App: identity claims
    App->>DB: get_or_create principal + create session
    App-->>Browser: app tokens/session response
```

## 5) Device Code Flow (CLI / Headless)

```
sequenceDiagram
    participant CLI
    participant App
    participant DB as Auth DB
    participant Browser
    participant OIDC as OIDC Provider

    CLI->>App: POST /auth/provider/{provider}/device_code/authorize
    App->>DB: create pending_session (device_code, user_code, expiry)
    App-->>CLI: user_code + verification_uri + polling interval

    CLI->>App: POST /auth/provider/{provider}/device_code/token (poll)
    App->>DB: lookup pending_session
    alt not approved yet
        App-->>CLI: authorization_pending
    else approved
        App-->>CLI: access_token + refresh_token
    end

    Browser->>App: visit verification_uri + user_code
    App->>OIDC: user authenticates via provider
    OIDC-->>App: identity
    App->>DB: link pending_session -> real session
```

## 6) Refresh Token Flow

```
sequenceDiagram
    participant Client
    participant App
    participant DB as Auth DB

    Client->>App: POST /auth/refresh (refresh_token)
    App->>App: validate refresh JWT signature/claims
    App->>DB: lookup session by sid
    alt session valid and not expired/revoked
        App->>DB: update refresh_count + last_refreshed
        App-->>Client: new access_token (+ maybe rotated refresh token)
    else invalid/expired
        App-->>Client: 401 re-authenticate
    end
```

## 7) API Key Flow

```
sequenceDiagram
    participant Client
    participant App
    participant DB as Auth DB

    Client->>App: Request with API key header
    App->>DB: hash + lookup api_key(first_eight, hashed_secret)
    alt key valid + principal exists + not expired
        App->>App: authorize scopes/policy
        App-->>Client: 200 protected resource
    else invalid
        App-->>Client: 401/403
    end
```

## 8) Application Integration Steps

```
flowchart TD
    A[Create app server] --> B[Configure authenticators]
    B --> C[Register auth routes]
    C --> D[Configure auth DB + migrations]
    D --> E[Wire policy/authorization layer]
    E --> F[Protect resource routes with scopes]
    F --> G[Run background cleanup for expired sessions and API keys]
```
