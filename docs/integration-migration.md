# Integration Migration Guide

This guide describes how to migrate host applications (such as Tiled and
bluesky-httpserver) toward a shared authentication integration layer.

## Goal

Keep authenticator and storage behavior centralized in
`bluesky-authentication`, while keeping host-specific policy and response
schemas local to each application.

## Current shared building blocks

- Authenticator interfaces and implementations:
  `bluesky_authentication.protocols`,
  `bluesky_authentication.authenticators`
- Auth persistence models and common DB helpers:
  `bluesky_authentication.auth_store`
- Shared route topology helper:
  `bluesky_authentication.integration.build_authentication_router`

## Proposed extraction sequence

1. Centralize route registration (done by adapter + route factory)
2. Extract token/session workflow functions into shared workflow modules
3. Extract device-code workflow state transitions into shared modules
4. Extract API-key lifecycle operations into shared modules
5. Move startup auth maintenance helpers (purge loops and checks) behind
   reusable helpers
6. Align migration assets and revision strategy for shared DB operations

## Adapter responsibilities

Host applications should provide an adapter that bridges shared route wiring
to host behavior:

- Base routes (refresh, revoke, api-key, etc.)
- Provider-specific handler factories (internal and external flows)
- Optional authenticator-defined extra routes
- Host settings, policy checks, and schema serialization

This keeps policy and API-shape differences local while maximizing shared
authentication logic.

## App-level migration notes

### Tiled

- Replace duplicated provider route registration in `tiled.server.app` with
  `build_authentication_router(...)` + a Tiled adapter.
- Keep Tiled scope policy and schemas in `tiled.server.*`.

### bluesky-httpserver

- Replace duplicated provider route registration in
  `bluesky_httpserver.app` with `build_authentication_router(...)` + an
  HTTP-server adapter.
- Keep API access manager integration and response schema contracts local.

## End state

At completion, host applications should mostly configure adapters and include a
shared router, while the majority of authentication workflow behavior lives in
`bluesky-authentication`.
