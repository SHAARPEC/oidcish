# Changelog

## [1.0.3] - 2023-10-08

### Changed

-  One of the `role`` and `client_role`` claims is now required in the access token.

## [1.0.2] - 2023-08-30

### Changed

-   Made 'jti' claim optional (some IDP's don't provide it).

## [1.0.1] - 2023-07-07

### Changed

-   Made 'sub' and 'idp' claims optional (some IDP's don't provide them).

## [1.0.0] - 2023-07-06

### Changed

-   Migrate to pydantic v2
-   Migrate to ruff for linting
-   Upgrade all dependencies.

### Fixed

-   Fix integration tests so that they run in docker-compose.

## [0.3.1] - 2023-04-05

### Added

-   Add integration test setup with docker-compose using OIDC mock server.
-   Add integration test for client credentials refresh.

### Fixed

-   Warn when client credentials can not be parsed.
-   Make `amr` and `auth_time` claims optional.

## [0.3.0] - 2023-03-27

### Added

-   Support for client credentials flow.

## [0.2.0] - 2023-02-22

### Added

-   Add authorization code flow (no refresh).
-   Add device flow (no refresh).
-   Add crypto functions.
-   Add no auth flow.
-   Upgrade library dependencies.

### Changed

### Fixed

-   Fix tests.
