# Changelog

## [0.3.1] - 2023-04-05

### Added
- Add integration test setup with docker-compose using OIDC mock server.
- Add integration test for client credentials refresh.

### Fixed
- Warn when client credentials can not be parsed.
- Make `amr` and `auth_time` claims optional.

## [0.3.0] - 2023-03-27

### Added
- Support for client credentials flow.

## [0.2.0] - 2023-02-22

### Added
- Add authorization code flow (no refresh).
- Add device flow (no refresh).
- Add crypto functions.
- Add no auth flow.
- Upgrade library dependencies.

### Changed

### Fixed
- Fix tests.
