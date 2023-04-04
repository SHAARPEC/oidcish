# oidcish

- "Oh I Don't Care If Something Happens"
- "OIDC Is Definitely Cool If Someone Helps"

## What?

Library to connect to your OIDC provider via:

- Authentication code flow
- Device code flow
- Client credentials flow

## Usage

```python
>>> from oidcish import DeviceFlow, CodeFlow, CredentialsFlow
>>> auth = DeviceFlow(
...     host="https://idp.example.com",
...     client_id=...,
...     client_secret=...,
...     scope=...,
...     audience=...
...)
Visit https://idp.example.com/device?userCode=594658190 to complete sign-in.
# Or use env file for auth
# auth = DeviceFlow(_env_file="path/to/my/env.file")
# Or use authorization code flow
# auth = CodeFlow(_env_file="path/to/my/env.file")
# Or use client credentials flow
# auth = CredentialsFlow(_env_file="path/to/my/env.file")
>>> print(auth.credentials.access_token)
eyJhbGciOiJSU...
```

## Options

Device flow can be used with the following options:

| Option | Environment variable | Default | Description |
|-|-|-|-|
| host | OIDCISH_HOST | *No default* | The address to the IDP server. |
| client_id | OIDCISH_CLIENT_ID | *No default* | The client id. |
| client_secret | OIDCISH_CLIENT_SECRET | *No default* | The client secret. |
| scope | OIDCISH_SCOPE | openid profile offline_access | A space separated, case-sensitive list of scopes. |
| audience | OIDCISH_AUDIENCE | *No default* | The access claim was designated for this audience. |

The OIDCISH_ prefix can be set with the OIDCISH_ENV_PREFIX environment variable.

Code flow can be used with the following options:

| Option | Environment variable | Default | Description |
|-|-|-|-|
| host | OIDCISH_HOST | *No default* | The address to the IDP server. |
| client_id | OIDCISH_CLIENT_ID | *No default* | The client id. |
| client_secret | OIDCISH_CLIENT_SECRET | *No default* | The client secret. |
| redirect_uri | OIDCISH_REDIRECT_URI | http://localhost | Must exactly match one of the allowed redirect URIs for the client. |
| username | OIDCISH_USERNAME | *No default* | The user name. |
| password | OIDCISH_PASSWORD | *No default* | The user password. |
| scope | OIDCISH_SCOPE | openid profile offline_access | A space separated, case-sensitive list of scopes. |
| audience | OIDCISH_AUDIENCE | *No default* | The access claim was designated for this audience. |

The OIDCISH_ prefix can be set with the OIDCISH_ENV_PREFIX environment variable.

Client credentials flow can be used with the following options:

| Option | Environment variable | Default | Description |
|-|-|-|-|
| host | OIDCISH_HOST | *No default* | The address to the IDP server. |
| client_id | OIDCISH_CLIENT_ID | *No default* | The client id. |
| client_secret | OIDCISH_CLIENT_SECRET | *No default* | The client secret. |
| audience | OIDCISH_AUDIENCE | *No default* | The access claim was designated for this audience. |

The OIDCISH_ prefix can be set with the OIDCISH_ENV_PREFIX environment variable.
