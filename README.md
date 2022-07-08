# oidcish

- "Oh I Don't Care If Something Happens"
- "OIDC Is Definitely Cool If Someone Helps"

## What?

Library to connect to your OIDC provider via:

- Authentication code flow
- Device code flow

## Usage

```python
>>> from oidcish import DeviceFlow, CodeFlow
>>> auth = DeviceFlow(host="https://example.idp.com")
Visit https://idp.example.com/device?userCode=594658190 to complete sign-in.
# Or
# auth = CodeFlow(host="https://example.idp.com")
>>> print(auth.credentials.access_token)
eyJhbGciOiJSU...
```

## Options

Device flow can be used with the following options:

| Option | Default | Description |
|-|-|-|
| client_id | *No default* | The client id. |
| client_secret | *No default* | The client secret. |
| scope | openid profile offline_access | A space separated, case-sensitive list of scopes. |
| audience | *No default* | The access claim was designated for this audience. |

Code flow can be used with the following options:

| Option | Default | Description |
|-|-|-|
| client_id | *No default* | The client id. |
| client_secret | *No default* | The client secret. |
| redirect_uri | http://localhost | Must exactly match one of the allowed redirect URIs for the client. |
| username | *No default* | The user name. |
| password | *No default* | The user password. |
| scope | openid profile offline_access | A space separated, case-sensitive list of scopes. |
| audience | *No default* | The access claim was designated for this audience. |
