---
jupyter:
  jupytext:
    formats: ipynb,md
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.13.7
  kernelspec:
    display_name: Python 3 (ipykernel)
    language: python
    name: python3
---

# Accessing the Analytics API with client credentials

The Analytics API can also be accessed without explicit user login (Device code flow instead of Authorization flow) using the client id and the client secret. This is done by sending requests to the IDP endpoints. 

This is not implemented in a Python library in SHAARPEC yet, but this notebook shows how this flow is done in Python. The idea is general.

```python
import requests
import pandas as pd
from pydantic import BaseSettings
from shaarpec_analytics.login import Credentials
```

<!-- #region -->
An .env file in the same folder as the notebook is needed for authenticating with the API:
```bash
SHAARPEC_IDP_CLIENT_ID=replace_with_client_id
SHAARPEC_IDP_CLIENT_SECRET=replace_with_client_secret
SHAARPEC_IDP_SCOPE="openid shaarpec_api.full_access_scope offline_access"
```
Note:
- `shaarpec_api.full_access_scope` is needed to have access to the Analytics API
- `offline_access` is needed to get a long-lived refresh token which can be traded for authentication tokens.
<!-- #endregion -->

```python
!find -maxdepth 1 -name ".env" -printf 'name="%f", changed=%CY-%Cm-%Cd, size=%s'
```

We define a [pydantic](https://pydantic-docs.helpmanual.io) class to hold authentication settings and then read the settings from the .env file.

```python
class ClientSettings(BaseSettings):
    client_id: str
    client_secret: str
    scope: str

    class Config:
        """Additional configurations."""

        env_prefix = "shaarpec_idp_"
        env_file = ".env"
        extra = "ignore"
```

```python
settings = ClientSettings()
settings
```

## Authenticating with the API
First part of the device code login flow, asks you to go to an URL to finish the login procedure.

```python
response = requests.post(
    "https://idp-demo.shaarpec.com/connect/deviceauthorization",
    data=settings.dict(),
)
verification_uri_complete=response.json().get("verification_uri_complete")
device_code = response.json().get("device_code")

print(f"Visit {verification_uri_complete} to complete sign-in.")
```

In the webpage, enter whatever name you like to have for your device. After accepting you have completed the sign-in. At this point, you can ask for API credentials using the device code:

```python
response = requests.post(
    "https://idp-demo.shaarpec.com/connect/token",
    data=dict(
        settings,
        grant_type="urn:ietf:params:oauth:grant-type:device_code",
        device_code=device_code,
    ),
)
credentials = Credentials.parse_obj(response.json())
```

Use `credentials.access_token` to ask for resources in the Analytics API. Note that the access_token is short-lived (1 hr). You can trade the long-lived (24 h) refresh token for a new access token. You can define a function that refreshes your credentials like this:

```python
def refresh(credentials: Credentials) -> Credentials:
    response = requests.post(
        "https://idp-demo.shaarpec.com/connect/token",
        data=dict(
            settings,
            grant_type="refresh_token",
            refresh_token=credentials.refresh_token,
        ),
    )
    return Credentials.parse_obj(response.json())
```

If you don't use your refresh token for 24 h, it will expire and you have to initiate the full device code login flow again.


## Reading data from the API
Access resources in the Analytics API with your access token in the `x-auth-request-access-token` header and the `accept` header set to `application/json`.

```python
response = requests.get(
    "https://api-demo.shaarpec.com/terminology/condition_type/codes",
    headers={
        "x-auth-request-access-token": f"{credentials.access_token}",
        "accept": "application/json",
    },
)
condition_codes = pd.Series(response.json(), name="ICD10")
condition_codes.to_frame("description")
```
