# oidcish

- "Oh I Don't Care If Something Happens"
- "OIDC Is Definitely Cool If Someone Helps"

## What?

Library to connect to your OIDC provider via:

- Device code flow

## Usage

```python
auth = DeviceFlow(host="https://my.idp.com")
auth.credentials.access_token
```
