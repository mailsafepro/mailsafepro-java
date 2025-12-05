# API Versioning Policy

MailSafePro uses **Semantic Versioning** and **URL Path Versioning**.

## Current Version: v1
Base URL: `https://api.mailsafepro.com/v1`

## Deprecation Policy
- We provide **6 months notice** before removing a deprecated endpoint.
- Deprecated endpoints return standard RFC 8594 headers:
  - `Deprecation: true`
  - `Sunset: <HTTP-date>` (Date when the endpoint will become unresponsive)
  - `Link: <url>; rel="deprecation"` (Link to migration guide)

## Migration Guides

### Migrating to v1
- Update base URL from `/` to `/v1`.
- Authentication remains the same (Bearer Token).
