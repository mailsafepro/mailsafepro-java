# 3. API Versioning Strategy

Date: 2025-11-27

## Status

Accepted

## Context

As the API evolves, we will inevitably need to introduce breaking changes. We need a strategy to manage these changes without disrupting existing clients. We considered Header-based versioning and URL-based versioning.

## Decision

We will use **URL Path Versioning** (e.g., `/v1/validate/email`).

- **Clarity**: The version is explicitly visible in the URL, making it easy for developers to understand which version they are using.
- **Tooling**: Works well with standard HTTP tools, caches, and load balancers.
- **FastAPI Integration**: Easily implemented using `APIRouter` prefixes.

We will also implement **RFC 8594** standard headers (`Deprecation`, `Sunset`, `Link`) to communicate deprecation status to clients programmatically.

## Consequences

### Positive
- **Explicit**: No ambiguity about which version is being requested.
- **Parallel Support**: Easy to host v1 and v2 routers simultaneously in the same application.
- **Standardization**: Deprecation headers follow IETF standards.

### Negative
- **URL Pollution**: URLs become slightly longer.
- **Client Migration**: Clients must update their base URLs to upgrade (though this is true for most strategies).
