"""A3 egress wall: run the gateway's outbound provider calls inside a
Modal Sandbox constrained by `outbound_domain_allowlist`.

The public FastAPI app stays in the Modal Function (it authenticates and
validates requests); the code that actually makes outbound provider HTTP
calls runs in a Sandbox that can only reach the declared provider domains.
See `glc.egress.allowlist` for the minimal domain set and
`glc.egress.sandbox_client` for the Function-side client.
"""

from glc.egress.allowlist import PROVIDER_EGRESS_ALLOWLIST

__all__ = ["PROVIDER_EGRESS_ALLOWLIST"]
