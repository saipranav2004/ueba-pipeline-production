"""Identity connectors.

The pipeline targets Active Directory. Entra ID sign-in ingestion is retained as
the cloud face of a hybrid AD estate (AD synced to Entra via Entra Connect);
third-party IDP connectors are intentionally not included, since an AD-centric
deployment does not use them.
"""
from ueba_pipeline.connectors.base import (
    CanonicalIdentityEvent, IdentityConnector, normalize_username_cross_idp,
)
from ueba_pipeline.connectors.entra_signin import EntraSignInConnector

__all__ = [
    "CanonicalIdentityEvent", "IdentityConnector", "normalize_username_cross_idp",
    "EntraSignInConnector",
]

# Connector registry: maps source_name -> connector class.
CONNECTOR_REGISTRY: dict[str, type] = {
    "entra_id": EntraSignInConnector,
}
