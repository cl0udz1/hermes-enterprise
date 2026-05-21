"""Enterprise security layer for the Hermes downstream distribution.

This package must stay import-safe: importing it should not read user config,
create files, start services, or change normal Hermes behavior.
"""

from enterprise.mode import EnterpriseEdition, EnterpriseMode, is_enterprise_enabled

__all__ = [
    "EnterpriseEdition",
    "EnterpriseMode",
    "is_enterprise_enabled",
]
