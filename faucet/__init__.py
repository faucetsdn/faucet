# pylint: disable=missing-docstring
from pbr.version import VersionInfo

__all__ = (
    '__version__',
)

__version__ = VersionInfo('faucet').semantic_version().release_string()
