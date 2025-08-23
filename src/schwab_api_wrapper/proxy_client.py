import logging

from schwab_api_wrapper.schemas.oauth import Token
from .base_client import BaseClient


class ProxyClient(BaseClient):
    def __init__(self, proxy_base_url: str):
        # Do not call any token/file/redis setup. Just set the base override.
        self.base_override = proxy_base_url.rstrip("/")

    # --- OAuth/token storage interface (unused for proxy) ---
    def save_token(self, token: Token, refresh_token_reset: bool = False):
        # No-op: proxy handles auth externally
        return None

    def load_parameters(self, filepath: str | None = None):
        # No parameters are needed for proxy mode
        return {}

    def dump_parameters(self, filepath: str | None = None):
        # Nothing to persist
        return None

    def configurable_refresh(self):
        # Nothing to refresh for proxy mode
        return None

    @property
    def headers(self):
        # Intentionally exclude Authorization; proxy injects it
        return {
            "accept": "application/json",
        }
