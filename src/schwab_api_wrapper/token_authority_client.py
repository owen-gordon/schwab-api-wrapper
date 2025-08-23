import json
import logging
import threading
from typing import Optional

import requests

from schwab_api_wrapper.schemas.oauth import Token
from .base_client import BaseClient


class TokenAuthorityClient(BaseClient):
    """
    Client that fetches bearer tokens from a Token Authority Service (TAS).

    - Starts a background thread that subscribes to TAS `/stream` (SSE)
      and updates an in-memory access token.
    - Sends requests directly to Schwab API (no proxy) with the current token.
    - Does not manage refresh/renew of refresh tokens; TAS is the source of truth.
    """

    def __init__(
        self,
        token_authority_base_url: str,
        start_stream: bool = True,
        session: Optional[requests.Session] = None,
    ):
        # Initialize BaseClient sessions and retry config
        super().__init__()

        self.token_authority_base_url = token_authority_base_url.rstrip("/")
        if session is not None:
            self.session = session

        # Shared token state protected by a lock
        self._access_token_lock = threading.RLock()
        self._access_token: Optional[str] = None

        # We talk directly to Schwab API; ensure base_override is not used
        self.base_override = None

        # Prime the token once so first requests have Authorization immediately
        self._prime_token()

        if start_stream:
            self._start_token_stream_thread()

    # --- OAuth/token storage interface (unused for TAS) ---
    def save_token(self, token: Token, refresh_token_reset: bool = False):
        # Not used; TAS is the token source
        return None

    def load_parameters(self, filepath: str | None = None):
        return {}

    def dump_parameters(self, filepath: str | None = None):
        return None

    def configurable_refresh(self):
        return None

    @property
    def headers(self):
        # Do not use BaseClient.headers which triggers refresh; just apply current token
        token = self._get_access_token()
        hdrs = {"accept": "application/json"}
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        return hdrs

    def _get_access_token(self) -> Optional[str]:
        with self._access_token_lock:
            return self._access_token

    def _set_access_token(self, token: Optional[str]) -> None:
        with self._access_token_lock:
            self._access_token = token

    def _start_token_stream_thread(self):
        thread = threading.Thread(target=self._token_stream_worker, daemon=True)
        thread.start()

    def _token_stream_worker(self):
        url = f"{self.token_authority_base_url}/stream"
        headers = {"accept": "text/event-stream"}

        # Basic SSE loop using streaming requests
        while True:
            try:
                with requests.get(url, headers=headers, stream=True, timeout=60) as r:
                    if r.status_code != 200:
                        logging.getLogger(__name__).warning(
                            f"Token stream subscribe failed: {r.status_code}"
                        )
                        continue

                    buffer = ""
                    for line in r.iter_lines(decode_unicode=True):
                        if line is None:
                            continue
                        if line == "":
                            # End of event
                            event_data = self._parse_sse_data(buffer)
                            buffer = ""
                            if event_data is None:
                                continue
                            access_token = event_data.get("access_token")
                            if access_token:
                                self._set_access_token(access_token)
                                logging.getLogger(__name__).debug(
                                    f"Access token updated from stream. Epoch: {event_data.get('epoch')}"
                                )
                            continue
                        if line.startswith(":"):
                            # Comment/keepalive
                            continue
                        if line.startswith("data:"):
                            buffer += line[len("data:") :].lstrip() + "\n"
            except Exception as ex:
                logging.getLogger(__name__).warning(
                    f"Token stream disconnected, retrying: {ex}"
                )

    @staticmethod
    def _parse_sse_data(raw: str) -> Optional[dict]:
        try:
            # Allow multi-line data; join and parse as JSON
            raw = raw.strip()
            if not raw:
                return None
            return json.loads(raw)
        except Exception:
            return None

    def _prime_token(self) -> None:
        try:
            url = f"{self.token_authority_base_url}/token"
            r = requests.get(url, headers={"accept": "application/json"}, timeout=10)
            if r.status_code == 200:
                payload = r.json()
                token = payload.get("access_token")
                if token:
                    self._set_access_token(token)
                    logging.getLogger(__name__).debug(
                        f"Access token primed from /token. Epoch: {payload.get('epoch')}"
                    )
        except Exception as ex:
            logging.getLogger(__name__).warning(
                f"Failed to prime token from /token: {ex}"
            )
