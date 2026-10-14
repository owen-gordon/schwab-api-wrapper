import unittest
from unittest.mock import MagicMock, patch

import requests

from schwab_api_wrapper.token_authority_client import (
    STREAM_RETRY_SECS,
    TokenAuthorityClient,
)


class StopLoop(Exception):
    pass


class TestTokenStreamRetry(unittest.TestCase):
    def _run_worker(self, get_side_effect=None, get_return=None):
        # Bypass __init__ (it primes a token and starts the thread); the worker only needs the URL.
        client = TokenAuthorityClient.__new__(TokenAuthorityClient)
        client.token_authority_base_url = "http://tas.invalid"
        sleeps = []

        def fake_sleep(secs):
            sleeps.append(secs)
            if len(sleeps) == 3:
                raise StopLoop

        with (
            patch(
                "schwab_api_wrapper.token_authority_client.requests.get",
                side_effect=get_side_effect,
                return_value=get_return,
            ) as get,
            patch(
                "schwab_api_wrapper.token_authority_client.time.sleep",
                side_effect=fake_sleep,
            ),
        ):
            with self.assertRaises(StopLoop):
                client._token_stream_worker()
        return get, sleeps

    def test_waits_between_retries_when_tas_is_unreachable(self):
        get, sleeps = self._run_worker(
            get_side_effect=requests.ConnectionError("connection refused")
        )
        self.assertEqual(sleeps, [STREAM_RETRY_SECS] * 3)
        self.assertEqual(get.call_count, 3)

    def test_waits_between_retries_on_non_200(self):
        response = MagicMock(status_code=503)
        response.__enter__.return_value = response
        get, sleeps = self._run_worker(get_return=response)
        self.assertEqual(sleeps, [STREAM_RETRY_SECS] * 3)
        self.assertEqual(get.call_count, 3)


if __name__ == "__main__":
    unittest.main()
