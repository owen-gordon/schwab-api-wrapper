import unittest
from unittest.mock import patch, MagicMock, mock_open
import json
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import responses
import ssl

from schwab_api_wrapper import RedisClient, Token, OAuthException
from schwab_api_wrapper.utils import *

FAKE_TOKEN = {
    KEY_TTL: 1800,
    KEY_TOKEN_TYPE: "Bearer",
    "scope": "api",
    KEY_TOKEN_REFRESH: "refresh_token",
    KEY_TOKEN_ACCESS: "access_token",
    KEY_TOKEN_ID: "id_token",
    KEY_CLIENT_ID: "client_id",
    KEY_CLIENT_SECRET: "client_secret",
    KEY_URI_REDIRECT: "redirect_uri",
    KEY_ACCESS_TOKEN_VALID_UNTIL: (
        datetime.now(ZoneInfo("America/New_York")) + timedelta(minutes=30)
    ).isoformat(),
    KEY_REFRESH_TOKEN_VALID_UNTIL: (
        datetime.now(ZoneInfo("America/New_York")) + timedelta(days=7)
    ).isoformat(),
}


class TestRedisClient(unittest.TestCase):
    def setUp(self):
        responses.add(
            responses.POST,
            TOKEN_URL,
            json={
                KEY_TOKEN_ACCESS: "new_access_token",
                KEY_TTL: 1800,
                KEY_TOKEN_REFRESH: "new_refresh_token",
                KEY_TOKEN_ID: "new_id_token",
                "scope": "api",
                "token_type": "Bearer",
            },
            status=200,
        )

        key = Fernet.generate_key()
        self.fernet_key = key

        # Mock reading from a file
        self.patcher = patch(
            "builtins.open",
            unittest.mock.mock_open(
                read_data=json.dumps(
                    {
                        KEY_REDIS_HOST: "localhost",
                        KEY_REDIS_PORT: 6379,
                        KEY_REDIS_PASSWORD: "password",
                        KEY_REDIS_ENCRYPTION_KEY: key.decode(),
                    }
                )
            ),
        )

        self.cipher_suite = Fernet(key)

        self.mock_file = self.patcher.start()

        # Mock Redis
        self.redis_patch = patch("redis.Redis")

        self.mock_redis_constructor = self.redis_patch.start()
        self.mock_redis_constructor.side_effect = lambda *args, **kwargs: MagicMock()

        # Define a function to create a new mock redis client with a configured get() method
        def create_redis_mock(*args, **kwargs):
            mock_redis = MagicMock()
            encrypted_token = self.cipher_suite.encrypt(json.dumps(FAKE_TOKEN).encode())
            mock_redis.get.return_value = encrypted_token
            return mock_redis

        self.mock_redis_constructor.side_effect = create_redis_mock

    def tearDown(self):
        self.patcher.stop()
        self.redis_patch.stop()

    @responses.activate
    def test_initialization(self):
        client = RedisClient("dummy_path")
        self.mock_file.assert_called_once_with("dummy_path", "r")
        self.assertTrue(client.redis)
        # Default config in setUp does not include CA cert path or explicit ssl keys => plaintext
        _, kwargs = self.mock_redis_constructor.call_args
        self.assertNotIn("ssl", kwargs)

    @responses.activate
    def test_encrypt_decrypt_token(self):
        client = RedisClient("dummy_path")
        encrypted = client.encrypt_token()
        decrypted = client.decrypt_token(encrypted)
        self.assertEqual(client.parameters, decrypted)

    @responses.activate
    def test_save_load_token(self):
        client = RedisClient("dummy_path")
        client.save_token(Token(**FAKE_TOKEN))
        loaded_token = client.load_parameters()
        self.assertEqual(FAKE_TOKEN, loaded_token)

    @responses.activate
    def test_refresh_connection(self):
        client = RedisClient("dummy_path")
        old_redis = client.redis
        client.configurable_refresh()
        self.assertNotEqual(old_redis, client.redis)

    @responses.activate
    def test_refresh_token_failure(self):
        # Mock the HTTP POST response for a successful token refresh
        # Set up the mock response
        responses.add(
            responses.POST,
            TOKEN_URL,
            json={
                "error": "unsupported_token_type",
                "error_description": (
                    '400 Bad Request: "{"error_description":"Exception while authenticating refresh token [tokenDigest=******, Exception=Failed refresh token authentication [tokenDigest=******]]","error":"refresh_token_authentication_error"}"'
                ),
            },
            status=400,
        )

        client = RedisClient("dummy_path")

        with self.assertRaises(OAuthException):
            # Call the method under test
            client.refresh()

    @responses.activate
    def test_tls_enabled_explicit_without_ca_uses_system_store(self):
        config = {
            KEY_REDIS_HOST: "localhost",
            KEY_REDIS_PORT: 6379,
            KEY_REDIS_PASSWORD: "password",
            KEY_REDIS_ENCRYPTION_KEY: self.fernet_key.decode(),
            KEY_REDIS_SSL: True,
            KEY_REDIS_SSL_VERIFY: True,
        }

        with patch("builtins.open", mock_open(read_data=json.dumps(config))):
            RedisClient("dummy_path")

        _, kwargs = self.mock_redis_constructor.call_args
        self.assertTrue(kwargs.get("ssl"))
        self.assertEqual(kwargs.get("ssl_cert_reqs"), ssl.CERT_REQUIRED)
        self.assertNotIn("ssl_ca_certs", kwargs)

    @responses.activate
    def test_tls_enabled_without_verification(self):
        config = {
            KEY_REDIS_HOST: "localhost",
            KEY_REDIS_PORT: 6379,
            KEY_REDIS_PASSWORD: "password",
            KEY_REDIS_ENCRYPTION_KEY: self.fernet_key.decode(),
            KEY_REDIS_SSL: True,
            KEY_REDIS_SSL_VERIFY: False,
        }

        with patch("builtins.open", mock_open(read_data=json.dumps(config))):
            RedisClient("dummy_path")

        _, kwargs = self.mock_redis_constructor.call_args
        self.assertTrue(kwargs.get("ssl"))
        self.assertEqual(kwargs.get("ssl_cert_reqs"), ssl.CERT_NONE)
        self.assertEqual(kwargs.get("ssl_check_hostname"), False)

    @responses.activate
    def test_ssl_false_forces_plaintext_even_with_ca_cert_path(self):
        config = {
            KEY_REDIS_HOST: "localhost",
            KEY_REDIS_PORT: 6379,
            KEY_REDIS_PASSWORD: "password",
            KEY_REDIS_ENCRYPTION_KEY: self.fernet_key.decode(),
            KEY_REDIS_SSL: False,
            KEY_REDIS_CA_CERT_PATH: "ca.crt",
        }

        with patch("builtins.open", mock_open(read_data=json.dumps(config))):
            RedisClient("dummy_path")

        _, kwargs = self.mock_redis_constructor.call_args
        self.assertNotIn("ssl", kwargs)


if __name__ == "__main__":
    unittest.main()
