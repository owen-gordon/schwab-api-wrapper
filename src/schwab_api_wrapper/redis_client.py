import json
import redis
from cryptography.fernet import Fernet

from .utils import (
    KEY_REDIS_HOST,
    KEY_REDIS_PORT,
    KEY_REDIS_PASSWORD,
    KEY_REDIS_ENCRYPTION_KEY,
    KEY_REDIS_CA_CERT_PATH,
    KEY_REDIS_SSL,
    KEY_REDIS_SSL_VERIFY,
)
from .base_client import BaseClient
from schwab_api_wrapper.schemas.oauth import Token
import ssl

import logging


class RedisClient(BaseClient):
    def __init__(
        self,
        redis_config_filepath: str,
        renew_refresh_token: bool = False,
        immediate_refresh: bool = True,
    ):
        super().__init__()

        self.redis_config_filepath = redis_config_filepath
        with open(self.redis_config_filepath, "r") as fin:
            self.redis_parameters = json.load(fin)

        self.encryption_key = self.get_encryption_key()

        self.cipher_suite = Fernet(self.encryption_key)

        self.redis = self.create_redis_client()

        self.parameters = self.load_parameters()
        self.set_parameter_instance_values(self.parameters)

        self.assert_refresh_token_not_expired(
            renew_refresh_token
        )  # check if refresh token is expired and exit if so

        if immediate_refresh:
            self.refresh()

    def create_redis_client(self) -> redis.Redis:
        logger = logging.getLogger(__name__)

        ca_cert_path = self.redis_parameters.get(KEY_REDIS_CA_CERT_PATH)

        use_ssl = self.redis_parameters.get(KEY_REDIS_SSL)
        ssl_verify = self.redis_parameters.get(KEY_REDIS_SSL_VERIFY)

        redis_kwargs: dict = {
            "host": self.redis_parameters[KEY_REDIS_HOST],
            "port": self.redis_parameters[KEY_REDIS_PORT],
            "password": self.redis_parameters[KEY_REDIS_PASSWORD],
        }

        if not use_ssl:
            logger.info("Creating Redis client without SSL (plaintext connection)")
            return redis.Redis(**redis_kwargs)

        # TLS enabled
        redis_kwargs["ssl"] = True

        if ssl_verify:
            if ca_cert_path:
                logger.info(
                    "Creating Redis client with SSL (certificate verification enabled) and CA certificate path: %s",
                    ca_cert_path,
                )
                redis_kwargs["ssl_ca_certs"] = ca_cert_path
            else:
                logger.info(
                    "Creating Redis client with SSL (certificate verification enabled) using system CA store"
                )

            redis_kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED
            return redis.Redis(**redis_kwargs)

        # TLS enabled but verification disabled (insecure)
        logger.warning(
            "Creating Redis client with SSL but certificate verification is DISABLED (ssl_verify=false). "
            "This is insecure and vulnerable to man-in-the-middle attacks. Use only in local/dev or trusted networks."
        )
        redis_kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
        redis_kwargs["ssl_check_hostname"] = False
        return redis.Redis(**redis_kwargs)

    def get_encryption_key(self) -> bytes:
        return self.redis_parameters[KEY_REDIS_ENCRYPTION_KEY].encode()

    def save_token(self, token: Token, refresh_token_reset: bool = False):
        self.update_parameters(token, refresh_token_reset)

        self.dump_parameters()

    def configurable_refresh(self):
        self.redis.close()
        self.redis = self.create_redis_client()

    def load_parameters(self, _: str | None = None) -> dict:
        encrypted_token = self.redis.get("token")
        return self.decrypt_token(encrypted_token)

    def dump_parameters(self, _: str | None = None) -> bool:
        encrypted_token = self.encrypt_token()
        return self.redis.set("token", encrypted_token)

    def encrypt_token(self) -> bytes:
        return self.cipher_suite.encrypt(json.dumps(self.parameters).encode())

    def decrypt_token(self, encrypted_token: bytes) -> dict:
        return json.loads(self.cipher_suite.decrypt(encrypted_token).decode())
