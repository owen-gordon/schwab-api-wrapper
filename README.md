# Schwab API Wrapper
# schwab-api-wrapper

## Redis configuration

When using `RedisClient`, the Redis connection is configured via a JSON file (see `redis_config.json`).

### TLS / SSL options

You can control transport security with two optional keys:
- `ssl` (bool): enable TLS for the Redis connection
- `ssl_verify` (bool): when `ssl: true`, verify the server certificate

Backwards-compatible behavior:
- If `ssl` is omitted, the client behaves like older versions: TLS is enabled when `ca_cert_path` is present; otherwise the connection is plaintext.
- If `ssl` is true and `ssl_verify` is omitted, verification defaults to true.

### Examples

Plaintext (insecure):

```json
{
  "host": "localhost",
  "port": 6379,
  "password": "your_password",
  "encryption_key": "your_fernet_key",
  "ssl": false
}
```

TLS with certificate verification (recommended):

```json
{
  "host": "your.redis.host",
  "port": 6379,
  "password": "your_password",
  "encryption_key": "your_fernet_key",
  "ssl": true,
  "ssl_verify": true,
  "ca_cert_path": "path/to/ca.crt"
}
```

TLS without certificate verification (insecure; vulnerable to MITM):

```json
{
  "host": "your.redis.host",
  "port": 6379,
  "password": "your_password",
  "encryption_key": "your_fernet_key",
  "ssl": true,
  "ssl_verify": false
}
```
