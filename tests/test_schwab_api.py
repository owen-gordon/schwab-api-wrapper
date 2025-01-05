import unittest
from unittest.mock import patch, mock_open
import responses
import json
from datetime import datetime, timedelta
import os
from pathlib import Path
import logging
from zoneinfo import ZoneInfo

from schwab_api_wrapper.utils import *

from schwab_api_wrapper.schemas.trader_api.accounts_schemas import AccountNumbersResponse
from schwab_api_wrapper.schemas.trader_api import AccountsAndTradingError
from schwab_api_wrapper.schemas.trader_api.accounts_schemas import AccountsResponse, Account
from schwab_api_wrapper.schemas.trader_api import (
    OrderResponse,
    Order,
    OrderRequest,
    PreviewOrder,
)
from schwab_api_wrapper.schemas.trader_api.transactions_schemas import (
    Transaction,
    TransactionResponse,
    TransactionType,
)

from schwab_api_wrapper.schemas.market_data import QuoteResponse
from schwab_api_wrapper.schemas.market_data import MarketDataError
from schwab_api_wrapper.schemas.market_data import MarketHoursResponse
from schwab_api_wrapper.schemas.market_data.price_history_schemas import CandleList
from schwab_api_wrapper.schemas.market_data import InstrumentsRoot

from schwab_api_wrapper.file_client import FileClient

from schwab_api_wrapper.oauth_exception import OAuthException

logging.basicConfig(level=logging.INFO)


PARAMETERS_FILE_NAME = "fakefile.json"

fake_json = {
    KEY_CLIENT_ID: "your_client_id",
    KEY_CLIENT_SECRET: "your_client_secret",
    KEY_URI_REDIRECT: "your_redirect_uri",
    KEY_TOKEN_REFRESH: "your_refresh_token",
    KEY_TOKEN_ACCESS: "your_access_token",
    KEY_TOKEN_ID: "your_id_token",
    KEY_ACCESS_TOKEN_VALID_UNTIL: (
        datetime.now(ZoneInfo("America/New_York")) + timedelta(minutes=30)
    ).isoformat(),
    KEY_REFRESH_TOKEN_VALID_UNTIL: (
        datetime.now(ZoneInfo("America/New_York")) + timedelta(days=7)
    ).isoformat(),
}


class TestSchwabAPI(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open, read_data=json.dumps(fake_json))
    def setUp(self, mock_file) -> None:  # mock_file is required for the @patch wrapper
        self.api = FileClient(PARAMETERS_FILE_NAME, immediate_refresh=False)
        self.encrypted_account_number = "DEMO123456"
        self.order_id = 12345678
        self.transaction_id = 20240424145200
        self.sample_dir = Path(os.path.dirname(__file__)) / "sample_responses_sanitized"

    @patch("builtins.open", new_callable=mock_open, read_data=json.dumps(fake_json))
    @responses.activate
    def test_refresh_token_success(self, mock_file):
        # Mock the HTTP POST response for a successful token refresh
        # Set up the mock response
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

        # Call the method under test
        self.api.refresh()

        # Assert the new tokens are updated correctly
        self.assertEqual(self.api.access_token, "new_access_token")
        self.assertEqual(self.api.refresh_token, "new_refresh_token")
        self.assertEqual(self.api.id_token, "new_id_token")
        self.assertLess(
            self.api.access_token_valid_until,
            datetime.now(ZoneInfo("America/New_York")) + timedelta(minutes=30),
        )

    @patch("builtins.open", new_callable=mock_open, read_data=json.dumps(fake_json))
    @responses.activate
    def test_refresh_token_failure(self, mock_file):
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

        with self.assertRaises(OAuthException):
            # Call the method under test
            self.api.refresh()

    @responses.activate
    def test_account_numbers_success(self):
        responses.add(
            responses.GET,
            ACCOUNT_NUMBERS_URL,
            json=[{"accountNumber": "12345", "hashValue": "abcde"}],
            status=200,
        )
        result, error = self.api.account_numbers()
        self.assertIsInstance(result, AccountNumbersResponse)
        self.assertEqual(result[0].accountNumber, "12345")
        self.assertIsNone(error)

    @responses.activate
    def test_account_numbers_unauthorized(self):
        responses.add(
            responses.GET,
            ACCOUNT_NUMBERS_URL,
            json={
                "errors": [
                    {
                        "id": "1234beef-abcd-1234-8765-78753tx55436mn",
                        "status": 401,
                        "title": "Unauthorized",
                        "detail": "Client not authorized",
                    },
                ],
            },
            status=401,
        )
        result, error = self.api.account_numbers()
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(error.errors[0].title, "Unauthorized")
        self.assertEqual(error.errors[0].detail, "Client not authorized")

    @responses.activate
    def test_account_numbers_service_unavailable(self):
        responses.add(
            responses.GET,
            ACCOUNT_NUMBERS_URL,
            json={
                "errors": [
                    {
                        "id": "1234beef-abcd-1234-8765-78753tx55436mn",
                        "status": 503,
                        "title": "Service Unavailable",
                        "detail": "Service temporarily unavailable",
                    },
                ],
            },
            status=503,
        )
        result, error = self.api.account_numbers(retry=False)
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(error.errors[0].detail, "Service temporarily unavailable")
        self.assertIsNone(error.message)

    @responses.activate
    def test_account_numbers_service_retry_unavailable(self):
        responses.add(
            responses.GET,
            ACCOUNT_NUMBERS_URL,
            json={
                "errors": [
                    {
                        "id": "1234beef-abcd-1234-8765-78753tx55436mn",
                        "status": 503,
                        "title": "Service Unavailable",
                        "detail": "Service temporarily unavailable",
                    },
                ],
            },
            status=503,
        )
        result, error = self.api.account_numbers(retry=True)
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(error.errors[0].detail, "Service temporarily unavailable")
        self.assertEqual(error.message, "Maximum number of retries reached")

    @responses.activate
    def test_quotes_success(self):
        responses.add(
            responses.GET,
            QUOTES_URL,
            json=json.load(
                open(
                    self.sample_dir / "quotes.json",
                    "r",
                )
            ),
            status=200,
        )

        result, error = self.api.quotes(
            ["F", "AAPL", "$SPX", "FXAIX", "DJX 231215C00290000"], indicative=True
        )
        self.assertIsInstance(result, QuoteResponse)
        self.assertIsNone(error)

    @responses.activate
    def test_quote_bad_request(self):
        responses.add(
            responses.GET,
            QUOTES_URL,
            json={
                "errors": [
                    {
                        "id": "0be22ae7-efdf-44d9-99f4-f138049d76ca",
                        "status": "400",
                        "title": "Bad Request",
                        "detail": "Search combination should have min of 1.",
                        "source": {
                            "pointer": [
                                "/data/attributes/symbols",
                                "/data/attributes/cusips",
                                "/data/attributes/ssids",
                            ]
                        },
                    },
                ]
            },
            status=400,
        )

        result, error = self.api.quotes([])
        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)

    @responses.activate
    def test_quote_internal_server_error(self):
        responses.add(
            responses.GET,
            QUOTES_URL,
            json={
                "errors": [
                    {
                        "id": "0be22ae7-efdf-44d9-99f4-f138049d76ca",
                        "status": 500,
                        "title": "Internal Server Error",
                    }
                ]
            },
            status=500,
        )

        result, error = self.api.quotes(
            ["F", "AAPL", "$SPX", "FXAIX", "DJX 231215C00290000"], retry=False
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)
        self.assertIsNone(error.message)

    @responses.activate
    def test_quote_retry_internal_server_error(self):
        responses.add(
            responses.GET,
            QUOTES_URL,
            json={
                "errors": [
                    {
                        "id": "0be22ae7-efdf-44d9-99f4-f138049d76ca",
                        "status": 500,
                        "title": "Internal Server Error",
                    }
                ]
            },
            status=500,
        )

        result, error = self.api.quotes(
            ["F", "AAPL", "$SPX", "FXAIX", "DJX 231215C00290000"], retry=True
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)
        self.assertEqual(error.message, "Maximum number of retries reached")

    @responses.activate
    def test_market_hours_success(self):
        responses.add(
            responses.GET,
            MARKET_HOURS_URL,
            json=json.load(
                open(
                    self.sample_dir / "market_hours.json",
                    "r",
                )
            ),
            status=200,
        )

        result, error = self.api.market_hours(
            markets=[MarketID.EQUITY, MarketID.OPTION]
        )

        self.assertIsInstance(result, MarketHoursResponse)
        self.assertIsNone(error)

    @responses.activate
    def test_market_hours_bad_request(self):
        responses.add(
            responses.GET,
            MARKET_HOURS_URL,
            json={
                "errors": [
                    {
                        "id": "0be22ae7-efdf-44d9-99f4-f138049d76ca",
                        "status": "400",
                        "title": "Bad Request",
                        "detail": "Search combination should have min of 1.",
                        "source": {
                            "pointer": [
                                "/data/attributes/symbols",
                                "/data/attributes/cusips",
                                "/data/attributes/ssids",
                            ]
                        },
                    },
                ]
            },
            status=400,
        )

        result, error = self.api.market_hours(markets=[])
        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)

    @responses.activate
    def test_market_hours_internal_server_error(self):
        responses.add(
            responses.GET,
            MARKET_HOURS_URL,
            json={
                "errors": [
                    {
                        "id": "0be22ae7-efdf-44d9-99f4-f138049d76ca",
                        "status": 500,
                        "title": "Internal Server Error",
                    }
                ]
            },
            status=500,
        )

        result, error = self.api.market_hours(
            markets=[MarketID.EQUITY, MarketID.OPTION]
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)
        self.assertIsNone(error.message)

    @responses.activate
    def test_market_hours_retry_internal_server_error(self):
        responses.add(
            responses.GET,
            MARKET_HOURS_URL,
            json={
                "errors": [
                    {
                        "id": "0be22ae7-efdf-44d9-99f4-f138049d76ca",
                        "status": 500,
                        "title": "Internal Server Error",
                    }
                ]
            },
            status=500,
        )

        result, error = self.api.market_hours(
            markets=[MarketID.EQUITY, MarketID.OPTION], retry=True
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)
        self.assertEqual(error.message, "Maximum number of retries reached")

    @responses.activate
    def test_single_market_hours_success(self):
        responses.add(
            responses.GET,
            f"{MARKET_HOURS_URL}/{MarketID.EQUITY.value}",
            json={
                "equity": {
                    "EQ": {
                        "date": "2022-04-14",
                        "marketType": "EQUITY",
                        "exchange": "NULL",
                        "category": "NULL",
                        "product": "EQ",
                        "productName": "equity",
                        "isOpen": True,
                        "sessionHours": {
                            "preMarket": [
                                {
                                    "start": "2022-04-14T07:00:00-04:00",
                                    "end": "2022-04-14T09:30:00-04:00",
                                }
                            ],
                            "regularMarket": [
                                {
                                    "start": "2022-04-14T09:30:00-04:00",
                                    "end": "2022-04-14T16:00:00-04:00",
                                }
                            ],
                            "postMarket": [
                                {
                                    "start": "2022-04-14T16:00:00-04:00",
                                    "end": "2022-04-14T20:00:00-04:00",
                                }
                            ],
                        },
                    }
                }
            },
            status=200,
        )

        result, error = self.api.single_market_hours(MarketID.EQUITY)

        self.assertIsInstance(result, MarketHoursResponse)
        self.assertIsNone(error)

    @responses.activate
    def test_single_market_hours_internal_server_error(self):
        responses.add(
            responses.GET,
            f"{MARKET_HOURS_URL}/{MarketID.EQUITY.value}",
            json={
                "errors": [
                    {
                        "id": "0be22ae7-efdf-44d9-99f4-f138049d76ca",
                        "status": 500,
                        "title": "Internal Server Error",
                    }
                ]
            },
            status=500,
        )
        result, error = self.api.single_market_hours(MarketID.EQUITY)
        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)
        self.assertIsNone(error.message)

    @responses.activate
    def test_single_market_hours_retry_internal_server_error(self):
        responses.add(
            responses.GET,
            f"{MARKET_HOURS_URL}/{MarketID.EQUITY.value}",
            json={
                "errors": [
                    {
                        "id": "0be22ae7-efdf-44d9-99f4-f138049d76ca",
                        "status": 500,
                        "title": "Internal Server Error",
                    }
                ]
            },
            status=500,
        )

        result, error = self.api.single_market_hours(MarketID.EQUITY, retry=True)
        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)
        self.assertEqual(error.message, "Maximum number of retries reached")

    @responses.activate
    def test_accounts_success(self):
        responses.add(
            responses.GET,
            ACCOUNTS_URL,
            json=json.load(
                open(
                    self.sample_dir / "accounts.json",
                    "r",
                )
            ),
            status=200,
        )

        result, error = self.api.accounts(account_field=AccountsField.POSITIONS)
        self.assertIsInstance(result, AccountsResponse)
        self.assertIsNone(error)

    @responses.activate
    def test_single_account_success(self):
        responses.add(
            responses.GET,
            f"{ACCOUNTS_URL}/{self.encrypted_account_number}",
            json=json.load(
                open(
                    self.sample_dir / "single_account.json",
                    "r",
                )
            ),
            status=200,
        )

        result, error = self.api.single_account(
            self.encrypted_account_number,
            account_field=AccountsField.POSITIONS,
        )
        self.assertIsInstance(result, Account)
        self.assertIsNone(error)

    @responses.activate
    def test_single_account_unauthorized(self):
        responses.add(
            responses.GET,
            f"{ACCOUNTS_URL}/{self.encrypted_account_number}",
            json={
                "message": "Unauthorized",
            },
            status=401,
        )

        result, error = self.api.single_account(
            self.encrypted_account_number,
            account_field=AccountsField.POSITIONS,
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)

    @responses.activate
    def test_price_history_success(self):
        responses.add(
            responses.GET,
            PRICE_HISTORY_URL,
            json={
                "symbol": "AAPL",
                "empty": False,
                "previousClose": 174.56,
                "previousCloseDate": 1639029600000,
                "candles": [
                    {
                        "open": 175.01,
                        "high": 175.15,
                        "low": 175.01,
                        "close": 175.04,
                        "volume": 10719,
                        "datetime": 1639137600000,
                    },
                    {
                        "open": 175.08,
                        "high": 175.09,
                        "low": 175.05,
                        "close": 175.05,
                        "volume": 500,
                        "datetime": 1639137660000,
                    },
                    {
                        "open": 176.22,
                        "high": 176.27,
                        "low": 176.22,
                        "close": 176.25,
                        "volume": 3395,
                        "datetime": 1640307300000,
                    },
                    {
                        "open": 176.26,
                        "high": 176.27,
                        "low": 176.26,
                        "close": 176.26,
                        "volume": 2174,
                        "datetime": 1640307360000,
                    },
                    {
                        "open": 176.26,
                        "high": 176.31,
                        "low": 176.26,
                        "close": 176.3,
                        "volume": 15401,
                        "datetime": 1640307420000,
                    },
                    {
                        "open": 176.3,
                        "high": 176.3,
                        "low": 176.3,
                        "close": 176.3,
                        "volume": 1700,
                        "datetime": 1640307480000,
                    },
                    {
                        "open": 176.3,
                        "high": 176.5,
                        "low": 176.3,
                        "close": 176.32,
                        "volume": 5941,
                        "datetime": 1640307540000,
                    },
                ],
            },
            status=200,
        )

        result, error = self.api.price_history(
            "AAPL", PeriodFrequencyParameters(PeriodType.DAY), need_previous_close=True
        )
        self.assertIsInstance(result, CandleList)
        self.assertIsNone(error)

    @responses.activate
    def test_price_history_bad_request(self):
        responses.add(
            responses.GET,
            PRICE_HISTORY_URL,
            json={
                "errors": [
                    {
                        "id": "0be22ae7-efdf-44d9-99f4-f138049d76ca",
                        "status": "400",
                        "title": "Bad Request",
                        "detail": "Search combination should have min of 1.",
                        "source": {
                            "pointer": [
                                "/data/attributes/symbols",
                                "/data/attributes/cusips",
                                "/data/attributes/ssids",
                            ]
                        },
                    },
                ]
            },
            status=400,
        )

        result, error = self.api.price_history(
            "AAPL", PeriodFrequencyParameters(PeriodType.DAY), need_previous_close=True
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)

    @responses.activate
    def test_price_history_internal_server_error(self):
        responses.add(
            responses.GET,
            PRICE_HISTORY_URL,
            json={
                "errors": [
                    {
                        "id": "0be22ae7-efdf-44d9-99f4-f138049d76ca",
                        "status": 500,
                        "title": "Internal Server Error",
                    }
                ]
            },
            status=500,
        )

        result, error = self.api.price_history(
            "AAPL",
            PeriodFrequencyParameters(PeriodType.DAY),
            need_previous_close=True,
            retry=False,
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)
        self.assertIsNone(error.message)

    @responses.activate
    def test_price_history_retry_internal_server_error(self):
        responses.add(
            responses.GET,
            PRICE_HISTORY_URL,
            json={
                "errors": [
                    {
                        "id": "0be22ae7-efdf-44d9-99f4-f138049d76ca",
                        "status": 500,
                        "title": "Internal Server Error",
                    }
                ]
            },
            status=500,
        )

        result, error = self.api.price_history(
            "AAPL",
            PeriodFrequencyParameters(PeriodType.DAY),
            need_previous_close=True,
            retry=True,
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)
        self.assertEqual(error.message, "Maximum number of retries reached")

    @responses.activate
    def test_get_all_orders_success(self):
        responses.add(
            responses.GET,
            ORDERS_URL,
            json=json.load(
                open(
                    self.sample_dir / "all_orders.json",
                    "r",
                )
            ),
            status=200,
        )

        result, error = self.api.get_all_orders(
            datetime(2023, 1, 1), datetime(2023, 12, 31)
        )
        self.assertIsInstance(result, OrderResponse)
        self.assertIsNone(error)

    @responses.activate
    def test_get_all_orders_bad_request(self):
        responses.add(
            responses.GET,
            ORDERS_URL,
            json={
                "message": "'2024-03-01T12:00:00.000+0000' is not a valid value for fromEnteredTime"
            },
            status=400,
        )

        result, error = self.api.get_all_orders(
            datetime(2023, 1, 1), datetime(2023, 12, 31)
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(
            error.message,
            "'2024-03-01T12:00:00.000+0000' is not a valid value for fromEnteredTime",
        )

    @responses.activate
    def test_get_account_orders_success(self):
        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders",
            json=json.load(
                open(
                    self.sample_dir / "all_orders.json",
                    "r",
                )
            ),
            status=200,
        )

        result, error = self.api.get_account_orders(
            self.encrypted_account_number, datetime(2023, 1, 1), datetime(2023, 12, 31)
        )
        self.assertIsInstance(result, OrderResponse)
        self.assertIsNone(error)

    @responses.activate
    def test_get_account_orders_unauthorized(self):
        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders",
            json={"message": "Unauthorized"},
            status=401,
        )

        result, error = self.api.get_account_orders(
            self.encrypted_account_number, datetime(2023, 1, 1), datetime(2023, 12, 31)
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)

    @responses.activate
    def test_get_single_order_success(self):
        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders/{self.order_id}",
            json=json.load(
                open(
                    self.sample_dir / "order.json",
                    "r",
                )
            ),
            status=200,
        )

        result, error = self.api.get_single_order(
            self.encrypted_account_number, self.order_id
        )
        self.assertIsInstance(result, Order)
        self.assertIsNone(error)

    @responses.activate
    def test_get_single_order_not_found(self):
        encrypted_account_number = "encrypted_account_number"
        order_id = 12345678

        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{encrypted_account_number}/orders/{order_id}",
            json={"message": "Order not found"},
            status=404,
        )

        result, error = self.api.get_single_order(encrypted_account_number, order_id)
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)

    @responses.activate
    def test_place_order_success(self):
        responses.add(
            responses.POST,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders",
            headers={
                "Location": f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders/{self.order_id}"
            },
            status=201,
        )

        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders/{self.order_id}",
            json=json.load(
                open(
                    self.sample_dir / "order.json",
                    "r",
                )
            ),
            status=200,
        )

        order_details = {
            "orderType": "LIMIT",
            "session": "PM",
            "price": 0.01,
            "duration": "DAY",
            "orderStrategyType": "SINGLE",
            "orderLegCollection": [
                {
                    "instruction": "BUY",
                    "quantity": 1,
                    "instrument": {"symbol": "F", "assetType": "EQUITY"},
                }
            ],
        }

        order_request = OrderRequest(**order_details)

        result, error = self.api.place_order(
            self.encrypted_account_number, order_request
        )

        self.assertIsInstance(result, Order)
        self.assertIsNone(error)

    @responses.activate
    def test_place_order_retreival_failure(self):
        responses.add(
            responses.POST,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders",
            headers={
                "Location": f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders/{self.order_id}"
            },
            status=201,
        )

        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders/{self.order_id}",
            json={"message": "Order not found"},
            status=404,
        )

        order_details = {
            "orderType": "LIMIT",
            "session": "PM",
            "price": 0.01,
            "duration": "DAY",
            "orderStrategyType": "SINGLE",
            "orderLegCollection": [
                {
                    "instruction": "BUY",
                    "quantity": 1,
                    "instrument": {"symbol": "F", "assetType": "EQUITY"},
                }
            ],
        }

        order_request = OrderRequest(**order_details)

        result, error = self.api.place_order(
            self.encrypted_account_number, order_request
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(
            error.message,
            "Order placed successfully. GET order API call failed. Order not found",
        )

    @responses.activate
    def test_place_order_internal_server_error(self):
        responses.add(
            responses.POST,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders",
            json={
                "errors": [
                    {
                        "id": "32bd3075-b5d2-4672-ea90-309a49c5cbf7",
                        "status": 500,
                        "title": "Internal Server Error",
                    }
                ]
            },
            status=400,  # i know this is 400, thats what the api responds with...
        )

        order_details = {
            "orderType": "LIMIT",
            "session": "PM",
            "price": 0.01,
            "duration": "DAY",
            "orderStrategyType": "SINGLE",
            "orderLegCollection": [
                {
                    "instruction": "BUY",
                    "quantity": 1,
                    "instrument": {"symbol": "F", "assetType": "EQUITY"},
                }
            ],
        }

        order_request = OrderRequest(**order_details)

        result, error = self.api.place_order(
            self.encrypted_account_number, order_request
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(error.errors[0].status, 500)
        self.assertEqual(error.errors[0].title, "Internal Server Error")

    @responses.activate
    def test_place_order_bad_request(self):
        responses.add(
            responses.POST,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders",
            json={
                "message": "Invalid request data",
                "errors": [
                    "Field: orderStrategyType - must not be null",
                    "Duration cannot be null. Valid values: DAY, GOOD_TILL_CANCEL, FILL_OR_KILL",
                ],
            },
            status=400,
        )

        order_details = {
            "orderType": "LIMIT",
            "session": "PM",
            "price": 0.01,
            "duration": "DAY",
            "orderStrategyType": "SINGLE",
            "orderLegCollection": [
                {
                    "instruction": "BUY",
                    "quantity": 1,
                    "instrument": {"symbol": "F", "assetType": "EQUITY"},
                }
            ],
        }

        order_request = OrderRequest(**order_details)

        result, error = self.api.place_order(
            self.encrypted_account_number, order_request
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(error.message, "Invalid request data")
        self.assertEqual(error.errors[0], "Field: orderStrategyType - must not be null")
        self.assertEqual(
            error.errors[1],
            "Duration cannot be null. Valid values: DAY, GOOD_TILL_CANCEL, FILL_OR_KILL",
        )

    @responses.activate
    def test_place_order_bad_request_other(self):
        responses.add(
            responses.POST,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders",
            json={
                "message": "A validation error occurred while processing the request."
            },
            status=400,
        )

        order_details = {
            "orderType": "LIMIT",
            "session": "PM",
            "price": 0.01,
            "duration": "DAY",
            "orderStrategyType": "SINGLE",
            "orderLegCollection": [
                {
                    "instruction": "BUY",
                    "quantity": 1,
                    "instrument": {"symbol": "F", "assetType": "EQUITY"},
                }
            ],
        }

        order_request = OrderRequest(**order_details)

        result, error = self.api.place_order(
            self.encrypted_account_number, order_request
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(
            error.message, "A validation error occurred while processing the request."
        )

    @responses.activate
    def test_cancel_order_success(self):
        responses.add(
            responses.DELETE,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders/{self.order_id}",
            status=200,
        )

        result, error = self.api.cancel_order(
            self.encrypted_account_number, self.order_id
        )
        # the function returns no result so result will ways be None and this test will never fail
        self.assertIsNone(result)
        self.assertIsNone(error)

    @responses.activate
    def test_cancel_order_bad_request(self):
        responses.add(
            responses.DELETE,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders/{self.order_id}",
            json={"message": "Unauthorized"},
            status=401,
        )

        result, error = self.api.cancel_order(
            self.encrypted_account_number, self.order_id
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)

    @responses.activate
    def test_replace_order_success(self):
        responses.add(
            responses.PUT,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders/{self.order_id}",
            headers={
                "Location": f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders/{self.order_id}"
            },
            status=201,
        )

        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders/{self.order_id}",
            json=json.load(
                open(
                    self.sample_dir / "order.json",
                    "r",
                )
            ),
            status=200,
        )

        order_details = {
            "orderType": "LIMIT",
            "session": "PM",
            "price": 0.01,
            "duration": "DAY",
            "orderStrategyType": "SINGLE",
            "orderLegCollection": [
                {
                    "instruction": "BUY",
                    "quantity": 1,
                    "instrument": {"symbol": "F", "assetType": "EQUITY"},
                }
            ],
        }

        order_request = OrderRequest(**order_details)

        result, error = self.api.replace_order(
            self.encrypted_account_number, self.order_id, order_request
        )

        self.assertIsInstance(result, Order)
        self.assertIsNone(error)

    @responses.activate
    def test_replace_order_bad_request(self):
        responses.add(
            responses.PUT,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/orders/{self.order_id}",
            json={"message": "Unauthorized"},
            status=401,
        )

        order_details = {
            "orderType": "LIMIT",
            "session": "PM",
            "price": 0.01,
            "duration": "DAY",
            "orderStrategyType": "SINGLE",
            "orderLegCollection": [
                {
                    "instruction": "BUY",
                    "quantity": 1,
                    "instrument": {"symbol": "F", "assetType": "EQUITY"},
                }
            ],
        }

        order_request = OrderRequest(**order_details)

        result, error = self.api.replace_order(
            self.encrypted_account_number, self.order_id, order_request
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)

    @responses.activate
    def test_preview_order_success(self):
        responses.add(
            responses.POST,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/previewOrder",
            json=json.load(
                open(
                    self.sample_dir / "order.json",
                    "r",
                )
            ),
            status=200,
        )

        order_details = {
            "orderType": "LIMIT",
            "session": "PM",
            "price": 0.01,
            "duration": "DAY",
            "orderStrategyType": "SINGLE",
            "orderLegCollection": [
                {
                    "instruction": "BUY",
                    "quantity": 1,
                    "instrument": {"symbol": "F", "assetType": "EQUITY"},
                }
            ],
        }

        order_request = OrderRequest(**order_details)

        result, error = self.api.preview_order(
            self.encrypted_account_number, order_request
        )

        self.assertIsInstance(result, PreviewOrder)
        self.assertIsNone(error)

    @responses.activate
    def test_preview_order_bad_request(self):
        responses.add(
            responses.POST,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/previewOrder",
            json={"message": "Unauthorized"},
            status=401,
        )

        order_details = {
            "orderType": "LIMIT",
            "session": "PM",
            "price": 0.01,
            "duration": "DAY",
            "orderStrategyType": "SINGLE",
            "orderLegCollection": [
                {
                    "instruction": "BUY",
                    "quantity": 1,
                    "instrument": {"symbol": "F", "assetType": "EQUITY"},
                }
            ],
        }

        order_request = OrderRequest(**order_details)

        result, error = self.api.preview_order(
            self.encrypted_account_number, order_request
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)

    @responses.activate
    def test_get_transactions_success(self):
        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/transactions",
            json=json.load(
                open(
                    self.sample_dir / "transactions.json",
                    "r",
                )
            ),
            status=200,
        )

        result, error = self.api.get_transactions(
            self.encrypted_account_number,
            datetime(2024, 3, 1),
            datetime(2024, 4, 15),
            TransactionType.TRADE,
            symbol="GM",
        )

        self.assertIsInstance(result, TransactionResponse)
        self.assertIsNone(error)

    @responses.activate
    def test_get_transactions_multiple_types_success(self):
        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/transactions",
            json=json.load(
                open(
                    self.sample_dir / "multi_type_transactions.json",
                    "r",
                )
            ),
            status=200,
        )

        result, error = self.api.get_transactions(
            self.encrypted_account_number,
            datetime(2024, 3, 1),
            datetime(2024, 4, 15),
            [TransactionType.TRADE, TransactionType.CASH_RECEIPT],
            symbol="GM",
        )

        self.assertIsInstance(result, TransactionResponse)
        self.assertIsNone(error)

    @responses.activate
    def test_get_transactions_bad_request(self):
        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/transactions",
            json={
                "message": "'2024-04-15T12:00:00+1200' is not a valid value for endDate"
            },
            status=400,
        )

        result, error = self.api.get_transactions(
            self.encrypted_account_number,
            datetime(2024, 3, 1),
            datetime(2024, 4, 15),
            TransactionType.TRADE,
            symbol="GM",
        )

        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(
            error.message,
            "'2024-04-15T12:00:00+1200' is not a valid value for endDate",
        )

    @responses.activate
    def test_get_transactions_unauthorized(self):
        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/transactions",
            json={"message": "Unauthorized"},
            status=401,
        )

        result, error = self.api.get_transactions(
            self.encrypted_account_number,
            datetime(2024, 3, 1),
            datetime(2024, 4, 15),
            TransactionType.TRADE,
            symbol="GM",
        )

        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(error.message, "Unauthorized")

    @responses.activate
    def test_get_transactions_internal_server_error(self):
        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/transactions",
            json={
                "message": "Application encountered unexpected error that prevented fulfilling this request"
            },
            status=401,
        )

        result, error = self.api.get_transactions(
            self.encrypted_account_number,
            datetime(2024, 3, 1),
            datetime(2024, 4, 15),
            TransactionType.TRADE,
            symbol="GM",
        )

        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(
            error.message,
            "Application encountered unexpected error that prevented fulfilling this request",
        )

    @responses.activate
    def test_get_single_transaction_success(self):
        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/transactions/{self.transaction_id}",
            json=json.load(
                open(
                    self.sample_dir / "single_transaction.json",
                    "r",
                )
            ),
            status=200,
        )

        result, error = self.api.get_single_transaction(
            self.encrypted_account_number, self.transaction_id
        )

        self.assertIsInstance(result, Transaction)
        self.assertIsNone(error)

    @responses.activate
    def test_get_transactions_unauthorized(self):
        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/transactions/{self.transaction_id}",
            json={"message": "Unauthorized"},
            status=401,
        )

        result, error = self.api.get_single_transaction(
            self.encrypted_account_number, self.transaction_id
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(error.message, "Unauthorized")

    @responses.activate
    def test_get_transactions_not_found(self):
        responses.add(
            responses.GET,
            f"{TRADER_API_ENDPOINT}/accounts/{self.encrypted_account_number}/transactions/{self.transaction_id}",
            json={"message": "Transaction not found"},
            status=404,
        )

        result, error = self.api.get_single_transaction(
            self.encrypted_account_number, self.transaction_id
        )
        self.assertIsNone(result)
        self.assertIsInstance(error, AccountsAndTradingError)
        self.assertEqual(error.message, "Transaction not found")

    @responses.activate
    def test_instruments_symbol_search(self):
        responses.add(
            responses.GET,
            INSTRUMENTS_URL,
            json={
                "instruments": [
                    {
                        "cusip": "037833100",
                        "symbol": "AAPL",
                        "description": "Apple Inc",
                        "exchange": "NASDAQ",
                        "assetType": "EQUITY",
                    },
                    {
                        "cusip": "00206R102",
                        "symbol": "T",
                        "description": "A T & T Inc",
                        "exchange": "NYSE",
                        "assetType": "EQUITY",
                    },
                ],
            },
            status=200,
        )

        result, error = self.api.instruments(["AAPL", "T"], Projection.SYMBOL_SEARCH)

        self.assertIsInstance(result, InstrumentsRoot)
        self.assertIsNone(error)

    @responses.activate
    def test_instruments_fundamentals(self):
        responses.add(
            responses.GET,
            INSTRUMENTS_URL,
            json=json.load(
                open(
                    self.sample_dir / "instruments_fundamentals.json",
                    "r",
                )
            ),
            status=200,
        )

        result, error = self.api.instruments(["AAPL", "T"], Projection.FUNDAMENTAL)

        self.assertIsInstance(result, InstrumentsRoot)
        self.assertIsNone(error)

    @responses.activate
    def test_instruments_bad_projection(self):
        responses.add(
            responses.GET,
            INSTRUMENTS_URL,
            json={
                "errors": [
                    {
                        "id": "cd214562-7489-4c98-af64-e3db04037f09",
                        "status": "400",
                        "title": "Bad Request",
                        "detail": (
                            "Projection has to be one of following: symbol-search,symbol-regex,desc-search,desc-regex,search,funda"
                            "mental"
                        ),
                        "source": {
                            "parameter": "projection",
                        },
                    },
                ],
            },
            status=400,
        )

        result, error = self.api.instruments(["AAPL", "T"], Projection.SYMBOL_SEARCH)

        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)
        self.assertEqual(
            error.errors[0].detail,
            "Projection has to be one of following: symbol-search,symbol-regex,desc-search,desc-regex,search,fundamental",
        )
        self.assertEqual(error.errors[0].source.parameter, "projection")

    @responses.activate
    def test_instruments_bad_symbol(self):
        responses.add(
            responses.GET,
            INSTRUMENTS_URL,
            json={
                "errors": [
                    {
                        "id": "4c8591c4-0946-4424-9648-fe7b6e026906",
                        "status": "400",
                        "title": "Bad Request",
                        "detail": "Symbol cannot be null or empty.",
                        "source": {
                            "parameter": "symbol",
                        },
                    },
                ],
            },
            status=400,
        )

        result, error = self.api.instruments(["AAPL", "T"], Projection.SYMBOL_SEARCH)

        self.assertIsNone(result)
        self.assertIsInstance(error, MarketDataError)
        self.assertEqual(error.errors[0].detail, "Symbol cannot be null or empty.")
        self.assertEqual(error.errors[0].source.parameter, "symbol")


if __name__ == "__main__":
    unittest.main()
