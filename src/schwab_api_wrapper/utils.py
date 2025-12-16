from enum import Enum
from urllib.parse import urlparse, parse_qs
from typing import Optional


KEY_REDIS_HOST = "host"
KEY_REDIS_PORT = "port"
KEY_REDIS_PASSWORD = "password"
KEY_REDIS_ENCRYPTION_KEY = "encryption_key"
KEY_REDIS_CA_CERT_PATH = "ca_cert_path"
KEY_REDIS_SSL = "ssl"
KEY_REDIS_SSL_VERIFY = "ssl_verify"


KEY_CLIENT_ID = "client_id"
KEY_CLIENT_SECRET = "client_secret"
KEY_URL_AUTH = "auth_url"
KEY_URL_TOKEN = "token_url"
KEY_URI_REDIRECT = "redirect_uri"
KEY_TOKEN_ACCESS = "access_token"
KEY_ACCESS_TOKEN_VALID_UNTIL = "access_token_valid_until"
KEY_TOKEN_REFRESH = "refresh_token"
KEY_REFRESH_TOKEN_VALID_UNTIL = "refresh_token_valid_until"
KEY_TOKEN_ID = "id_token"
KEY_TOKEN_TYPE = "token_type"
KEY_TTL = "expires_in"

KEY_GRANT_TYPE = "grant_type"
KEY_CODE = "code"
VALUE_CODE_AUTHORIZATION = "authorization_code"

STATUS_CODE_OK = 200
STATUS_CODE_CREATED = 201
STATUS_CODE_CLIENT_ERROR = 400
STATUS_CODE_FORBIDDEN = 403

BASE_URL = "https://api.schwabapi.com"
MARKET_DATA_ENDPOINT = f"{BASE_URL}/marketdata/v1"
TRADER_API_ENDPOINT = f"{BASE_URL}/trader/v1"

AUTH_URL = f"{BASE_URL}/v1/oauth/authorize"
TOKEN_URL = f"{BASE_URL}/v1/oauth/token"

QUOTES_URL = f"{MARKET_DATA_ENDPOINT}/quotes"
MARKET_HOURS_URL = f"{MARKET_DATA_ENDPOINT}/markets"
PRICE_HISTORY_URL = f"{MARKET_DATA_ENDPOINT}/pricehistory"
INSTRUMENTS_URL = f"{MARKET_DATA_ENDPOINT}/instruments"

ACCOUNT_NUMBERS_URL = f"{TRADER_API_ENDPOINT}/accounts/accountNumbers"
ACCOUNTS_URL = f"{TRADER_API_ENDPOINT}/accounts"
ORDERS_URL = f"{TRADER_API_ENDPOINT}/orders"


# Parse redirect URL for desired parameters
def get_code_from_url(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    queryArguments = parse_qs(parsed.query)

    return (queryArguments["code"][0], queryArguments["session"][0])


class AccountsField(Enum):
    POSITIONS = "positions"


class QuotesField(Enum):
    QUOTE = "quote"
    FUNDAMENTAL = "fundamental"
    EXTENDED = "extended"
    REFERENCE = "reference"
    REGULAR = "regular"


class Projection(Enum):
    SYMBOL_SEARCH = "symbol-search"
    SYMBOL_REGEX = "symbol-regex"
    DESC_SEARCH = "desc-search"
    DESC_REGEX = "desc-regex"
    SEARCH = "search"
    FUNDAMENTAL = "fundamental"


class MarketID(Enum):
    EQUITY = "equity"
    OPTION = "option"
    BOND = "bond"
    FUTURE = "future"
    FOREX = "forex"


class PeriodType(Enum):
    DAY = "day"
    MONTH = "month"
    YEAR = "year"
    YTD = "ytd"


class Period(Enum):
    ONE = 1
    TWO = 2
    THREE = 3
    FOUR = 4
    FIVE = 5
    SIX = 6
    TEN = 10
    FIFTEEN = 15
    TWENTY = 20


class PeriodOptions:
    valid_options = {
        PeriodType.DAY: {
            Period.ONE,
            Period.TWO,
            Period.THREE,
            Period.FOUR,
            Period.FIVE,
            Period.TEN,
        },
        PeriodType.MONTH: {Period.ONE, Period.TWO, Period.THREE, Period.SIX},
        PeriodType.YEAR: {
            Period.ONE,
            Period.TWO,
            Period.THREE,
            Period.FIVE,
            Period.TEN,
            Period.FIFTEEN,
            Period.TWENTY,
        },
        PeriodType.YTD: {Period.ONE},
    }

    @classmethod
    def get_default(cls, period_type: PeriodType) -> Period:
        defaults = {
            PeriodType.DAY: Period.TEN,
            PeriodType.MONTH: Period.ONE,
            PeriodType.YEAR: Period.ONE,
            PeriodType.YEAR: Period.ONE,
        }

        return defaults[period_type]

    @classmethod
    def valid_period(cls, period_type: PeriodType, period: Period) -> bool:
        return period in cls.valid_options[period_type]


class FrequencyType(Enum):
    MINUTE = "minute"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class FrequencyTypeOptions:
    valid_options = {
        PeriodType.DAY: {FrequencyType.MINUTE},
        PeriodType.MONTH: {FrequencyType.DAILY, FrequencyType.WEEKLY},
        PeriodType.YEAR: {
            FrequencyType.DAILY,
            FrequencyType.WEEKLY,
            FrequencyType.MONTHLY,
        },
        PeriodType.YTD: {FrequencyType.DAILY, FrequencyType.WEEKLY},
    }

    @classmethod
    def get_default(cls, period_type: PeriodType) -> FrequencyType:
        defaults = {
            PeriodType.DAY: FrequencyType.MINUTE,
            PeriodType.MONTH: FrequencyType.WEEKLY,
            PeriodType.YEAR: FrequencyType.MONTHLY,
            PeriodType.YEAR: FrequencyType.WEEKLY,
        }

        return defaults[period_type]

    @classmethod
    def valid_frequency_type(
        cls, period_type: PeriodType, frequency_type: FrequencyType
    ) -> bool:
        return frequency_type in cls.valid_options[period_type]


class Frequency(Enum):
    ONE = 1
    FIVE = 5
    TEN = 10
    FIFTEEN = 15
    THIRTY = 30


class FrequencyOptions:
    valid_options = {
        PeriodType.DAY: {
            Frequency.ONE,
            Frequency.FIVE,
            Frequency.TEN,
            Frequency.FIFTEEN,
            Frequency.THIRTY,
        },
        PeriodType.MONTH: {Frequency.ONE},
        PeriodType.YEAR: {Frequency.ONE},
        PeriodType.YTD: {Frequency.ONE},
    }

    @classmethod
    def get_default(cls, _: PeriodType) -> Frequency:
        return Frequency.ONE

    @classmethod
    def valid_frequency(cls, period_type: PeriodType, frequency: Frequency) -> bool:
        return frequency in cls.valid_options[period_type]


class InvalidPeriodPeriodTypeCombination(Exception):
    pass


class InvalidFrequencyTypePeriodTypeCombinatino(Exception):
    pass


class InvalidFrequencyPeriodTypeCombination(Exception):
    pass


class PeriodFrequencyParameters:
    def __init__(
        self,
        period_type: PeriodType,
        period: Optional[Period] = None,
        frequency_type: Optional[FrequencyType] = None,
        frequency: Optional[Frequency] = None,
    ) -> None:
        self.period_type = period_type

        if period:
            if not PeriodOptions.valid_period(self.period_type, period):
                raise InvalidPeriodPeriodTypeCombination(
                    f"{period} is not a valid period for {self.period_type}.\n"
                    f"Valid periods for {self.period_type} are {' | '.join([f'Period.{p.name}' for p in PeriodOptions.valid_options[self.period_type]])}"
                )
            self.period = period
        else:
            self.period = PeriodOptions.get_default(self.period_type)

        if frequency_type:
            if not FrequencyTypeOptions.valid_frequency_type(
                self.period_type, frequency_type
            ):
                raise InvalidFrequencyTypePeriodTypeCombinatino(
                    f"{frequency_type} is not a valid frequency type for {self.period_type}.\n"
                    f"Valid frequency types for {self.period_type} are {' | '.join([f'FrequencyType.{ft.name}' for ft in FrequencyTypeOptions.valid_options[self.period_type]])}"
                )
            self.frequency_type = frequency_type
        else:
            self.frequency_type = FrequencyTypeOptions.get_default(self.period_type)

        if frequency:
            if not FrequencyOptions.valid_frequency(self.period_type, frequency):
                raise InvalidFrequencyPeriodTypeCombination(
                    f"{frequency} is not a valid frequency for {self.period_type}.\n"
                    f"Valid frequencies for {self.period_type} are {' | '.join([f'Frequency.{f.name}' for f in FrequencyOptions.valid_options[self.period_type]])}"
                )
            self.frequency = frequency
        else:
            self.frequency = FrequencyOptions.get_default(self.period_type)

    def get_params(self) -> dict[str, int | str]:
        return {
            "periodType": self.period_type.value,
            "period": self.period.value,
            "frequencyType": self.frequency_type.value,
            "frequency": self.frequency.value,
        }


class OrderStatus(Enum):
    AWAITING_PARENT_ORDER = "AWAITING_PARENT_ORDER"
    AWAITING_CONDITION = "AWAITING_CONDITION"
    AWAITING_STOP_CONDITION = "AWAITING_STOP_CONDITION"
    AWAITING_MANUAL_REVIEW = "AWAITING_MANUAL_REVIEW"
    ACCEPTED = "ACCEPTED"
    AWAITING_UR_OUT = "AWAITING_UR_OUT"
    PENDING_ACTIVATION = "PENDING_ACTIVATION"
    QUEUED = "QUEUED"
    WORKING = "WORKING"
    REJECTED = "REJECTED"
    PENDING_CANCEL = "PENDING_CANCEL"
    CANCELED = "CANCELED"
    PENDING_REPLACE = "PENDING_REPLACE"
    REPLACED = "REPLACED"
    FILLED = "FILLED"
    EXPIRED = "EXPIRED"
    NEW = "NEW"
    AWAITING_RELEASE_TIME = "AWAITING_RELEASE_TIME"
    PENDING_ACKNOWLEDGEMENT = "PENDING_ACKNOWLEDGEMENT"
    PENDING_RECALL = "PENDING_RECALL"
    UNKNOWN = "UNKNOWN"
