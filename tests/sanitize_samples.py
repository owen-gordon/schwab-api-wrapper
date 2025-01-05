import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Union, Set
from datetime import datetime, timedelta

SAMPLE_DIR = Path(__file__).parent / "sample_responses"
SANITIZED_DIR = Path(__file__).parent / "sample_responses_sanitized"

# Common replacement values
SAMPLE_SYMBOLS = ["AAPL", "MSFT", "GOOGL", "F", "T"]
SAMPLE_ACCOUNT = "DEMO123456"
SAMPLE_CUSIP = "000000000"
SAMPLE_ORDER_ID = "12345678"
SAMPLE_DATE = datetime(2024, 1, 1, 12, 0, 0)  # Use a fixed date for consistency
SAMPLE_DESCRIPTION = "Sample Transaction"
SAMPLE_BANK = "DEMO BANK"

# Fields that should preserve their original values
PRESERVE_FIELDS = {
    "isOpen", "realtime", "isShortable", "indicative",
    "assetMainType", "assetSubType", "divFreq", "type",
    "status", "feeType", "positionEffect", "instruction",
    "activityType", "securityStatus", "exchangeName", "exchange",
    "assetType", "date", "declarationDate", "dividendDate",
    "dividendPayDate", "nextDividendDate", "nextDividendPayDate",
    "invalidSymbols"  # Option symbols can contain dates
}

# Additional safe values that should not trigger validation errors
SAFE_VALUES = {
    # Status values
    "Normal", "Closed", "EXECUTION", "VALID",
    
    # Asset types
    "CASH_EQUIVALENT", "EQUITY", "MUTUAL_FUND", "CURRENCY",
    
    # Exchange names
    "Index", "Mutual Fund", "NYSE", "NASDAQ",
    
    # Security statuses
    "ACTIVE", "INACTIVE",
    
    # Special symbols
    "$SPX", "FXAIX", "CURRENCY_USD",
    "DJX 231215C00290000",  # Example option symbol
    
    # Common descriptive values
    "COMMON_STOCK", "SWEEP_VEHICLE",
    
    # Standard account values
    "CASH", "MARGIN",
    
    # Sample/demo values
    SAMPLE_ACCOUNT, SAMPLE_CUSIP, SAMPLE_DESCRIPTION, SAMPLE_BANK,
    *SAMPLE_SYMBOLS, "Sample Transaction", "Transfer from DEMO BANK",
    "DEMO123456", "000000000", "string"
}

# Valid enum values
VALID_DIV_FREQ = [0, 1, 2, 3, 4, 6, 11, 12]
VALID_ASSET_SUBTYPES = {
    "EQUITY": ["COE", "PRF", "ADR", "GDR", "CEF", "ETF", "ETN", "UIT", "WAR", "RGT"],
    "MUTUAL_FUND": ["OEF", "CEF", "MMF"],
}

# Patterns for sensitive data
SENSITIVE_PATTERNS = {
    "cusip": r"[0-9A-Z]{9}",  # 9 character CUSIP
    "account_number": r"\b\d{8,12}\b",  # 8-12 digit account numbers
    "routing_number": r"\b\d{9}\b",  # 9 digit routing numbers
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email addresses
    "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # Phone numbers
    "ssn": r"\b\d{3}[-]?\d{2}[-]?\d{4}\b",  # Social Security Numbers
    "date": r"\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b",  # Dates in common formats
    "name": r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)?\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b",  # Common name patterns
    "bank": r"\b(?:Bank|BANK|bank)\s+(?:of|OF|of)\s+[A-Za-z\s]+\b|\b[A-Za-z]+\s+(?:Bank|BANK|bank)\b",  # Bank names
}

# Fields that are known to be sensitive but have special handling
SENSITIVE_FIELDS = {
    "cusip", "accountNumber", "routingNumber", "email", "phone", 
    "ssn", "name", "description", "symbol", "instrumentId"
}

class SensitiveDataError(Exception):
    """Exception raised when sensitive data is found in sanitized output."""
    pass

def is_date_field(path: str) -> bool:
    """Check if the field is a date-related field that should be preserved."""
    date_fields = {
        "date", "declarationDate", "dividendDate",
        "dividendPayDate", "nextDividendDate", "nextDividendPayDate",
        "tradeDate", "settlementDate", "time", "enteredTime",
        "closeTime"
    }
    return any(field in path.lower() for field in date_fields)

def is_sanitized_value(value: Any, field_type: str, path: str = "") -> bool:
    """Check if a value matches known safe/sanitized values."""
    if not isinstance(value, str):
        return True
    
    # Check if value is in the safe values set
    if value in SAFE_VALUES:
        return True
    
    # Add common safe values for specific field types
    if field_type == "symbol":
        return value in SAMPLE_SYMBOLS or value in {"CURRENCY_USD", "$SPX", "FXAIX"}
    elif field_type == "cusip":
        return value == SAMPLE_CUSIP or value == "000000000"
    elif field_type == "description":
        return value == SAMPLE_DESCRIPTION or value.startswith("Transfer from")
    elif field_type == "date" or is_date_field(path):
        # Accept both our sanitized format and the original format
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%S+0000")
            return True
        except ValueError:
            try:
                datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
                return True
            except ValueError:
                try:
                    datetime.strptime(value, "%Y-%m-%d")
                    return True
                except ValueError:
                    return False
    
    return False

def validate_no_sensitive_data(data: Any, path: str = "") -> Set[str]:
    """
    Recursively validate that no sensitive data patterns exist in the sanitized data.
    Returns a set of validation errors found.
    """
    errors = set()
    
    if isinstance(data, dict):
        for key, value in data.items():
            new_path = f"{path}.{key}" if path else key
            
            # Skip validation for preserved fields
            if key in PRESERVE_FIELDS:
                continue
                
            # Check if this is a known sensitive field
            if key in SENSITIVE_FIELDS:
                if not is_sanitized_value(value, key, new_path):
                    errors.add(f"Sensitive field '{new_path}' contains potentially unsanitized value: {value}")
            
            # Recurse into nested structures
            errors.update(validate_no_sensitive_data(value, new_path))
            
    elif isinstance(data, list):
        for i, item in enumerate(data):
            new_path = f"{path}[{i}]"
            errors.update(validate_no_sensitive_data(item, new_path))
            
    elif isinstance(data, str):
        # Skip validation for paths that contain preserved field names
        if any(field in path for field in PRESERVE_FIELDS):
            return errors
            
        # Check string against all sensitive patterns
        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, data):
                # Ignore matches that are known safe values
                if not is_sanitized_value(data, pattern_name, path):
                    errors.add(f"Found potential {pattern_name} in {path}: {data}")
    
    return errors

def get_valid_div_freq(current_value: int) -> int:
    """Get a valid dividend frequency value."""
    return VALID_DIV_FREQ[0]  # Always use the first valid value

def get_valid_asset_subtype(asset_main_type: str) -> str:
    """Get a valid asset subtype for the given main type."""
    valid_subtypes = VALID_ASSET_SUBTYPES.get(asset_main_type, [])
    return valid_subtypes[0] if valid_subtypes else "COE"

def sanitize_date(value: str) -> str:
    """Convert any date string to a sanitized date string in the same format."""
    try:
        # Parse the date string and generate a new one with the same format
        original_date = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z")
        time_delta = timedelta(days=(original_date - SAMPLE_DATE).days % 30)  # Keep relative dates within a month
        return (SAMPLE_DATE + time_delta).strftime("%Y-%m-%dT%H:%M:%S+0000")
    except (ValueError, TypeError):
        return SAMPLE_DATE.strftime("%Y-%m-%dT%H:%M:%S+0000")

def sanitize_description(value: str) -> str:
    """Sanitize description strings that might contain sensitive information."""
    if any(keyword in value.lower() for keyword in ["bank", "transfer", "tfr", "ach", "wire"]):
        return f"Transfer from {SAMPLE_BANK}"
    return SAMPLE_DESCRIPTION

def sanitize_number(value: Union[int, float], preserve_small_numbers: bool = False) -> Union[int, float]:
    """Replace actual numbers with sample values while preserving data type."""
    if preserve_small_numbers and (isinstance(value, bool) or (isinstance(value, (int, float)) and value <= 1)):
        return value  # Preserve booleans and small numbers (0-1 range)
    
    if isinstance(value, int):
        return 100 if value > 0 else 0
    return 100.00 if value > 0 else 0.00

def sanitize_string(value: str, key: str = None, parent_context: Dict[str, Any] = None) -> str:
    """Sanitize potentially sensitive strings."""
    # Handle specific field types
    if key == "description":
        return sanitize_description(value)
    elif key == "time" or key == "enteredTime" or key == "closeTime" or key == "tradeDate" or key == "settlementDate":
        return sanitize_date(value)
    elif key == "cusip":
        return SAMPLE_CUSIP
    
    # Preserve specific field values
    if key in PRESERVE_FIELDS:
        if key == "assetSubType" and parent_context and "assetMainType" in parent_context:
            return get_valid_asset_subtype(parent_context["assetMainType"])
        return value
    
    if value.isdigit():  # Account numbers, order IDs, etc.
        return SAMPLE_ACCOUNT
    return value

def sanitize_instrument(instrument: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize instrument data while preserving required fields."""
    sanitized = {}
    for key, value in instrument.items():
        if key in PRESERVE_FIELDS:
            sanitized[key] = value
        elif key == "symbol":
            sanitized[key] = SAMPLE_SYMBOLS[0]
        elif key == "cusip":
            sanitized[key] = SAMPLE_CUSIP
        else:
            sanitized[key] = sanitize_value(value, key, parent_context=instrument)
    return sanitized

def sanitize_quote(quote: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize quote data while ensuring required fields are present."""
    sanitized = {}
    # Preserve all original fields
    for key, value in quote.items():
        sanitized[key] = sanitize_value(value, key)
    
    # Ensure required fields are present with valid values
    required_fields = {
        "askPrice": 100.0,
        "askSize": 100,
        "askTime": 100,
        "bidPrice": 100.0,
        "bidSize": 100,
        "bidTime": 100,
        "highPrice": 100.0,
        "lastPrice": 100.0,
        "lastSize": 100,
        "lowPrice": 100.0,
        "mark": 100.0,
        "markChange": 10.0,
        "markPercentChange": 1.0,
        "openPrice": 100.0,
        "quoteTime": 100,
        "totalVolume": 1000,
        "nAV": 100.0,  # Required for mutual funds
    }
    
    for field, default_value in required_fields.items():
        if field not in sanitized:
            sanitized[field] = default_value
    
    return sanitized

def sanitize_fundamental(fundamental: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize fundamental data while ensuring valid enum values."""
    sanitized = {}
    for key, value in fundamental.items():
        if key == "divFreq":
            sanitized[key] = get_valid_div_freq(value)
        else:
            sanitized[key] = sanitize_value(value, key)
    return sanitized

def sanitize_value(value: Any, key: str = None, parent_context: Dict[str, Any] = None) -> Any:
    """Recursively sanitize values in the JSON structure."""
    if isinstance(value, bool):
        return value  # Always preserve boolean values
    elif isinstance(value, (int, float)):
        if key == "divFreq":
            return get_valid_div_freq(value)
        return sanitize_number(value, preserve_small_numbers=key in PRESERVE_FIELDS)
    elif isinstance(value, str):
        return sanitize_string(value, key, parent_context)
    elif isinstance(value, dict):
        if key == "quote":  # Special handling for quote objects
            return sanitize_quote(value)
        elif key == "fundamental":  # Special handling for fundamental objects
            return sanitize_fundamental(value)
        elif key == "instrument":  # Special handling for instrument objects
            return sanitize_instrument(value)
        return {k: sanitize_value(v, k, parent_context=value) for k, v in value.items()}
    elif isinstance(value, list):
        return [sanitize_value(item, key) for item in value]
    return value

def sanitize_file(input_path: Path, output_path: Path):
    """Sanitize a single sample response file."""
    with open(input_path, 'r') as f:
        data = json.load(f)
    
    # Sanitize the data
    sanitized_data = sanitize_value(data)
    
    # Validate the sanitized data
    validation_errors = validate_no_sensitive_data(sanitized_data)
    if validation_errors:
        print(f"\nValidation errors found in {input_path.name}:")
        for error in sorted(validation_errors):
            print(f"  - {error}")
        raise SensitiveDataError(f"Sensitive data found in sanitized output for {input_path.name}")
    
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write sanitized data
    with open(output_path, 'w') as f:
        json.dump(sanitized_data, f, indent=4)

def main():
    """Sanitize all sample response files."""
    SANITIZED_DIR.mkdir(parents=True, exist_ok=True)
    
    any_errors = False
    for file_path in SAMPLE_DIR.glob('*.json'):
        output_path = SANITIZED_DIR / file_path.name
        print(f"Sanitizing {file_path.name}...")
        try:
            sanitize_file(file_path, output_path)
            print(f"Created sanitized version at {output_path}")
        except SensitiveDataError as e:
            print(f"Error: {e}")
            any_errors = True
            continue
    
    if any_errors:
        print("\nSanitization completed with errors. Please review the output above.")
        exit(1)
    else:
        print("\nSanitization completed successfully!")

if __name__ == "__main__":
    main() 