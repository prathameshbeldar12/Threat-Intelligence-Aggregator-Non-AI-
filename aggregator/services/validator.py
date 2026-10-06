import ipaddress
import re
from urllib.parse import urlparse

# Regex patterns
DOMAIN_PATTERN = re.compile(
    r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])'
    r'(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))+$'
)
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')

def validate_ip(value):
    """
    Validates if the value is a valid IPv4 address.
    """
    if not value or not isinstance(value, str):
        return False
    try:
        ip = ipaddress.ip_address(value.strip())
        return ip.version == 4
    except ValueError:
        return False

def validate_domain(value):
    """
    Validates if the value is a valid domain structure.
    """
    if not value or not isinstance(value, str):
        return False
    val = value.strip()
    # Length checks
    if len(val) > 253 or len(val) < 3:
        return False
    # Regex check
    if not DOMAIN_PATTERN.match(val):
        return False
    # Check segment lengths (each part must be <= 63 chars)
    parts = val.split('.')
    if any(len(part) > 63 or len(part) == 0 for part in parts):
        return False
    # Simple check for TLD (must not be all numeric)
    if parts[-1].isdigit():
        return False
    return True

def validate_url(value):
    """
    Validates if the value is a valid URL structure.
    """
    if not value or not isinstance(value, str):
        return False
    val = value.strip()
    try:
        parsed = urlparse(val)
        # Must have scheme and network location (domain/IP)
        if not parsed.scheme or not parsed.netloc:
            return False
        if parsed.scheme.lower() not in ['http', 'https', 'ftp', 'sftp']:
            return False
        # Validate netloc (strip port if present)
        host = parsed.netloc.split(':')[0]
        return validate_ip(host) or validate_domain(host)
    except Exception:
        return False

def validate_hash(value):
    """
    Validates if the value matches MD5, SHA1 or SHA256 hexadecimal formats.
    """
    if not value or not isinstance(value, str):
        return False
    val = value.strip()
    return bool(MD5_PATTERN.match(val) or SHA1_PATTERN.match(val) or SHA256_PATTERN.match(val))

def validate_email(value):
    """
    Validates if the value is a valid email structure.
    """
    if not value or not isinstance(value, str):
        return False
    val = value.strip()
    if len(val) > 254:
        return False
    return bool(EMAIL_PATTERN.match(val))

def validate_ioc(value, ioc_type):
    """
    Dispatcher to validate a specific type of IOC.
    """
    type_map = {
        'IPv4': validate_ip,
        'Domain': validate_domain,
        'URL': validate_url,
        'Hash': validate_hash,
        'Email': validate_email,
    }
    validator = type_map.get(ioc_type)
    if validator:
        return validator(value)
    return False
