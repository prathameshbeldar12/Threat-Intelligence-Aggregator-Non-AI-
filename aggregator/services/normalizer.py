from urllib.parse import urlparse, urlunparse

def normalize_ip(value):
    """
    Normalizes an IP address by stripping whitespaces.
    """
    if not value:
        return ""
    return value.strip()

def normalize_domain(value):
    """
    Normalizes a domain by stripping whitespaces, lowercasing, and removing trailing dots.
    """
    if not value:
        return ""
    val = value.strip().lower()
    if val.endswith('.'):
        val = val[:-1]
    return val

def normalize_url(value):
    """
    Normalizes a URL structure. Lowercases the scheme and network location,
    removes standard ports, and standardizes trailing characters.
    """
    if not value:
        return ""
    val = value.strip()
    try:
        parsed = urlparse(val)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Remove standard ports if present
        if scheme == 'http' and netloc.endswith(':80'):
            netloc = netloc[:-3]
        elif scheme == 'https' and netloc.endswith(':443'):
            netloc = netloc[:-4]
            
        path = parsed.path
        # Normalize double slashes in paths except prefix
        while '//' in path:
            path = path.replace('//', '/')
            
        # Reconstruct URL
        normalized = urlunparse((
            scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        return normalized
    except Exception:
        return val

def normalize_hash(value):
    """
    Normalizes a hash by stripping whitespaces and lowercasing.
    """
    if not value:
        return ""
    return value.strip().lower()

def normalize_email(value):
    """
    Normalizes an email by stripping whitespaces and lowercasing.
    """
    if not value:
        return ""
    return value.strip().lower()

def normalize_ioc(value, ioc_type):
    """
    Dispatcher to normalize a specific type of IOC.
    """
    type_map = {
        'IPv4': normalize_ip,
        'Domain': normalize_domain,
        'URL': normalize_url,
        'Hash': normalize_hash,
        'Email': normalize_email,
    }
    normalizer = type_map.get(ioc_type)
    if normalizer:
        return normalizer(value)
    return value.strip()
