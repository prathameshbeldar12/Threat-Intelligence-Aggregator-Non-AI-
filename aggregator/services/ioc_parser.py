import re
from aggregator.services.validator import (
    validate_ip, validate_domain, validate_url, validate_hash, validate_email
)

# Regex for extracting candidate tokens from free-form text
# IP Candidate: simple digit and dot boundaries
IP_CANDIDATE = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
# Email Candidate
EMAIL_CANDIDATE = re.compile(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b')
# Hash Candidate (MD5/SHA1/SHA256 hex strings)
HASH_CANDIDATE = re.compile(r'\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b', re.IGNORECASE)
# URL Candidate (starts with http/https/ftp)
URL_CANDIDATE = re.compile(r'\b(?:https?|ftp|sftp)://[^\s/$.?#].[^\s]*', re.IGNORECASE)
# Domain Candidate: tokens separated by dots (excluding IPs and emails)
DOMAIN_CANDIDATE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,18}\b', re.IGNORECASE)

def detect_ioc_type(value):
    """
    Detects and validates the IOC type of a given string.
    Returns 'IPv4', 'Domain', 'URL', 'Hash', 'Email', or None.
    """
    if not value or not isinstance(value, str):
        return None
    
    val = value.strip()
    
    # Try Hash first (since it is regex-simple)
    if validate_hash(val):
        return 'Hash'
    # Try IP
    if validate_ip(val):
        return 'IPv4'
    # Try Email
    if validate_email(val):
        return 'Email'
    # Try URL
    if validate_url(val):
        return 'URL'
    # Try Domain
    if validate_domain(val):
        return 'Domain'
        
    return None

def extract_iocs_from_text(text):
    """
    Extracts all valid, normalized IOCs from a block of text.
    Returns a list of dicts: [{'value': original_value, 'type': detected_type}]
    """
    if not text:
        return []
        
    results = []
    seen_values = set()

    # Helper to add unique valid values
    def add_if_valid(val, ioc_type):
        if val not in seen_values:
            seen_values.add(val)
            results.append({
                'value': val,
                'type': ioc_type
            })

    # 1. Extract URL candidates
    for match in URL_CANDIDATE.findall(text):
        if validate_url(match):
            add_if_valid(match, 'URL')

    # 2. Extract Email candidates
    for match in EMAIL_CANDIDATE.findall(text):
        if validate_email(match):
            add_if_valid(match, 'Email')

    # 3. Extract IP candidates
    for match in IP_CANDIDATE.findall(text):
        if validate_ip(match):
            add_if_valid(match, 'IPv4')

    # 4. Extract Hash candidates
    for match in HASH_CANDIDATE.findall(text):
        if validate_hash(match):
            add_if_valid(match, 'Hash')

    # 5. Extract Domain candidates
    for match in DOMAIN_CANDIDATE.findall(text):
        # Prevent adding part of emails or URLs as domains
        if validate_domain(match):
            # Check if this domain is already part of an extracted URL or Email
            is_subpart = False
            for r in results:
                if r['type'] in ['URL', 'Email'] and match.lower() in r['value'].lower():
                    is_subpart = True
                    break
            if not is_subpart:
                add_if_valid(match, 'Domain')

    return results
