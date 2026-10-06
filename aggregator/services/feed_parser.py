import csv
import json
import re
from aggregator.services.ioc_parser import detect_ioc_type
from aggregator.services.normalizer import normalize_ioc
from aggregator.services.validator import validate_ioc

# Header aliases for mapping fields
INDICATOR_ALIASES = ['indicator', 'ioc', 'value', 'ip', 'domain', 'url', 'hash', 'email', 'address']
TYPE_ALIASES = ['type', 'ioc_type', 'indicator_type']

def parse_txt_feed(content):
    """
    Parses a TXT feed: one indicator per line. Comments starting with # or // are ignored.
    """
    successful = []
    rejected = []
    
    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        # Ignore comments or empty lines
        if not line or line.startswith('#') or line.startswith('//'):
            continue
            
        # Detect type
        detected_type = detect_ioc_type(line)
        if detected_type:
            normalized = normalize_ioc(line, detected_type)
            successful.append({
                'raw_value': line,
                'normalized_value': normalized,
                'type': detected_type
            })
        else:
            rejected.append({
                'raw_value': line,
                'reason': f"Could not detect valid IOC type at line {line_num}"
            })
            
    return successful, rejected

def parse_csv_feed(content):
    """
    Parses a CSV feed by finding indicator columns automatically.
    """
    successful = []
    rejected = []
    
    # Try parsing CSV lines
    lines = content.splitlines()
    if not lines:
        return [], []
        
    reader = csv.reader(lines)
    try:
        headers = next(reader)
    except StopIteration:
        return [], []
        
    # Standardize headers to lowercase and strip whitespace
    headers_clean = [h.strip().lower() for h in headers]
    
    # Find columns
    indicator_idx = -1
    type_idx = -1
    
    for alias in INDICATOR_ALIASES:
        if alias in headers_clean:
            indicator_idx = headers_clean.index(alias)
            break
            
    for alias in TYPE_ALIASES:
        if alias in headers_clean:
            type_idx = headers_clean.index(alias)
            break
            
    # Fallback: if no indicator alias found, use the first column
    if indicator_idx == -1 and len(headers_clean) > 0:
        indicator_idx = 0

    # Parse rows
    for row_num, row in enumerate(reader, 2):
        if not row or len(row) <= indicator_idx:
            continue
            
        raw_val = row[indicator_idx].strip()
        if not raw_val:
            continue
            
        # Determine/detect type
        ioc_type = None
        if type_idx != -1 and type_idx < len(row):
            provided_type = row[type_idx].strip().lower()
            # Map provided type to standard format
            if 'ip' in provided_type:
                ioc_type = 'IPv4'
            elif 'domain' in provided_type:
                ioc_type = 'Domain'
            elif 'url' in provided_type:
                ioc_type = 'URL'
            elif 'hash' in provided_type:
                ioc_type = 'Hash'
            elif 'email' in provided_type:
                ioc_type = 'Email'
                
        # If type not provided or invalid mapping, automatically detect
        if not ioc_type:
            ioc_type = detect_ioc_type(raw_val)
            
        if ioc_type and validate_ioc(raw_val, ioc_type):
            normalized = normalize_ioc(raw_val, ioc_type)
            successful.append({
                'raw_value': raw_val,
                'normalized_value': normalized,
                'type': ioc_type
            })
        else:
            rejected.append({
                'raw_value': raw_val,
                'reason': f"Validation failed or type undetectable at row {row_num}"
            })
            
    return successful, rejected

def extract_stix_indicators(data):
    """
    Parses STIX patterns for indicators if STIX JSON structure is present.
    Pattern examples: 
    - [ipv4-addr:value = '192.168.1.100']
    - [domain-name:value = 'malicious.com']
    - [file:hashes.'SHA-256' = '275a021b...']
    """
    successful = []
    rejected = []
    
    # Simple regex to parse STIX patterns
    pattern_re = re.compile(r"\[([\w\-:]+)\s*=\s*'([^']+)'\]")
    
    objects = data.get('objects', [])
    for obj in objects:
        if obj.get('type') == 'indicator' and 'pattern' in obj:
            pat = obj['pattern']
            match = pattern_re.search(pat)
            if match:
                stix_type, value = match.groups()
                # Map STIX type
                ioc_type = None
                if 'ipv4-addr' in stix_type:
                    ioc_type = 'IPv4'
                elif 'domain' in stix_type:
                    ioc_type = 'Domain'
                elif 'url' in stix_type:
                    ioc_type = 'URL'
                elif 'file:hashes' in stix_type or 'hash' in stix_type:
                    ioc_type = 'Hash'
                elif 'email' in stix_type:
                    ioc_type = 'Email'
                    
                if not ioc_type:
                    ioc_type = detect_ioc_type(value)
                    
                if ioc_type and validate_ioc(value, ioc_type):
                    normalized = normalize_ioc(value, ioc_type)
                    successful.append({
                        'raw_value': value,
                        'normalized_value': normalized,
                        'type': ioc_type
                    })
                else:
                    rejected.append({
                        'raw_value': value,
                        'reason': f"STIX pattern validation failed: {pat}"
                    })
    return successful, rejected

def parse_json_feed(content):
    """
    Parses JSON feed content. Supports list of dicts, single dict, or STIX format.
    """
    successful = []
    rejected = []
    
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return [], [{'raw_value': 'JSON Content', 'reason': f"Invalid JSON format: {str(e)}"}]
        
    # Check if this is a STIX bundle
    if isinstance(data, dict) and data.get('type') == 'bundle' and 'objects' in data:
        return extract_stix_indicators(data)
        
    # If list of objects
    if isinstance(data, list):
        for idx, item in enumerate(data):
            if not isinstance(item, dict):
                rejected.append({'raw_value': str(item), 'reason': f"JSON list item at index {idx} is not an object"})
                continue
                
            # Search keys
            indicator_val = None
            detected_type = None
            
            # Find indicator key
            for alias in INDICATOR_ALIASES:
                if alias in item:
                    indicator_val = str(item[alias]).strip()
                    break
                    
            if not indicator_val:
                # If no alias match, take first key-value pair that has string length > 0
                for k, v in item.items():
                    if v and isinstance(v, (str, int, float)):
                        indicator_val = str(v).strip()
                        break
                        
            if not indicator_val:
                rejected.append({'raw_value': str(item), 'reason': f"No indicator key found at list item {idx}"})
                continue
                
            # Find type key
            for alias in TYPE_ALIASES:
                if alias in item:
                    provided_type = str(item[alias]).strip().lower()
                    if 'ip' in provided_type:
                        detected_type = 'IPv4'
                    elif 'domain' in provided_type:
                        detected_type = 'Domain'
                    elif 'url' in provided_type:
                        detected_type = 'URL'
                    elif 'hash' in provided_type:
                        detected_type = 'Hash'
                    elif 'email' in provided_type:
                        detected_type = 'Email'
                    break
                    
            if not detected_type:
                detected_type = detect_ioc_type(indicator_val)
                
            if detected_type and validate_ioc(indicator_val, detected_type):
                normalized = normalize_ioc(indicator_val, detected_type)
                successful.append({
                    'raw_value': indicator_val,
                    'normalized_value': normalized,
                    'type': detected_type
                })
            else:
                rejected.append({
                    'raw_value': indicator_val,
                    'reason': f"JSON validation failed or type undetectable at index {idx}"
                })
                
    elif isinstance(data, dict):
        # Single object JSON
        indicator_val = None
        detected_type = None
        
        for alias in INDICATOR_ALIASES:
            if alias in data:
                indicator_val = str(data[alias]).strip()
                break
                
        if indicator_val:
            detected_type = detect_ioc_type(indicator_val)
            if detected_type and validate_ioc(indicator_val, detected_type):
                normalized = normalize_ioc(indicator_val, detected_type)
                successful.append({
                    'raw_value': indicator_val,
                    'normalized_value': normalized,
                    'type': detected_type
                })
            else:
                rejected.append({
                    'raw_value': indicator_val,
                    'reason': "JSON object validation failed"
                })
        else:
            rejected.append({
                'raw_value': 'JSON Object',
                'reason': "No matching indicator keys found in JSON root object"
            })
            
    else:
        rejected.append({
            'raw_value': str(data),
            'reason': "Unsupported JSON format (must be list of objects, single object, or STIX)"
        })
        
    return successful, rejected

def parse_feed_content(content, feed_type):
    """
    Main parser gateway.
    """
    ftype = feed_type.upper()
    if ftype == 'CSV':
        return parse_csv_feed(content)
    elif ftype == 'JSON':
        return parse_json_feed(content)
    elif ftype == 'TXT':
        return parse_txt_feed(content)
    else:
        return [], [{'raw_value': 'ALL', 'reason': f"Unsupported feed format type: {feed_type}"}]
