from django.utils import timezone
import datetime

def calculate_risk_and_severity(source_count, occurrence_count, ioc_type, categories=None, last_seen=None):
    """
    Deterministically calculates risk score (0-100), severity, and generating a text reason.
    No AI/ML.
    
    Base score rules:
    - 1 feed: 20 points
    - 2 feeds: 40 points
    - 3 feeds: 60 points
    - 4 feeds: 80 points
    - 5+ feeds: 100 points
    
    Additions:
    - Occurrences: +2 points per occurrence, capped at +15 points.
    - IOC Type Weight: +5 points for Hash, URL, Email (often highly specific indicators), +2 points for IP, Domain.
    - Category Weight: +10 points if feed categories contain 'malware', 'ransomware', 'phishing', or 'botnet'.
    - Recency Weight: +10 points if seen within the last 24 hours.
    
    Rules cap at 100.
    
    Severity:
    - 0-24: Low
    - 25-49: Medium
    - 50-74: High
    - 75-100: Critical
    """
    if source_count <= 0:
        return 0, 'Low', "No active sources reported for this indicator."
        
    # 1. Base Score calculation
    if source_count == 1:
        base_score = 20
    elif source_count == 2:
        base_score = 40
    elif source_count == 3:
        base_score = 60
    elif source_count == 4:
        base_score = 80
    else:
        base_score = 100
        
    additions = 0
    reasons_list = [f"Observed in {source_count} independent feeds (Base: {base_score} pts)."]
    
    # 2. Add occurrences bonus
    if occurrence_count > 0:
        occ_bonus = min(occurrence_count * 2, 15)
        additions += occ_bonus
        reasons_list.append(f"Recorded {occurrence_count} total occurrences (+{occ_bonus} pts).")
        
    # 3. Add IOC Type Weight
    type_bonus = 0
    if ioc_type in ['Hash', 'URL', 'Email']:
        type_bonus = 5
        additions += type_bonus
        reasons_list.append(f"High-specificity indicator type {ioc_type} (+{type_bonus} pts).")
    elif ioc_type in ['IPv4', 'Domain']:
        type_bonus = 2
        additions += type_bonus
        reasons_list.append(f"Standard indicator type {ioc_type} (+{type_bonus} pts).")
        
    # 4. Add Category Weight
    if categories:
        has_critical_cat = False
        cat_matches = []
        for cat in categories:
            cat_lower = str(cat).lower()
            if any(term in cat_lower for term in ['malware', 'ransomware', 'phishing', 'botnet', 'exploit', 'compromised']):
                has_critical_cat = True
                cat_matches.append(cat)
                
        if has_critical_cat:
            additions += 10
            reasons_list.append(f"Associated with critical threat categories: {', '.join(cat_matches[:2])} (+10 pts).")
            
    # 5. Add Recency Weight
    if last_seen:
        now = timezone.now()
        delta = now - last_seen
        if delta < datetime.timedelta(hours=24):
            additions += 10
            reasons_list.append("Observed recently (within last 24 hours) (+10 pts).")
            
    # Calculate final score (max 100)
    risk_score = min(base_score + additions, 100)
    
    # Severity classification
    if risk_score <= 24:
        severity = 'Low'
    elif risk_score <= 49:
        severity = 'Medium'
    elif risk_score <= 74:
        severity = 'High'
    else:
        severity = 'Critical'
        
    # Join reasons
    reason = " ".join(reasons_list)
    if risk_score == 100 and (base_score + additions) > 100:
        reason += " Risk score capped at maximum value of 100."
        
    return risk_score, severity, reason
