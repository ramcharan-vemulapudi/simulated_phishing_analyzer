# analyzer.py

import re
from rules import PHISHING_RULES

def analyze_email(header_text, body_text):
    """
    Analyzes simulated email header and body for phishing characteristics.

    Args:
        header_text (str): The simulated email header content.
        body_text (str): The simulated email body content.

    Returns:
        tuple: (total_score, triggered_alerts)
               total_score (int): The sum of scores for triggered rules.
               triggered_alerts (list): A list of dictionaries, each containing
                                        'name' and 'explanation' of triggered rules.
    """
    total_score = 0
    triggered_alerts = []

    for rule in PHISHING_RULES:
        pattern = rule['pattern']
        text_to_analyze = ""

        if rule['type'] == 'header':
            text_to_analyze = header_text
        elif rule['type'] == 'body':
            text_to_analyze = body_text
        else:
            continue # Skip if rule type is unknown

        # Specific handling for Sender Spoofing - Reply-To Mismatch
        if rule['name'] == "Sender Spoofing - Reply-To Mismatch" and rule['type'] == 'header':
            match = re.search(pattern, text_to_analyze, re.IGNORECASE | re.DOTALL)
            if match:
                from_addr = match.group('from_addr').strip()
                reply_to_addr = match.group('reply_to_addr').strip()
                if from_addr.lower() != reply_to_addr.lower():
                    total_score += rule['score']
                    triggered_alerts.append({
                        "name": rule['name'],
                        "explanation": rule['explanation']
                    })
            continue # Move to the next rule

        # General pattern matching for other rules
        if re.search(pattern, text_to_analyze, re.IGNORECASE | re.DOTALL):
            total_score += rule['score']
            triggered_alerts.append({
                "name": rule['name'],
                "explanation": rule['explanation']
            })

    return total_score, triggered_alerts

def get_risk_category(score):
    """
    Determines the risk category based on the total score.

    Args:
        score (int): The total phishing risk score.

    Returns:
        str: The risk category (e.g., "Low", "Medium", "High", "Very High").
    """
    if score >= 15:
        return "Very High"
    elif score >= 10:
        return "High"
    elif score >= 5:
        return "Medium"
    else:
        return "Low"
