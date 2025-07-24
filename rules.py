# rules.py

import re

PHISHING_RULES = [
    {
        "name": "Generic Greeting",
        "pattern": r"Dear (Customer|User|Valued Client|Friend|Account Holder),",
        "type": "body",
        "score": 2,
        "explanation": "Phishing emails often use generic greetings instead of your personalized name to target a wide audience. Legitimate organizations typically address you by name."
    },
    {
        "name": "Urgency/Threat Language",
        "pattern": r"(immediate action required|account suspended|security alert|urgent action|fail to confirm|your account will be closed|threat of closure|payment issue|fraud alert)",
        "type": "body",
        "score": 3,
        "explanation": "Scammers use urgent or threatening language to pressure you into acting quickly without thinking or verifying the email's legitimacy."
    },
    {
        "name": "Request for Personal Info",
        "pattern": r"(verify your account|update your details|confirm your password|provide your social security number|credit card details|bank account information)",
        "type": "body",
        "score": 4,
        "explanation": "Legitimate companies rarely ask for sensitive personal information (like passwords or full credit card numbers) directly via email or through unverified links. Always navigate directly to their official website."
    },
    {
        "name": "Suspicious Link - Text Mismatch (Concept)",
        # This is a conceptual rule. Actual implementation requires more sophisticated HTML parsing
        # For this beginner project, we'll look for common link patterns and warn generally.
        "pattern": r"https?://(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[^\s\"']*|bit\.ly|tinyurl\.com",
        "type": "body",
        "score": 5,
        "explanation": "Links in phishing emails often point to malicious websites. Even if the text looks legitimate, the actual URL can be different. Always hover over links to see the true destination or type the URL directly into your browser. Be wary of URL shorteners."
    },
    {
        "name": "Sender Spoofing - Reply-To Mismatch",
        # This regex tries to capture 'From' and 'Reply-To' for comparison
        # It's simplified and might not catch all cases, but good for a start.
        # We will parse this in the analyzer.
        "pattern": r"From:.*?<(?P<from_addr>[^>]+)>.*?Reply-To:\s*<(?P<reply_to_addr>[^>]+)>",
        "type": "header",
        "score": 5,
        "explanation": "If the 'Reply-To' address is different from the 'From' address, it indicates that replies will go to a different (potentially malicious) sender, which is a common spoofing technique."
    },
    {
        "name": "Typo/Grammar Errors",
        "pattern": r"(your accounts is|pleese|recieve|occured|securty|informtion)", # Common typos
        "type": "body",
        "score": 2,
        "explanation": "Many phishing emails contain spelling or grammatical errors. While not all legitimate emails are perfect, a high number of obvious errors is a strong red flag."
    },
    {
        "name": "Unusual Attachments (Conceptual)",
        # For simplicity, we'll flag keywords that suggest attachments if the context doesn't fit
        "pattern": r"(attachment|invoice|receipt|document|file)\.(exe|zip|js|vbs|docm|xlsm)",
        "type": "body",
        "score": 4,
        "explanation": "Unexpected attachments, especially executable files (.exe), script files (.js, .vbs), or macros-enabled documents (.docm, .xlsm), are common vectors for malware. Do not open them unless you are absolutely sure of the sender and context."
    },
    {
        "name": "Non-Personalized Security Alert",
        "pattern": r"we detected unusual activity on your account|your account has been compromised",
        "type": "body",
        "score": 3,
        "explanation": "While legitimate security alerts exist, non-personalized alerts combined with urgent language are highly suspicious. Always verify security notifications directly with the service provider."
    },
    {
        "name": "Direct Click Prompts",
        "pattern": r"(click here to|login now|update now|download now)",
        "type": "body",
        "score": 3,
        "explanation": "Phishing emails often contain direct calls to action that encourage immediate clicks without verification. Be cautious of such prompts."
    }
]
