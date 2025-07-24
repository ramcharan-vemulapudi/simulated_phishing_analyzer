# main.py

import sys
import os
from analyzer import analyze_email, get_risk_category

def get_multiline_input(prompt):
    """
    Helper function to get multi-line input from the user.
    Input ends when user enters an empty line.
    """
    print(prompt)
    lines = []
    while True:
        try:
            line = input()
            if not line:
                break
            lines.append(line)
        except EOFError: # Handles Ctrl+D on Unix-like systems
            break
    return "\n".join(lines)

def main():
    print("-" * 70)
    print("      Welcome to the Simulated Phishing Email Analyzer (SPEA)      ")
    print("-" * 70)
    print("\n")
    print("!!! IMPORTANT DISCLAIMER !!!")
    print("------------------------------------------------------------------")
    print("This tool is for EDUCATIONAL AND SIMULATION PURPOSES ONLY.")
    print("DO NOT use this tool to analyze REAL, LIVE emails.")
    print("Analyzing real emails with third-party tools can expose sensitive")
    print("information and violate privacy. Always use official methods for")
    print("reporting suspicious emails (e.g., your email provider's tools).")
    print("------------------------------------------------------------------")
    print("\n")

    print("Please paste or type your SIMULATED EMAIL HEADER below.")
    print("Press ENTER twice (empty line) to finish header input.")
    simulated_header = get_multiline_input(">>> Header (e.g., From: John Doe <john@example.com>):")

    print("\n")

    print("Please paste or type your SIMULATED EMAIL BODY below.")
    print("Press ENTER twice (empty line) to finish body input.")
    simulated_body = get_multiline_input(">>> Body:")

    if not simulated_header and not simulated_body:
        print("\nNo input provided. Exiting analyzer.")
        sys.exit(0)

    print("\n" + "=" * 70)
    print("Analyzing Simulated Email...")
    print("=" * 70)

    total_score, triggered_alerts = analyze_email(simulated_header, simulated_body)
    risk_category = get_risk_category(total_score)

    print(f"\nTotal Risk Score: {total_score}")
    print(f"Risk Category: {risk_category}\n")

    if triggered_alerts:
        print("Detected Suspicious Characteristics:")
        print("------------------------------------")
        for alert in triggered_alerts:
            print(f"- {alert['name']}: {alert['explanation']}\n")
    else:
        print("No obvious suspicious characteristics detected by the current rules.")
        print("Remember, this is a SIMULATED analysis and not exhaustive.")

    print("\n" + "=" * 70)
    print("General Advice for Real Emails:")
    print("------------------------------------")
    print("1. **Verify Sender:** Check the sender's full email address, not just the name.")
    print("2. **Hover Over Links:** Before clicking, hover your mouse over links to see the actual URL. If it looks suspicious, do not click.")
    print("3. **Check for Urgency/Threats:** Be wary of emails demanding immediate action or threatening consequences.")
    print("4. **Look for Generic Greetings & Errors:** 'Dear Customer' and obvious typos are red flags.")
    print("5. **Never Share Sensitive Info:** Legitimate organizations won't ask for passwords or sensitive details via email.")
    print("6. **Report & Delete:** If you suspect a real email is phishing, report it to your email provider or IT department, then delete it.")
    print("7. **When in Doubt, Throw it Out:** If something feels off, it probably is. Err on the side of caution.")
    print("=" * 70)

if __name__ == "__main__":
    main()
