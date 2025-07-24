# Simulated Phishing Email Analyzer (SPEA)

## ⚠️ IMPORTANT DISCLAIMER ⚠️

**This tool is for EDUCATIONAL AND SIMULATION PURPOSES ONLY.**

**DO NOT use this tool to analyze REAL, LIVE emails.** Analyzing real emails with third-party tools can expose sensitive information and violate privacy and security protocols. Always use official methods for reporting suspicious emails (e.g., your email provider's built-in tools or your organization's IT security department).

---

## Project Overview

The **Simulated Phishing Email Analyzer (SPEA)** is a Python command-line tool designed to help users understand and identify common characteristics of phishing emails. It takes user-provided *simulated* email header and body content as input, analyzes it against a set of predefined phishing indicators, and provides a "risk score" along with educational explanations for each detected red flag.

The primary goal of this project is to enhance cybersecurity awareness by demonstrating how attackers craft convincing phishing attempts and what users should look out for.

## Features

* **Interactive Input:** Prompts the user to input simulated email header and body content.
* **Rule-Based Analysis:** Employs a set of rules to detect various phishing characteristics (e.g., generic greetings, urgent language, suspicious links, sender spoofing).
* **Risk Scoring:** Assigns a cumulative "risk score" based on the severity of detected indicators.
* **Categorized Risk:** Classifies the email's risk level (Low, Medium, High, Very High) for easy understanding.
* **Educational Explanations:** Provides clear, concise explanations for *why* each detected characteristic is suspicious, helping users learn about phishing tactics.
* **General Security Advice:** Offers actionable tips on how to handle suspicious emails in real-world scenarios.

## How to Run

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/ramcharan-vemulapudi/simulated-phishing-analyzer.git](https:/ramcharan-vemulapudi/github.com//simulated-phishing-analyzer.git)
    cd simulated-phishing-analyzer
    ```

2.  **Run the Python script:**
    ```bash
    python main.py
    ```

3.  **Follow the prompts:** The tool will ask you to paste or type your simulated email header and body content. Press `ENTER` twice (on an empty line) after each section to submit your input.

## Example Simulated Input

### Example 1: High Risk Phish

**Simulated Header:**

From: PayPal Security security@paya-pal.com
To: victim@example.com
Subject: Your Account Has Been Limited - Action Required Immediately
Reply-To: support@phish-paypal.ne

**Simulated Body:**
Dear Valued Client,

We detected unusual activity on your PayPal account. Your account has been temporarily limited due to suspicious login attempts from an unrecognized device. Immediate action is required to prevent permanent suspension.

To restore full access to your account and verify your details, please click on the link below:

Click Here To Update Your Information: http://paypal-verify.co/update/login.php

Failure to confirm your information within 24 hours will result in permanent account closure.

Thank you for your cooperation.

PayPal Security Team


### Example 2: Low Risk / Clean (Simulated)

**Simulated Header:**
From: Your Bank notifications@yourbank.com
To: John Doe john.doe@example.com
Subject: Your Monthly Statement is Ready


**Simulated Body:**
Dear John Doe,

Your monthly statement for July 2025 is now available.

You can view it securely by logging into your online banking portal at:
https://www.yourbank.com/login

Thank you,
Your Bank Team


## Concepts Demonstrated

* **Phishing Indicators:** Understanding the common traits of phishing emails.
* **Regular Expressions (Regex):** Using patterns to search for specific text.
* **String Manipulation:** Processing email content.
* **Conditional Logic:** Applying rules and scoring.
* **Defensive Cybersecurity:** Focusing on identifying threats rather than creating them.
* **User Education:** Designing a tool that provides actionable insights.


---
