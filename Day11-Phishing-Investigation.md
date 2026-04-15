# Day 11: Phishing Email Investigation 📧

## Scenario
A suspicious email was reported by a user claiming to be from PayPal. The task was to analyze the email and determine if it was legitimate or malicious.

---

## Objective
To identify phishing indicators and assess the legitimacy of the email.

---

## Email Analysis

### Sender Address
support@paypaI.com

- The domain is spoofed
- Uses a capital "I" instead of "l"
- This is a typosquatting technique

---

### Link Analysis
http://paypal-secure-login.com/verify

- Not an official PayPal domain
- Uses HTTP instead of HTTPS
- Likely a phishing website

---

### Content Analysis

- Creates urgency (“act immediately”)
- Threatens account suspension
- No personalization (“Dear Customer”)

---

## Indicators of Compromise (IOCs)

- Fake domain: paypaI.com
- Suspicious URL: paypal-secure-login.com
- Social engineering tactics

---

## Verdict

This email is a phishing attempt designed to steal user credentials.

---

## Recommended Actions

- Do not click the link
- Report the email
- Block the sender domain
- Educate users on phishing awareness

---

## Reflection

This exercise helped me understand how attackers use deception and urgency to trick users, and how to identify phishing attempts through careful analysis.

---

## Conclusion

Phishing remains one of the most common attack methods, and the ability to detect it is a critical cybersecurity skill.
