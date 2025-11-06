# PAW Sentinel - Atomic Alert System Configuration
# This configuration enables the "atomic" idea: every click becomes an automatic alert

# 🚨 EMAIL CONFIGURATION FOR AUTOMATIC ALERTS
export PAW_SMTP_SERVER="smtp.gmail.com"
export PAW_SMTP_PORT="587"
export PAW_SMTP_USER="your-email@gmail.com"
export PAW_SMTP_PASS="your-app-password"

# Optional: send all alerts to a specific address instead of the "victim"
# export PAW_ALERT_TO="security@yourcompany.com"

# 📧 HOW TO GET AN APP PASSWORD FOR GMAIL:
# 1. Go to https://myaccount.google.com/security
# 2. Enable "2-Step Verification"
# 3. Go to "App passwords"
# 4. Generate password for "PAW Sentinel"
# 5. Use that password above

# 🔄 HOW THE ATOMIC SYSTEM WORKS:
# 1. Victim clicks phishing link
# 2. Gets redirected to PAW canary server
# 3. System automatically sends alert email
# 4. Victim becomes active sensor against phishing
# 5. Free distribution → Massive network → End of phishing

# � WHY THIS IS NOT SPAM:
# - Only triggered when someone ACTUALLY clicks a phishing link
# - The site is compromised - we're helping the victim
# - No mass mailing - targeted protection
# - Similar to antivirus alerts or security warnings

# ⚠️  LEGAL CONSIDERATIONS:
# - Privacy: only store IP/UA, no personal data beyond that
# - Consent: inform users about the system
# - Abuse prevention: avoid alert spam
# - Security: protect email credentials