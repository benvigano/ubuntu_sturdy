#!/bin/bash
# 04-install-security-tools.sh

set -e
set -o pipefail

# Load configuration variables
source "$(dirname "$0")/config.sh"

echo "--- (5/6) Starting Security Tools Installation and Configuration ---"

# --- Install Packages ---

echo "Installing security packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get install -y postfix mailutils aide aide-common clamav clamav-daemon rkhunter fail2ban

# --- Configure Postfix for Gmail Relay ---

echo "Configuring Postfix to use Gmail as a relay..."

# Set debconf selections to automate Postfix installation
echo "postfix postfix/main_mailer_type select Satellite system" | debconf-set-selections
echo "postfix postfix/mailname string $(hostname)" | debconf-set-selections
echo "postfix postfix/relayhost string [smtp.gmail.com]:587" | debconf-set-selections

# Reconfigure postfix if it's already installed
dpkg-reconfigure -f noninteractive postfix

# Configure SASL authentication (idempotent - overwrites existing)
cat > /etc/postfix/sasl_passwd <<EOF
[smtp.gmail.com]:587    ${GMAIL_ADDRESS}:${GMAIL_APP_PASSWORD}
EOF

# Set permissions and update Postfix config
chmod 600 /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd
postconf -e "smtp_sasl_auth_enable = yes"
postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
postconf -e "smtp_sasl_security_options = noanonymous"
postconf -e "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
postconf -e "smtp_use_tls = yes"
postconf -e "relayhost = [smtp.gmail.com]:587"

systemctl restart postfix

# --- Verify Postfix Configuration ---

echo "Verifying Postfix configuration..."

# Verify critical Postfix settings
postfix_failures=()

# Check relayhost setting
actual_relayhost=$(postconf -h relayhost 2>/dev/null || echo "FAILED")
expected_relayhost="[smtp.gmail.com]:587"
if [[ "$actual_relayhost" != "$expected_relayhost" ]]; then
    postfix_failures+=("relayhost: expected '$expected_relayhost', got '$actual_relayhost'")
fi

# Check SASL auth is enabled
actual_sasl_auth=$(postconf -h smtp_sasl_auth_enable 2>/dev/null || echo "FAILED")
if [[ "$actual_sasl_auth" != "yes" ]]; then
    postfix_failures+=("smtp_sasl_auth_enable: expected 'yes', got '$actual_sasl_auth'")
fi

# Check TLS is enabled
actual_tls=$(postconf -h smtp_use_tls 2>/dev/null || echo "FAILED")
if [[ "$actual_tls" != "yes" ]]; then
    postfix_failures+=("smtp_use_tls: expected 'yes', got '$actual_tls'")
fi

# Check SASL password file exists and has correct permissions
if [[ ! -f "/etc/postfix/sasl_passwd" ]]; then
    postfix_failures+=("SASL password file missing: /etc/postfix/sasl_passwd")
else
    sasl_perms=$(stat -c "%a" "/etc/postfix/sasl_passwd" 2>/dev/null || echo "FAILED")
    if [[ "$sasl_perms" != "600" ]]; then
        postfix_failures+=("SASL password file permissions: expected '600', got '$sasl_perms'")
    fi
fi

# Check SASL password database exists
if [[ ! -f "/etc/postfix/sasl_passwd.db" ]]; then
    postfix_failures+=("SASL password database missing: /etc/postfix/sasl_passwd.db (postmap may have failed)")
fi

if [ ${#postfix_failures[@]} -gt 0 ]; then
    echo "ERROR: Critical Postfix settings verification failed:"
    for failure in "${postfix_failures[@]}"; do
        echo "  - $failure"
    done
    echo "This is a critical security configuration failure. Aborting."
    exit 1
fi

echo "Postfix configuration verified successfully."

# Get the absolute path to the configuration file
CONFIG_PATH=$(realpath "$(dirname "$0")/config.sh")

# Create email formatting helper script.
# We write the config source line separately to expand the CONFIG_PATH variable,
# then append the rest of the script with a quoted 'EOF' to prevent premature
# variable expansion of $1, $SUBJECT, etc.
echo "#!/bin/bash" > /usr/local/sbin/format_security_mail.sh
echo "# Load server configuration" >> /usr/local/sbin/format_security_mail.sh
echo "source \"${CONFIG_PATH}\"" >> /usr/local/sbin/format_security_mail.sh
cat >> /usr/local/sbin/format_security_mail.sh <<'EOF'
set -e
set -o pipefail

# Arguments:
# $1: severity (INFO, WARNING, or CRITICAL)
# $2: alert type (e.g., "VIRUS-FOUND", "UPDATE-FAILED")
# $3: subject details
# $4: email body (optional)

SEVERITY=$1
TYPE=$2
SUBJECT_DETAIL=$3
BODY=$4

# Uppercase variables for formatting
SEVERITY_UP=${SEVERITY^^}
TYPE_UP=${TYPE^^}

# Format the From header and Subject
FROM_HEADER="From: \"${SERVER_NAME} Security Alerts\" <${GMAIL_ADDRESS}>"
SUBJECT="Level: ${SEVERITY_UP} - ${TYPE_UP}: ${SUBJECT_DETAIL}"

# Format the body
if [ -z "$BODY" ]; then
    # If no body, use a simple message based on the subject.
    EMAIL_BODY="Type: ${TYPE_UP}\nDetails: ${SUBJECT_DETAIL}"
else
    EMAIL_BODY="Type: ${TYPE_UP}\nDetails: ${SUBJECT_DETAIL}\n\n${BODY}"
fi

# Construct and send the email using sendmail for reliable header control
(
echo "${FROM_HEADER}"
echo "To: ${NOTIFICATION_EMAIL}"
echo "Subject: ${SUBJECT}"
echo ""
echo -e "${EMAIL_BODY}"
) | /usr/sbin/sendmail -t
EOF

chmod +x /usr/local/sbin/format_security_mail.sh

# Send a test email and verify it was sent successfully
echo "Sending a test email to ${NOTIFICATION_EMAIL}..."
if ! /usr/local/sbin/format_security_mail.sh "INFO" "SETUP-TEST" "Initial email configuration test" "This is a test email from your new server setup. If you receive this, email notifications are working correctly."; then
    echo "ERROR: Failed to send test email. Email configuration may be incorrect."
    echo "Please check:"
    echo "  - GMAIL_ADDRESS and GMAIL_APP_PASSWORD in config.sh"
    echo "  - Gmail app password is correctly generated"
    echo "  - NOTIFICATION_EMAIL is valid"
    echo "Aborting setup due to email configuration failure."
    exit 1
fi

echo "Test email sent successfully. Please check your inbox to confirm it was received."
echo "If you don't receive it, there may be an issue with your Gmail configuration."
sleep 5 # Give postfix a moment to send

# --- Configure AIDE ---

echo "Configuring AIDE for file integrity monitoring..."
# Initialize the AIDE database. This can take a while.
# Skip if database already exists (idempotent)
if [[ ! -f /var/lib/aide/aide.db ]]; then
    echo "Initializing AIDE database... This may take several minutes."
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
else
    echo "AIDE database already exists, skipping initialization."
fi

# Create AIDE check wrapper
cat > /usr/local/sbin/check_aide.sh <<'EOF'
#!/bin/bash
set -e
set -o pipefail

CHECK_OUTPUT=$(/usr/bin/aide --check 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    # AIDE returns 0 for no changes, 1 for changes found, >1 for errors
    if [ $EXIT_CODE -eq 1 ]; then
        /usr/local/sbin/format_security_mail.sh "CRITICAL" "AIDE-CHANGES" "File integrity violations detected" "$CHECK_OUTPUT"
    else
        /usr/local/sbin/format_security_mail.sh "WARNING" "AIDE-ERROR" "Check failed" "$CHECK_OUTPUT"
    fi
fi
EOF

chmod +x /usr/local/sbin/check_aide.sh

# Set up a cron job to run a daily check
AIDE_HOUR=$(echo "${DAILY_TASKS_START_TIME}" | cut -d: -f1)
AIDE_MINUTE=$(echo "${DAILY_TASKS_START_TIME}" | cut -d: -f2)
# Idempotent cron job creation
cat > /etc/cron.d/aide <<EOF
# AIDE daily integrity check
${AIDE_MINUTE} ${AIDE_HOUR} * * * root /usr/local/sbin/check_aide.sh
EOF

# --- Configure ClamAV ---

echo "Configuring ClamAV for antivirus scanning..."
# Set up ClamAV update monitoring script
cat > /usr/local/sbin/check_clamav_update.sh <<'EOF'
#!/bin/bash
set -e
set -o pipefail

# Stop freshclam daemon to allow manual update check
systemctl stop clamav-freshclam

# Try to update and capture output
UPDATE_OUTPUT=$(freshclam 2>&1) || {
    ERROR_MSG="ClamAV signature update failed!\n\nError output:\n${UPDATE_OUTPUT}"
    /usr/local/sbin/format_security_mail.sh "WARNING" "CLAM-UPDATE-FAILED" "Signature update error" "$ERROR_MSG"
    # Restart daemon and exit with error
    systemctl start clamav-freshclam
    exit 1
}

# Restart the daemon
systemctl start clamav-freshclam

# If we get here, everything worked
echo "ClamAV signatures updated successfully."
EOF

chmod +x /usr/local/sbin/check_clamav_update.sh

# Add daily signature update check
cat > /etc/cron.d/clamav-update <<EOF
# Daily ClamAV signature update check
MAILTO="${NOTIFICATION_EMAIL}"
0 ${CLAM_HOUR} * * * root /usr/local/sbin/check_clamav_update.sh
EOF

# Create ClamAV scan wrapper
cat > /usr/local/sbin/run_clamscan.sh <<'EOF'
#!/bin/bash
set -e
set -o pipefail

SCAN_OUTPUT=$(/usr/bin/clamscan --infected --recursive --exclude-dir="^/sys|^/proc" / 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -eq 1 ]; then
    # Exit code 1 means viruses were found
    /usr/local/sbin/format_security_mail.sh "CRITICAL" "CLAM-VIRUS-FOUND" "Malware detected" "$SCAN_OUTPUT"
elif [ $EXIT_CODE -gt 1 ]; then
    # Exit codes >1 indicate errors
    /usr/local/sbin/format_security_mail.sh "WARNING" "CLAM-SCAN-ERROR" "Scan failed" "$SCAN_OUTPUT"
fi
EOF

chmod +x /usr/local/sbin/run_clamscan.sh

# Set up a cron job for a weekly scan
# Schedule 30 minutes after the base time
CLAM_HOUR=$(echo "${DAILY_TASKS_START_TIME}" | cut -d: -f1)
CLAM_MINUTE=$(echo "${DAILY_TASKS_START_TIME}" | cut -d: -f2)
CLAM_MINUTE=$((CLAM_MINUTE + 30))
if [ $CLAM_MINUTE -ge 60 ]; then
    CLAM_MINUTE=$((CLAM_MINUTE - 60))
    CLAM_HOUR=$((CLAM_HOUR + 1))
    if [ $CLAM_HOUR -ge 24 ]; then
        CLAM_HOUR=$((CLAM_HOUR - 24))
    fi
fi
# Idempotent cron job creation
cat > /etc/cron.d/clamav-scan <<EOF
# Weekly ClamAV scan
${CLAM_MINUTE} ${CLAM_HOUR} * * 0 root /usr/local/sbin/run_clamscan.sh
EOF

# --- Configure rkhunter ---

echo "Configuring rkhunter for rootkit scanning..."

# Disable web updates to avoid HTTP/HTTPS redirect issues with rkhunter.sourceforge.net
# This uses the signature files provided by the Ubuntu package, which are updated via APT
sed -i "s/^#*WEB_CMD=.*/WEB_CMD=\"\"/" /etc/rkhunter.conf
# Ensure the line exists if it doesn't
if ! grep -q "^WEB_CMD=" /etc/rkhunter.conf; then
    echo "WEB_CMD=\"\"" >> /etc/rkhunter.conf
fi

# Update data files
rkhunter --update
rkhunter --propupd

# Configure rkhunter to email on warnings and run via cron
sed -i "s/^MAILTO=.*/MAILTO=\"${NOTIFICATION_EMAIL}\"/" /etc/rkhunter.conf
sed -i "s/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN=\"true\"/" /etc/default/rkhunter
sed -i "s/^APT_AUTOGEN=.*/APT_AUTOGEN=\"true\"/" /etc/default/rkhunter

# --- Verify rkhunter Configuration ---

echo "Verifying rkhunter configuration..."

rkhunter_failures=()

# Check WEB_CMD is disabled (empty)
if ! grep -q "^WEB_CMD=\"\"" /etc/rkhunter.conf; then
    rkhunter_failures+=("WEB_CMD not properly disabled in /etc/rkhunter.conf")
fi

# Check MAILTO is set correctly
if ! grep -q "^MAILTO=\"${NOTIFICATION_EMAIL}\"" /etc/rkhunter.conf; then
    actual_mailto=$(grep "^MAILTO=" /etc/rkhunter.conf 2>/dev/null || echo "MISSING")
    rkhunter_failures+=("MAILTO setting incorrect: expected 'MAILTO=\"${NOTIFICATION_EMAIL}\"', found '$actual_mailto'")
fi

# Check CRON_DAILY_RUN is enabled
if ! grep -q "^CRON_DAILY_RUN=\"true\"" /etc/default/rkhunter; then
    actual_cron=$(grep "^CRON_DAILY_RUN=" /etc/default/rkhunter 2>/dev/null || echo "MISSING")
    rkhunter_failures+=("CRON_DAILY_RUN not enabled: expected 'true', found '$actual_cron'")
fi

# Check APT_AUTOGEN is enabled
if ! grep -q "^APT_AUTOGEN=\"true\"" /etc/default/rkhunter; then
    actual_autogen=$(grep "^APT_AUTOGEN=" /etc/default/rkhunter 2>/dev/null || echo "MISSING")
    rkhunter_failures+=("APT_AUTOGEN not enabled: expected 'true', found '$actual_autogen'")
fi

if [ ${#rkhunter_failures[@]} -gt 0 ]; then
    echo "ERROR: Critical rkhunter settings verification failed:"
    for failure in "${rkhunter_failures[@]}"; do
        echo "  - $failure"
    done
    echo "This is a critical security configuration failure. Aborting."
    exit 1
fi

echo "rkhunter configuration verified successfully."

# Set up automated weekly rkhunter package and property updates
cat > /usr/local/sbin/check_rkhunter_update.sh <<'EOF'
#!/bin/bash
set -e
set -o pipefail

# Load server configuration
source "$(dirname "$0")/../../ubuntu_sturdy/config.sh" 2>/dev/null || source "/root/ubuntu_sturdy/config.sh" 2>/dev/null || {
    # Fallback: extract email from rkhunter config
    NOTIFICATION_EMAIL=$(grep "^MAILTO=" /etc/rkhunter.conf 2>/dev/null | cut -d'"' -f2 || echo "root")
    SERVER_NAME=$(hostname)
}

# Update rkhunter package to get latest signatures
UPDATE_OUTPUT=$(/usr/bin/apt-get update && /usr/bin/apt-get install --only-upgrade rkhunter -y 2>&1) || {
    ERROR_MSG="rkhunter package update failed!\n\nError output:\n${UPDATE_OUTPUT}"
    /usr/local/sbin/format_security_mail.sh "WARNING" "RKHUNTER-UPDATE-FAILED" "Package update error" "$ERROR_MSG"
    exit 1
}

# Update file properties after package update
PROP_OUTPUT=$(/usr/bin/rkhunter --propupd --nocolors 2>&1) || {
    ERROR_MSG="rkhunter property update failed!\n\nError output:\n${PROP_OUTPUT}"
    /usr/local/sbin/format_security_mail.sh "WARNING" "RKHUNTER-UPDATE-FAILED" "Property update error" "$ERROR_MSG"
    exit 1
}

# If we get here, everything worked
echo "rkhunter updates completed successfully."
EOF

chmod +x /usr/local/sbin/check_rkhunter_update.sh

cat > /etc/cron.d/rkhunter-update <<EOF
# Weekly rkhunter package and property update
MAILTO="${NOTIFICATION_EMAIL}"
0 3 * * 1 root /usr/local/sbin/check_rkhunter_update.sh
EOF

# --- Configure fail2ban ---

echo "Configuring fail2ban..."
# Create custom action for our email format
cat > /etc/fail2ban/action.d/custom-mail.conf <<EOF
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = /usr/local/sbin/format_security_mail.sh "CRITICAL" "FAIL2BAN-BAN" "IP <ip> banned from <name>" "IP: <ip>\nJail: <name>\nTime: <datetime>\n\nLines leading to ban:\n<matches>"
actionunban = 

[Init]
EOF

# Create a local jail config to override defaults
# Idempotent jail configuration (overwrites existing)
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
destemail = ${NOTIFICATION_EMAIL}
sender = ${GMAIL_ADDRESS}
# Use our custom mail action (no start/stop notifications)
action = custom-mail[name=%(__name__)s]

[sshd]
enabled = true
port = ${SSH_PORT}
logpath = %(sshd_log)s
maxretry = 3
bantime = 1h

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
# Only send ban notifications, not start/stop
action = custom-mail[name=%(__name__)s]
bantime = 1w
findtime = 1d
maxretry = 5
EOF

systemctl restart fail2ban

# --- Verify fail2ban Configuration ---

echo "Verifying fail2ban configuration..."

fail2ban_failures=()

# Check fail2ban service is active
if ! systemctl is-active fail2ban >/dev/null 2>&1; then
    fail2ban_failures+=("fail2ban service is not active")
fi

# Check critical jail settings were applied
if ! grep -q "enabled = true" /etc/fail2ban/jail.local; then
    fail2ban_failures+=("No jails enabled in jail.local")
fi

if ! grep -q "port = ${SSH_PORT}" /etc/fail2ban/jail.local; then
    fail2ban_failures+=("SSH port not configured correctly in fail2ban")
fi

if ! grep -q "destemail = ${NOTIFICATION_EMAIL}" /etc/fail2ban/jail.local; then
    fail2ban_failures+=("Notification email not configured correctly in fail2ban")
fi

if [ ${#fail2ban_failures[@]} -gt 0 ]; then
    echo "ERROR: Critical fail2ban settings verification failed:"
    for failure in "${fail2ban_failures[@]}"; do
        echo "  - $failure"
    done
    echo "This is a critical security configuration failure. Aborting."
    exit 1
fi

echo "fail2ban configuration verified successfully."

# Set up automated fail2ban updates (filter patterns)
cat > /etc/cron.d/fail2ban-update <<EOF
# Weekly fail2ban update and restart
MAILTO="${NOTIFICATION_EMAIL}"
30 3 * * 1 root /usr/bin/apt-get update && /usr/bin/apt-get install --only-upgrade fail2ban -y && /usr/bin/systemctl restart fail2ban
EOF

# --- Configure Log Rotation ---

echo "Configuring comprehensive log rotation..."

# AIDE logs rotation
cat > /etc/logrotate.d/aide <<EOF
/var/log/aide/*.log {
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF

# Audit logs rotation (auditd)
cat > /etc/logrotate.d/audit-custom <<EOF
/var/log/audit/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    postrotate
        /usr/bin/systemctl reload auditd > /dev/null 2>&1 || true
    endscript
}
EOF

# fail2ban logs rotation
cat > /etc/logrotate.d/fail2ban-custom <<EOF
/var/log/fail2ban.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    postrotate
        /usr/bin/systemctl reload fail2ban > /dev/null 2>&1 || true
    endscript
}
EOF

# ClamAV logs rotation
cat > /etc/logrotate.d/clamav-custom <<EOF
/var/log/clamav/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 clamav adm
    postrotate
        /usr/bin/systemctl reload clamav-freshclam > /dev/null 2>&1 || true
    endscript
}
EOF

# rkhunter logs rotation
cat > /etc/logrotate.d/rkhunter-custom <<EOF
/var/log/rkhunter.log {
    monthly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF

# Postfix mail logs (additional to system default)
cat > /etc/logrotate.d/postfix-custom <<EOF
/var/log/mail.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 syslog adm
    postrotate
        /usr/bin/systemctl reload postfix > /dev/null 2>&1 || true
    endscript
}
EOF

echo "--- Security Tools Configuration Finished ---"
echo ""
