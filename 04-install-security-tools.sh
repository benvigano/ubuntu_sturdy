#!/bin/bash
# 04-install-security-tools.sh

set -e
set -o pipefail

# Load configuration variables
source "$(dirname "$0")/config.sh"

echo "--- (4/5) Starting Security Tools Installation and Configuration ---"

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
SERVER_NAME_UP=${SERVER_NAME^^}

# Format the From header and Subject
FROM_HEADER="From: \"${SERVER_NAME_UP} - System Alert\" <${GMAIL_ADDRESS}>"
SUBJECT="Severity: ${SEVERITY_UP} - ${TYPE_UP}: ${SUBJECT_DETAIL}"

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
# Update data files (ignore warnings)
rkhunter --update || true
rkhunter --propupd || true

# Configure rkhunter to email on warnings and run via cron
sed -i "s/^MAILTO=.*/MAILTO=\"${NOTIFICATION_EMAIL}\"/" /etc/rkhunter.conf
sed -i "s/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN=\"true\"/" /etc/default/rkhunter
sed -i "s/^APT_AUTOGEN=.*/APT_AUTOGEN=\"true\"/" /etc/default/rkhunter

# Set up automated weekly rkhunter database updates with status check
cat > /usr/local/sbin/check_rkhunter_update.sh <<'EOF'
#!/bin/bash
set -e
set -o pipefail

# Run update and capture output
UPDATE_OUTPUT=$(/usr/bin/rkhunter --update --nocolors 2>&1) || {
    ERROR_MSG="rkhunter database update failed!\n\nError output:\n${UPDATE_OUTPUT}"
    /usr/local/sbin/format_security_mail.sh "WARNING" "RKHUNTER-UPDATE-FAILED" "Database update error" "$ERROR_MSG"
    exit 1
}

# Run property update and capture output
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
# Weekly rkhunter database update
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
