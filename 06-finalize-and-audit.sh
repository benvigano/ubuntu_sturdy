#!/bin/bash
# 05-finalize-and-audit.sh

set -e
set -o pipefail

# Load configuration variables
source "$(dirname "$0")/config.sh"

echo "--- (6/6) Starting Finalization and Audit ---"

# --- Install Lynis and AppArmor ---

echo "Installing Lynis, AppArmor, and required profiles..."
apt-get install -y lynis apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra

# --- Configure AppArmor ---

echo "Configuring AppArmor mandatory access control..."

# Ensure AppArmor is enabled
systemctl enable apparmor
systemctl start apparmor

# Enable profiles for key services in complain mode first (safer)
echo "Enabling AppArmor profiles in complain mode..."

# Function to safely enable AppArmor profiles
enable_profile_if_exists() {
    local profile_name="$1"
    if aa-status | grep -q "$profile_name" 2>/dev/null || [ -f "/etc/apparmor.d/$profile_name" ]; then
        echo "Enabling profile: $profile_name"
        aa-complain "$profile_name"
    else
        echo "Profile $profile_name not found, skipping..."
    fi
}

# Try to enable common profiles for SSH and Postfix
enable_profile_if_exists "usr.sbin.sshd"
enable_profile_if_exists "usr.sbin.postfix"

# Try alternative profile names if the above don't exist
if ! aa-status | grep -q "usr.sbin.sshd" 2>/dev/null; then
    for alt_profile in "sshd" "/usr/sbin/sshd"; do
        enable_profile_if_exists "$alt_profile"
    done
fi

if ! aa-status | grep -q "usr.sbin.postfix" 2>/dev/null; then
    for alt_profile in "postfix" "/usr/sbin/postfix" "usr.lib.postfix.master"; do
        enable_profile_if_exists "$alt_profile"
    done
fi

# Ensure profiles are loaded
aa-status || {
    echo "Loading AppArmor profiles..."
    systemctl restart apparmor
}

# Wait for profiles to load
sleep 2

# Configure AppArmor to use our email notification system
echo "Setting up AppArmor notifications..."

# Create notification script
mkdir -p /etc/apparmor/notify.d/
cat > /etc/apparmor/notify.d/notify <<'EOF'
#!/bin/bash
set -e
set -o pipefail

# Load persistent configuration
source /etc/sturdy.conf

# $1 will be the event type (e.g., "DENIED")
# $2 will be the full message
/usr/local/sbin/format_security_mail.sh "WARNING" "APPARMOR-${1}" "AppArmor ${1} event detected" "${2}"
EOF

chmod +x /etc/apparmor/notify.d/notify

# Configure AppArmor notification settings
cat > /etc/apparmor/notify.conf <<EOF
# Enable notifications for all events
notify=yes

# Use our custom notification script
notify_handler=/etc/apparmor/notify.d/notify

# Log all types of events
debug_events=yes
denied_events=yes
error_events=yes
EOF

# Restart AppArmor to apply notification settings
systemctl restart apparmor

echo "AppArmor configured in permanent complain mode with violation alerts."

# --- Verify AppArmor Configuration ---

echo "Verifying AppArmor configuration..."

apparmor_failures=()

# Check AppArmor service is enabled and active
if ! systemctl is-enabled apparmor >/dev/null 2>&1; then
    apparmor_failures+=("AppArmor service is not enabled")
fi

if ! systemctl is-active apparmor >/dev/null 2>&1; then
    apparmor_failures+=("AppArmor service is not active")
fi

# Check AppArmor is actually loaded
if ! aa-status >/dev/null 2>&1; then
    apparmor_failures+=("AppArmor is not loaded or aa-status command failed")
fi

# Check that some profiles are loaded (at least one should be active)
profile_count=$(aa-status 2>/dev/null | grep -c "profiles are loaded" || echo "0")
if [[ "$profile_count" == "0" ]]; then
    apparmor_failures+=("No AppArmor profiles are loaded")
fi

# Check notification configuration
if [[ ! -x "/etc/apparmor/notify.d/notify" ]]; then
    apparmor_failures+=("AppArmor notification script missing or not executable")
fi

if ! grep -q "^notify=yes" /etc/apparmor/notify.conf; then
    apparmor_failures+=("AppArmor notifications not enabled in notify.conf")
fi

if ! grep -q "^notify_handler=" /etc/apparmor/notify.conf; then
    apparmor_failures+=("AppArmor notification handler not configured in notify.conf")
fi

if [ ${#apparmor_failures[@]} -gt 0 ]; then
    echo "ERROR: Critical AppArmor settings verification failed:"
    for failure in "${apparmor_failures[@]}"; do
        echo "  - $failure"
    done
    echo "This is a critical security configuration failure. Aborting."
    exit 1
fi

echo "AppArmor configuration verified successfully."

# --- Final Steps & Cleanup ---

echo "Performing final system cleanup..."
apt-get autoremove -y
apt-get clean

# --- Run Final Security Audit ---

echo "Running final Lynis security audit on the hardened system..."
echo "This may take a few minutes..."

# Run the audit in cron mode to reduce interactive elements
LYNIS_REPORT=$(lynis audit system --cronjob 2>&1)

echo "Lynis audit complete."
echo "Emailing the final security audit report..."

# Email the Lynis report for review
/usr/local/sbin/format_security_mail.sh "INFO" "LYNIS-AUDIT" "Final security audit of hardened system" "$LYNIS_REPORT"

echo "Final security audit report has been emailed to ${NOTIFICATION_EMAIL}."

echo ""
echo "--- Hardening Process Complete ---"
echo "The Lynis security audit report has been emailed to ${NOTIFICATION_EMAIL}."
echo "Please review the report for additional security suggestions."
echo "It is highly recommended to REBOOT the system now to ensure all changes are applied."
echo ""
