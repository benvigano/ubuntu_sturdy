#!/bin/bash
# 05-finalize-and-audit.sh

set -e
set -o pipefail

# Load configuration variables
source "$(dirname "$0")/config.sh"

echo "--- (5/5) Starting Finalization and Audit ---"

# --- Install Lynis ---

echo "Installing Lynis and AppArmor utilities..."
apt-get install -y lynis apparmor-utils apparmor-profiles

# --- Run Lynis Audit ---

echo "Running Lynis security audit... This may take a few minutes."
# We run the audit in cron mode to reduce interactive elements.
# The output will be emailed instead of saved to a file.
LYNIS_REPORT=$(lynis audit system --cronjob 2>&1)

echo "Lynis audit complete."
echo "Emailing the security audit report..."

# Email the Lynis report for review
/usr/local/sbin/format_security_mail.sh "INFO" "LYNIS-AUDIT" "Initial security audit completed" "$LYNIS_REPORT"

echo "Lynis audit report has been emailed to ${NOTIFICATION_EMAIL}."

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

# Set up monitoring for AppArmor violations
cat > /etc/cron.d/apparmor-violations <<EOF
# Daily AppArmor violation check
MAILTO="${NOTIFICATION_EMAIL}"
0 6 * * * root /usr/bin/aa-logprof --help >/dev/null 2>&1 && /usr/sbin/aa-logprof --update --dir /etc/apparmor.d/ --noprompt || true
EOF

# After a week, switch to enforce mode (more restrictive)
# This gives time to identify any legitimate violations first
cat > /etc/cron.d/apparmor-enforce <<'EOF'
# Switch to enforce mode after 7 days (runs once)
MAILTO="${NOTIFICATION_EMAIL}"
0 7 * * 7 root for profile in $(aa-status --complain 2>/dev/null | grep -E "(sshd|postfix)" | awk '{print $1}' || true); do aa-enforce "$profile" 2>/dev/null || true; done; /bin/rm -f /etc/cron.d/apparmor-enforce
EOF

echo "AppArmor configured. Profiles will switch to enforce mode after 7 days."

# --- Final Steps & Cleanup ---

echo "Performing final system cleanup..."
apt-get autoremove -y
apt-get clean

echo ""
echo "--- Hardening Process Complete ---"
echo "The Lynis security audit report has been emailed to ${NOTIFICATION_EMAIL}."
echo "Please review the report for additional security suggestions."
echo "It is highly recommended to REBOOT the system now to ensure all changes are applied."
echo ""
