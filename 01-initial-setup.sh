#!/bin/bash
# 01-initial-setup.sh

set -e
set -o pipefail

# Load configuration variables
source "$(dirname "$0")/config.sh"

echo "--- (1/6) Starting Initial System Setup ---"

# --- System Update and Time Synchronization ---

echo "Updating package lists and upgrading the system..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y
apt-get install -y chrony openssh-server

echo "Configuring timezone to UTC and enabling time synchronization..."
timedatectl set-timezone UTC
timedatectl set-ntp true

# --- Root Account Hardening ---

echo "Disabling the root account for login..."
# Lock the root account to prevent password-based login
passwd -l root
# Set the root shell to nologin to prevent interactive sessions
usermod -s /usr/sbin/nologin root

echo "Verifying that only the 'root' user has UID 0..."
# Awk script to find users with UID 0. The output should only be 'root'.
read -r -a uid_zero_users <<< "$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)"

if [[ "${#uid_zero_users[@]}" -ne 1 ]] || [[ "${uid_zero_users[0]}" != "root" ]]; then
    echo "ERROR: Found multiple users or a non-root user with UID 0."
    echo "Users with UID 0: ${uid_zero_users[*]}"
    echo "This is a critical security issue. Aborting."
    exit 1
else
    echo "UID 0 check passed. Only 'root' has UID 0."
fi

# --- Create Persistent Configuration ---

echo "Creating persistent configuration file at /etc/sturdy.conf..."
# This file stores non-sensitive variables needed for ongoing operations (cron jobs, etc.)
# It is created once and persists after the initial config.sh is shredded.
cat > /etc/sturdy.conf <<EOF
# Persistent configuration for Sturdy Ubuntu scripts
# This file is safe to keep and can be edited to update operational settings.

export NOTIFICATION_EMAIL="${NOTIFICATION_EMAIL}"
export GMAIL_ADDRESS="${GMAIL_ADDRESS}"
export SERVER_NAME="${SERVER_NAME}"
export SSH_PORT="${SSH_PORT}"
export ADMIN_USER="${ADMIN_USER}"
EOF

# Set secure permissions
chmod 644 /etc/sturdy.conf
chown root:root /etc/sturdy.conf

echo "Persistent configuration created successfully."

# --- Local Access Control ---

echo "Disabling ALL local TTY/console login to enforce SSH-only access..."

# Ensure pam_access.so is enforced for login. This makes the system use /etc/security/access.conf.
if ! grep -q "^account[[:space:]]\\{1,\\}required[[:space:]]\\{1,\\}pam_access.so" /etc/pam.d/login; then
    # Check if it exists but is commented out
    if grep -q "^#[[:space:]]*account[[:space:]]\\{1,\\}required[[:space:]]\\{1,\\}pam_access.so" /etc/pam.d/login; then
        # Uncomment the existing line
        sed -i 's/^#[[:space:]]*account[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_access.so/account     required      pam_access.so/' /etc/pam.d/login
        echo "Uncommented existing pam_access.so line in /etc/pam.d/login"
    else
        # Add a new line after the common-auth include
        sed -i '/^@include common-auth/a account     required      pam_access.so' /etc/pam.d/login
        echo "Added pam_access.so line to /etc/pam.d/login"
    fi
fi

# Add rule to deny ALL users from local TTY/console login.
ACCESS_RULE="-: ALL : LOCAL"
if ! grep -qF -- "${ACCESS_RULE}" /etc/security/access.conf; then
    echo "" >> /etc/security/access.conf
    echo "# Deny ALL users from local TTY/console login to enforce SSH-only access" >> /etc/security/access.conf
    echo "${ACCESS_RULE}" >> /etc/security/access.conf
fi

# --- Verify PAM Access Configuration ---

echo "Verifying PAM access control configuration..."

# Check that pam_access.so is actually enabled (not commented out) in /etc/pam.d/login
if ! grep -q "^account[[:space:]]\\{1,\\}required[[:space:]]\\{1,\\}pam_access.so" /etc/pam.d/login; then
    echo "ERROR: pam_access.so is not properly enabled in /etc/pam.d/login"
    echo "Expected to find uncommented line: account required pam_access.so"
    echo "Current pam_access lines in /etc/pam.d/login:"
    grep -n "pam_access" /etc/pam.d/login || echo "  (none found)"
    echo "This is a critical security configuration failure. Aborting."
    exit 1
fi

# Verify the access rule was added correctly
if ! grep -qF -- "${ACCESS_RULE}" /etc/security/access.conf; then
    echo "ERROR: Access control rule was not added to /etc/security/access.conf"
    echo "Expected rule: ${ACCESS_RULE}"
    echo "This is a critical security configuration failure. Aborting."
    exit 1
fi

# Check that pam_access.so module file exists
if ! find /lib* /usr/lib* -name "pam_access.so" 2>/dev/null | grep -q "pam_access.so"; then
    echo "ERROR: pam_access.so module not found on system"
    echo "The PAM access module may not be installed properly."
    echo "This is a critical security configuration failure. Aborting."
    exit 1
fi

echo "PAM access control configuration verified successfully."
echo "ALL users are now restricted from local TTY/console login. SSH is the only access method."

# --- Disable Console Login Prompts ---

echo "Disabling TTY/console login prompts entirely..."

# Disable getty services for all standard TTYs (tty1-tty6)
# This prevents login prompts from appearing on virtual consoles
for tty_num in {1..6}; do
    if systemctl is-enabled "getty@tty${tty_num}.service" >/dev/null 2>&1; then
        systemctl disable "getty@tty${tty_num}.service"
        systemctl stop "getty@tty${tty_num}.service" 2>/dev/null || true
        echo "Disabled getty@tty${tty_num}.service"
    fi
done

# Disable console-getty service if it exists
# This prevents login prompts from appearing on the main console
if systemctl is-enabled "console-getty.service" >/dev/null 2>&1; then
    systemctl disable "console-getty.service"
    systemctl stop "console-getty.service" 2>/dev/null || true
    echo "Disabled console-getty.service"
fi

# Configure systemd to not automatically spawn virtual terminals
# This prevents new TTYs from being created automatically
if ! grep -q "^NAutoVTs=0" /etc/systemd/logind.conf; then
    if grep -q "^#NAutoVTs=" /etc/systemd/logind.conf; then
        # Uncomment and set to 0
        sed -i 's/^#NAutoVTs=.*/NAutoVTs=0/' /etc/systemd/logind.conf
    else
        # Add the setting
        echo "NAutoVTs=0" >> /etc/systemd/logind.conf
    fi
    echo "Configured systemd to disable automatic virtual terminal spawning"
fi

echo "Console login prompts have been completely disabled."
echo "The system is now SSH-only with no local login interface."

# --- Verify Console Access Disabling ---

echo "Verifying console access disabling configuration..."

# Verify getty services are actually disabled
getty_failures=()
for tty_num in {1..6}; do
    if systemctl is-enabled "getty@tty${tty_num}.service" >/dev/null 2>&1; then
        getty_failures+=("getty@tty${tty_num}.service")
    fi
done

if [ ${#getty_failures[@]} -gt 0 ]; then
    echo "ERROR: Failed to disable getty services: ${getty_failures[*]}"
    echo "This is a critical security configuration failure. Aborting."
    exit 1
fi

# Verify systemd logind configuration
if ! grep -q "^NAutoVTs=0" /etc/systemd/logind.conf; then
    echo "ERROR: NAutoVTs=0 was not properly set in /etc/systemd/logind.conf"
    echo "Current NAutoVTs setting:"
    grep -n "NAutoVTs" /etc/systemd/logind.conf || echo "  (none found)"
    echo "This is a critical security configuration failure. Aborting."
    exit 1
fi

echo "Console access disabling verified successfully."

# --- Install auditd ---

echo "Installing and configuring auditd..."
apt-get install -y auditd audispd-plugins

# A basic but effective ruleset for auditd (idempotent - overwrites existing)
cat > /etc/audit/rules.d/10-hardening.rules <<EOF
## Log system startup and shutdown
-w /sbin/init -p x -k system-boot

## Log logon/logoff events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

## Log sudo command usage
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

## Log changes to user/group information
-w /etc/group -p wa -k user-group-changes
-w /etc/passwd -p wa -k user-group-changes
-w /etc/shadow -p wa -k user-group-changes
-w /etc/gshadow -p wa -k user-group-changes

## Log changes to system configuration
-w /etc/sysctl.conf -p wa -k sysctl-changes
-w /etc/modprobe.conf -p wa -k modprobe-changes

## Log unauthorized access attempts to files
-a always,exit -F arch=b64 -S open,openat,openat2 -F exit=-EACCES -k unauthorized-access
-a always,exit -F arch=b32 -S open,openat,openat2 -F exit=-EACCES -k unauthorized-access
-a always,exit -F arch=b64 -S open,openat,openat2 -F exit=-EPERM -k unauthorized-access
-a always,exit -F arch=b32 -S open,openat,openat2 -F exit=-EPERM -k unauthorized-access

## Make the audit configuration immutable
-e 2
EOF

# Add additional security monitoring rules
cat >> /etc/audit/rules.d/10-hardening.rules <<EOF

## Log kernel module loading/unloading (rootkit detection)
-a always,exit -F arch=b64 -S init_module,delete_module -k modules
-a always,exit -F arch=b32 -S init_module,delete_module -k modules

## Log privilege escalation attempts
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -k privilege-escalation
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid -k privilege-escalation

## Log network configuration changes
-a always,exit -F arch=b64 -S sethostname,setdomainname -k network-config
-a always,exit -F arch=b32 -S sethostname,setdomainname -k network-config
EOF

# Restart auditd to apply new rules
systemctl restart auditd

# --- Automatic Security Updates ---

echo "Configuring unattended-upgrades for automatic security updates..."
apt-get install -y unattended-upgrades

# Enable security updates only (idempotent - overwrites existing)
cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::DevRelease "auto";
EOF

# Configure APT to run the upgrades (idempotent - overwrites existing)
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Enable the unattended-upgrades service which will run at 6:00 AM and 6:00 PM
systemctl enable unattended-upgrades

# --- Kernel Hardening ---

echo "Applying kernel hardening settings..."

# Create sysctl configuration for security hardening (idempotent - overwrites existing)
cat > /etc/sysctl.d/99-security-hardening.conf <<EOF
# Network Security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# IPv6 Security (if enabled)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Memory Protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1

# File System Security
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF

# Apply the settings immediately
sysctl -p /etc/sysctl.d/99-security-hardening.conf

# --- Verify Kernel Hardening Configuration ---

echo "Verifying kernel hardening settings..."

# Define critical security settings that must be verified
declare -A REQUIRED_SYSCTL_SETTINGS=(
    ["net.ipv4.ip_forward"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.all.accept_source_route"]="0"
    ["kernel.dmesg_restrict"]="1"
    ["kernel.kptr_restrict"]="2"
    ["fs.suid_dumpable"]="0"
    ["fs.protected_hardlinks"]="1"
    ["fs.protected_symlinks"]="1"
)

sysctl_failures=()
for setting in "${!REQUIRED_SYSCTL_SETTINGS[@]}"; do
    expected_value="${REQUIRED_SYSCTL_SETTINGS[$setting]}"
    actual_value=$(sysctl -n "$setting" 2>/dev/null || echo "FAILED")
    
    if [[ "$actual_value" != "$expected_value" ]]; then
        sysctl_failures+=("$setting: expected '$expected_value', got '$actual_value'")
    fi
done

if [ ${#sysctl_failures[@]} -gt 0 ]; then
    echo "ERROR: Critical sysctl settings verification failed:"
    for failure in "${sysctl_failures[@]}"; do
        echo "  - $failure"
    done
    echo "This is a critical security configuration failure. Aborting."
    exit 1
fi

echo "Kernel hardening settings verified successfully."

echo "--- Initial System Setup Finished ---"
echo ""
