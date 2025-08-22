#!/bin/bash
# 01-initial-setup.sh

set -e
set -o pipefail

# Load configuration variables
source "$(dirname "$0")/config.sh"

echo "--- (1/5) Starting Initial System Setup ---"

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

# --- Admin User Access Control ---

echo "Disabling local console login for '${ADMIN_USER}' to enforce SSH-only access..."

# Ensure pam_access.so is enforced for login. This makes the system use /etc/security/access.conf.
# The regex handles various spacing. We add it before the session block for convention.
if ! grep -q "account[[:space:]]\\{1,\\}required[[:space:]]\\{1,\\}pam_access.so" /etc/pam.d/login; then
    sed -i '/# sessions are required/i account     required      pam_access.so' /etc/pam.d/login
fi

# Add rule to deny local login for the admin user.
# This is idempotent: it only adds the rule if it doesn't already exist for the user.
ACCESS_RULE="-: (${ADMIN_USER}) : LOCAL"
if ! grep -qF -- "${ACCESS_RULE}" /etc/security/access.conf; then
    echo "" >> /etc/security/access.conf
    echo "# Deny the admin user from local TTY login to enforce SSH-only access" >> /etc/security/access.conf
    echo "${ACCESS_RULE}" >> /etc/security/access.conf
fi

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

echo "--- Initial System Setup Finished ---"
echo ""
