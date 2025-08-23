#!/bin/bash
# 03-harden-ssh.sh

set -e
set -o pipefail

# Load configuration variables
source "$(dirname "$0")/config.sh"

SSHD_CONFIG="/etc/ssh/sshd_config"

echo "--- (4/6) Starting SSH Hardening ---"

# --- Set up Authorized Keys for Admin User ---

# Ensure the admin user exists
if ! id "${ADMIN_USER}" &>/dev/null; then
    echo "ERROR: The specified admin user '${ADMIN_USER}' does not exist. Aborting."
    exit 1
fi

echo "Setting up SSH authorized keys for user '${ADMIN_USER}'..."
ADMIN_HOME=$(getent passwd "${ADMIN_USER}" | cut -d: -f6)
SSH_DIR="${ADMIN_HOME}/.ssh"
AUTH_KEYS_FILE="${SSH_DIR}/authorized_keys"

mkdir -p "${SSH_DIR}"
echo "${ADMIN_USER_PUBLIC_KEY}" > "${AUTH_KEYS_FILE}"

# Set correct permissions
chmod 700 "${SSH_DIR}"
chmod 600 "${AUTH_KEYS_FILE}"
chown -R "${ADMIN_USER}":"${ADMIN_USER}" "${SSH_DIR}"

# --- Harden sshd_config ---

echo "Hardening the SSH daemon configuration at ${SSHD_CONFIG}..."

# Create a backup of the original config file
cp "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak-$(date +%F)"

# Configure SSH settings idempotently
update_sshd_config() {
    local key="$1"
    local value="$2"
    # Comment out any existing instance of the key
    sed -i -E "s/^[#\s]*${key}.*$/# &/" "${SSHD_CONFIG}"
    # Add the new key-value pair at the end of the file
    echo "${key} ${value}" >> "${SSHD_CONFIG}"
}

update_sshd_config "Port" "${SSH_PORT}"
update_sshd_config "Protocol" "2"
update_sshd_config "PermitRootLogin" "no"
update_sshd_config "PasswordAuthentication" "no"
update_sshd_config "PubkeyAuthentication" "yes"
update_sshd_config "PermitEmptyPasswords" "no"
update_sshd_config "ChallengeResponseAuthentication" "no"
update_sshd_config "KerberosAuthentication" "no"
update_sshd_config "GSSAPIAuthentication" "no"
update_sshd_config "UsePAM" "yes"
update_sshd_config "X11Forwarding" "no"
update_sshd_config "PrintMotd" "no"
update_sshd_config "ClientAliveInterval" "180"
update_sshd_config "ClientAliveCountMax" "2"
update_sshd_config "AllowUsers" "${ADMIN_USER}"
update_sshd_config "LoginGraceTime" "2m"
update_sshd_config "MaxAuthTries" "3"


# --- Restart SSH Service ---

echo "Validating SSH configuration and restarting the service..."
sshd -t
if [ $? -ne 0 ]; then
    echo "ERROR: SSH configuration is invalid. Please check ${SSHD_CONFIG}."
    echo "Restoring backup..."
    mv "${SSHD_CONFIG}.bak-$(date +%F)" "${SSHD_CONFIG}"
    exit 1
fi

systemctl restart ssh

# --- Verify SSH Configuration ---

echo "Verifying SSH hardening configuration..."

# Define critical SSH settings that must be verified
declare -A REQUIRED_SSH_SETTINGS=(
    ["Port"]="${SSH_PORT}"
    ["PermitRootLogin"]="no"
    ["PasswordAuthentication"]="no"
    ["PubkeyAuthentication"]="yes"
    ["PermitEmptyPasswords"]="no"
    ["UsePAM"]="yes"
    ["AllowUsers"]="${ADMIN_USER}"
    ["MaxAuthTries"]="3"
)

ssh_failures=()
for setting in "${!REQUIRED_SSH_SETTINGS[@]}"; do
    expected_value="${REQUIRED_SSH_SETTINGS[$setting]}"
    # Extract the actual value from sshd_config (get the last uncommented occurrence)
    actual_value=$(grep "^${setting}" "${SSHD_CONFIG}" | tail -1 | awk '{print $2}' || echo "MISSING")
    
    if [[ "$actual_value" != "$expected_value" ]]; then
        ssh_failures+=("$setting: expected '$expected_value', got '$actual_value'")
    fi
done

if [ ${#ssh_failures[@]} -gt 0 ]; then
    echo "ERROR: Critical SSH settings verification failed:"
    for failure in "${ssh_failures[@]}"; do
        echo "  - $failure"
    done
    echo "This is a critical security configuration failure. Aborting."
    exit 1
fi

# Verify SSH authorized keys file exists and has content
if [[ ! -f "${AUTH_KEYS_FILE}" ]] || [[ ! -s "${AUTH_KEYS_FILE}" ]]; then
    echo "ERROR: SSH authorized keys file is missing or empty: ${AUTH_KEYS_FILE}"
    echo "This would prevent SSH access. Aborting."
    exit 1
fi

echo "SSH hardening configuration verified successfully."

echo "SSH has been hardened. Remember to connect using port ${SSH_PORT}."
echo "Example: ssh -p ${SSH_PORT} ${ADMIN_USER}@your_server_ip"
echo "--- SSH Hardening Finished ---"
echo ""
