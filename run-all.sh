#!/bin/bash
#
# Runs all the numbered scripts in the correct order.

set -e
set -o pipefail

# --- Pre-flight Checks ---

# Check if running as root
if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: This script must be run as root."
  echo "Please run with 'sudo ./run-all.sh'"
  exit 1
fi

# Change to the script's directory
cd "$(dirname "$0")"

# Check for the configuration file
if [[ ! -f "config.sh" ]]; then
    echo "ERROR: The configuration file 'config.sh' was not found."
    echo "Please create it based on the example and fill in your details."
    exit 1
fi

# Load configuration variables
# The config file is sourced, making its variables available to this script
# and any sub-scripts it calls.
source config.sh

# --- Variable Validation ---

# Simple check to see if key variables are still set to their placeholder values
if [[ -z "$ADMIN_USER_PUBLIC_KEY" ]] || [[ "$ADMIN_USER" == "your_username" ]] || [[ "$GMAIL_APP_PASSWORD" == "your_gmail_app_password" ]]; then
    echo "ERROR: It looks like you haven't filled out the 'config.sh' file."
    echo "Please edit 'config.sh' and provide your specific details."
    exit 1
fi

# --- User Requirements Validation ---

echo "Validating user requirements..."

# Check if admin user exists
if ! id "${ADMIN_USER}" &>/dev/null; then
    echo "ERROR: User '${ADMIN_USER}' does not exist on this system."
    echo "Please create the user first or update ADMIN_USER in config.sh."
    exit 1
fi

# Check if admin user is not root
if [[ "${ADMIN_USER}" == "root" ]]; then
    echo "ERROR: ADMIN_USER cannot be 'root' for security reasons."
    echo "Please specify a non-root user in config.sh."
    exit 1
fi

# Check if admin user has sudo privileges
if ! sudo -l -U "${ADMIN_USER}" &>/dev/null; then
    echo "ERROR: User '${ADMIN_USER}' does not have sudo privileges."
    echo "Please add the user to the sudo group: sudo usermod -aG sudo ${ADMIN_USER}"
    exit 1
fi

# Check if we're not running as the admin user (security best practice)
if [[ "$(whoami)" == "${ADMIN_USER}" ]] && [[ "${EUID}" -eq 0 ]]; then
    echo "WARNING: You're running as the admin user with root privileges."
    echo "For better security, run this script as root: sudo ./run-all.sh"
fi

echo "User validation passed. User '${ADMIN_USER}' exists and has sudo privileges."

# --- Script Execution ---

echo "Starting Ubuntu Hardening Process..."

./01-initial-setup.sh
echo "[SUCCESS] Initial Setup script completed."

./02-configure-firewall.sh
echo "[SUCCESS] Firewall Configuration script completed."

./03-harden-ssh.sh
echo "[SUCCESS] SSH Hardening script completed."

./04-install-security-tools.sh
echo "[SUCCESS] Security Tools Installation and Configuration script completed."

./05-finalize-and-audit.sh
echo "[SUCCESS] Finalization and Audit script completed."

echo ""
echo "-----------------------------------------------------------"
echo "All hardening scripts have been executed successfully."
echo "Please review the output and the generated Lynis report."
echo "A system reboot is recommended to ensure all changes take effect."
echo "-----------------------------------------------------------"

exit 0
