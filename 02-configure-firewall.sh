#!/bin/bash
# 02-configure-firewall.sh

set -e
set -o pipefail

# Load configuration variables
source "$(dirname "$0")/config.sh"

echo "--- (2/5) Starting Firewall Configuration ---"

apt-get install -y ufw

# --- Base UFW Configuration ---

echo "Configuring UFW with default deny policy..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow in on lo
ufw allow out on lo

# --- Allow SSH ---

echo "Allowing SSH on port ${SSH_PORT} from any IP..."
ufw allow "${SSH_PORT}"/tcp


# --- Enable Firewall ---

echo "Enabling the firewall..."
ufw --force enable

echo "Firewall status:"
ufw status verbose

echo "--- Firewall Configuration Finished ---"
echo ""
