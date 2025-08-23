#!/bin/bash
# 01a-harden-grub.sh

set -e
set -o pipefail

# Load configuration variables
source "$(dirname "$0")/config.sh"

echo "--- (2/6) Starting GRUB Bootloader Hardening ---"

# --- Set GRUB Password ---

echo "Setting GRUB bootloader password to protect against unauthorized boot changes..."

# Check if a password is provided
if [[ -z "$GRUB_PASSWORD" ]]; then
    echo "ERROR: GRUB_PASSWORD is not set in config.sh. Aborting."
    echo "Please set a strong password to protect the bootloader."
    exit 1
fi

# Generate a hashed password for GRUB
# This is a non-interactive way to create the hash
echo "Generating GRUB password hash..."
GRUB_PASSWORD_HASH=$(echo -e "${GRUB_PASSWORD}\n${GRUB_PASSWORD}" | grub-mkpasswd-pbkdf2 | grep -o "grub.pbkdf2.sha512.*" || true)

# Verify we got a valid hash
if [[ ! "${GRUB_PASSWORD_HASH}" =~ ^grub\.pbkdf2\.sha512\. ]]; then
    echo "ERROR: Failed to generate a valid GRUB password hash. Output was:"
    echo -e "${GRUB_PASSWORD}\n${GRUB_PASSWORD}" | grub-mkpasswd-pbkdf2
    exit 1
fi

if [[ -z "$GRUB_PASSWORD_HASH" ]]; then
    echo "ERROR: Failed to generate GRUB password hash. Aborting."
    exit 1
fi

# Create a custom GRUB configuration file for security settings
# This is idempotent and safer than modifying existing files.
GRUB_SECURITY_FILE="/etc/grub.d/40_custom"
cat > "${GRUB_SECURITY_FILE}" <<'EOF'
#!/bin/sh
cat << 'EOL'
if [ "${grub_platform}" == "efi" ]; then
    set superusers="${GRUB_SUPERUSER}"
    password_pbkdf2 ${GRUB_SUPERUSER} ${GRUB_PASSWORD_HASH}
fi
EOL
EOF

# Replace the password hash placeholder with the actual hash
# This is done separately to avoid variable expansion issues in the heredoc
sed -i "s|\${GRUB_PASSWORD_HASH}|${GRUB_PASSWORD_HASH}|" "${GRUB_SECURITY_FILE}"

# Make the new GRUB config file executable
chmod +x "${GRUB_SECURITY_FILE}"

# Update the main GRUB configuration to apply all changes
echo "Updating GRUB configuration..."
update-grub

# --- Verify GRUB Hardening ---

echo "Verifying GRUB hardening configuration..."

GRUB_CONFIG_FILE="/boot/grub/grub.cfg"
grub_failures=()

# Check that the superuser is set in the final GRUB config
if ! grep -q "set superusers=\"${GRUB_SUPERUSER}\"" "${GRUB_CONFIG_FILE}"; then
    grub_failures+=("GRUB superuser was not set in ${GRUB_CONFIG_FILE}")
fi

# Check that the password is set in the final GRUB config
if ! grep -q "password_pbkdf2 ${GRUB_SUPERUSER}" "${GRUB_CONFIG_FILE}"; then
    grub_failures+=("GRUB password was not set in ${GRUB_CONFIG_FILE}")
fi

if [ ${#grub_failures[@]} -gt 0 ]; then
    echo "ERROR: Critical GRUB hardening verification failed:"
    for failure in "${grub_failures[@]}"; do
        echo "  - $failure"
    done
    # As a safety measure, remove the potentially broken security file
    rm -f "${GRUB_SECURITY_FILE}"
    update-grub
    echo "Reverted GRUB security changes."
    echo "This is a critical security configuration failure. Aborting."
    exit 1
fi

echo "GRUB configuration verified successfully."
echo "The GRUB bootloader is now password-protected."

echo "--- GRUB Bootloader Hardening Finished ---"
echo ""
