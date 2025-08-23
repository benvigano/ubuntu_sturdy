#!/bin/bash
set -e
set -o pipefail

echo "Testing all scheduled tasks..."

# Load persistent configuration
source /etc/sturdy.conf || {
    echo "ERROR: Persistent configuration not found at /etc/sturdy.conf. Run 01-initial-setup.sh first."
    exit 1
}

# Function to test a script
test_script() {
    local script="$1"
    local name="$2"
    
    echo "Testing ${name}..."
    if [[ ! -x "${script}" ]]; then
        echo "ERROR: Script not found or not executable: ${script}"
        return 1
    fi

    # Test script in a subshell to isolate environment
    (
        # Try to run the script
        if ! "${script}"; then
            echo "ERROR: ${name} failed to run"
            return 1
        fi
    ) || return 1

    echo "${name} test passed"
    return 0
}

failures=()

# Test AIDE check
if ! test_script "/usr/local/sbin/check_aide.sh" "AIDE Check"; then
    failures+=("AIDE Check")
fi

# Test ClamAV update
if ! test_script "/usr/local/sbin/check_clamav_update.sh" "ClamAV Update"; then
    failures+=("ClamAV Update")
fi

# Test ClamAV scan
if ! test_script "/usr/local/sbin/run_clamscan.sh" "ClamAV Scan"; then
    failures+=("ClamAV Scan")
fi

# Test rkhunter update
if ! test_script "/usr/local/sbin/check_rkhunter_update.sh" "Rkhunter Update"; then
    failures+=("Rkhunter Update")
fi

# Test AppArmor notification script
if ! test_script "/etc/apparmor/notify.d/notify" "AppArmor Notifications"; then
    failures+=("AppArmor Notifications")
fi

# Test email formatting
if ! test_script "/usr/local/sbin/format_security_mail.sh" "Email Formatting" "INFO" "TEST" "Test Subject" "Test Body"; then
    failures+=("Email Formatting")
fi

# Test log rotation configurations
test_logrotate() {
    local config="$1"
    local name="$2"
    
    echo "Testing ${name} log rotation config..."
    if ! logrotate -d "${config}" 2>&1 | grep -q "error:"; then
        echo "${name} rotation config test passed"
        return 0
    else
        echo "ERROR: ${name} rotation config test failed"
        return 1
    fi
}

# Test all log rotation configs
for config in aide audit-custom fail2ban-custom clamav-custom rkhunter-custom postfix-custom; do
    if ! test_logrotate "/etc/logrotate.d/${config}" "${config} rotation"; then
        failures+=("${config} log rotation")
    fi
done

# Test fail2ban update command (simulation)
echo "Testing fail2ban update command..."
if ! apt-get update -s >/dev/null 2>&1; then
    failures+=("Fail2ban update command - apt update failed")
elif ! apt-get install --only-upgrade fail2ban -s >/dev/null 2>&1; then
    failures+=("Fail2ban update command - package upgrade failed")
elif ! systemctl is-active fail2ban >/dev/null 2>&1; then
    failures+=("Fail2ban update command - service not active")
else
    echo "Fail2ban update command test passed"
fi

# Test rkhunter system cron functionality
echo "Testing rkhunter system cron..."
if ! grep -q "^CRON_DAILY_RUN=\"true\"" /etc/default/rkhunter; then
    failures+=("rkhunter system cron not enabled")
elif ! command -v rkhunter >/dev/null 2>&1; then
    failures+=("rkhunter command not found")
elif ! rkhunter --version >/dev/null 2>&1; then
    failures+=("rkhunter command execution failed")
else
    echo "rkhunter system cron test passed"
fi

# Test unattended-upgrades service
echo "Testing unattended-upgrades service..."
if ! systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
    failures+=("unattended-upgrades service not enabled")
elif ! systemctl is-active unattended-upgrades >/dev/null 2>&1; then
    failures+=("unattended-upgrades service not active")
elif ! unattended-upgrade --dry-run >/dev/null 2>&1; then
    failures+=("unattended-upgrades dry run failed")
else
    echo "unattended-upgrades service test passed"
fi

# Report results
if [ ${#failures[@]} -gt 0 ]; then
    echo "ERROR: Some scheduled tasks failed testing:"
    for failure in "${failures[@]}"; do
        echo "  - ${failure}"
    done
    exit 1
fi

echo "All scheduled tasks tested successfully!"
