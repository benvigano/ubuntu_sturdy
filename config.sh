#!/bin/bash
#
# Configuration file for Ubuntu Hardening Scripts
#
ADMIN_USER="admin_user"  # Must be an existing non-root user with sudo privileges.
ADMIN_USER_PUBLIC_KEY=""  # The full public SSH key for the admin user.
SSH_PORT="33001"  # A non-standard port for the SSH daemon.
GMAIL_ADDRESS="sender-email@gmail.com"  # A Gmail address that will send the alert emails.
GMAIL_APP_PASSWORD="sender_gmail_app_password"  # Password of the Gmail address.
NOTIFICATION_EMAIL="receiver@email.com"  # Destination email for all security notifications.
SERVER_NAME="server_name"  # Exclusively for alert email subject lines.
DAILY_TASKS_START_TIME="05:00"  # Start time (24h format) for daily security tasks.
