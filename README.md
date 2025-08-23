> [!IMPORTANT] 
> This configuration is intended **for fresh Ubuntu Server installations only**. Running this on existing production systems will almost certainly cause severe service disruption.

## Description
- Sets all **kernel**, **OS**, **OpenSSH Server** and **GRUB Bootloader** configuration for top security.
- Enables automatic security updates (unattended-upgrades)
- Sets up **comprehensive monitoring**, entirely configured for email-only alerting (zero periodic checks required). Alerts are sent only in case of security issues or threat detection - no periodic emails/summaries.
  - **ClamAV**: Antivirus with weekly system scans
  - **AIDE**: File integrity monitoring with daily checks
  - **rkhunter**: Rootkit detection with automated database updates
  - **fail2ban**: Intrusion prevention with recidive jail for repeat offenders
  - **auditd**: Advanced system auditing with kernel module and privilege escalation monitoring
  - **AppArmor**: Mandatory access control for critical services
  - **UFW**: Strict firewall configuration
  - **unattended-upgrades**: Automated security patches
  - **Postfix**: Email alerts via Gmail SMTP
  - **Lynis**: Initial security audit report emailed for review
- Ensures no long-term operations required:
  - Automated log rotation and cleanup
  - Weekly security tool database updates

### Scheduled Tasks
*(All times relative to DAILY_TASKS_START_TIME configured in config.sh)*

**Daily (via cron):**
- START      - File integrity check (AIDE)
- START+1h   - Security updates (unattended-upgrades)
- START+2h   - Antivirus signature update (ClamAV)
- START+3h   - Rootkit check (rkhunter)
- START+4h   - Time synchronization check (chrony)
- START+5h   - Kernel module integrity check

**Weekly (via cron):**
- Sunday   - START      - Full system antivirus scan (ClamAV)
- Saturday - START      - Rootkit database update (rkhunter)
- Saturday - START+1h   - Intrusion prevention update (fail2ban)

*Note: Tasks are intentionally spread out to avoid resource contention.

## Run
> [!TIP]  
> All scripts are **idempotent**, which means they are safe to re-run multiple times without side effects in case something goes wrong.

> [!NOTE]
>The following operational variables **will be stored** in a persistent configuration file (`/etc/sturdy.conf`) as they are needed by scheduled tasks:
>- NOTIFICATION_EMAIL
>- GMAIL_ADDRESS
>- SERVER_NAME
>- SSH_PORT
>- ADMIN_USER

```bash
git clone https://github.com/benvigano/sturdy_ubuntu.git`
cd sturdy_ubuntu
nano config.sh  # Fill in your variables
```



```bash
# If your user is not sudo:
sudo usermod -aG sudo your_username
```

```bash
# Make scripts exectuable
chmod +x *.sh
```

```bash
# Run the configuration
sudo ./run-all.sh

# Test ssh access from another terminal without closing the current terminal
# Test ssh access from another terminal
ssh -p your_ssh_port your_admin_user@your_server_ip

# Review Lynis audit report sent via email

# Store credentials you set in the config.sh file in a safe place:
# 1. ssh key corresponding to the public key you set
# 2. ssh port number
# 3. GRUB superuser user name and password

# (^^ IMPORTANT! Loosing both GRUB credentials and ssh keys will permanently lock you out of your your system!)

# Delete config file
shred -u config.sh

# Reboot the system
sudo reboot

# After rebooting, test GRUB access
```

## NOT covered

### Out of scope (but manual setup **highly  recommended**)
- **Physical Security:** BIOS/UEFI passwords, secure boot, disabling boot from external devices etc.
- **Installation Choices:** Full Disk Encryption (LUKS), ZFS, secure installation media verification etc.
- **LAN Security:** Wifi, router configuration, network segmentation.
- **Backup Strategy:** Retention policies, versioning etc.

### Design Choices
- **Disabling GRUB Recovery Mode:** Recovery mode is intentionally left enabled (password protected) as disabling it would cause permanent lockout in case access to the system is accidentally lost (lost ssh key, removed user from sudoers...).

### Possible changes/enhancements
- MFA for SSH
- Livepatch
- SELinux instead of AppArmor
- grsecurity
- HSMs
- Requiring pre-hashed grub password to avoid saving it in plaintext
#### In case of **outside-facing services**:
- Internet exposure - IP filtering, geo-blocking, VPN detection
- Service-specific hardening - web servers, databases, application-level security

## Troubleshooting
*(Requires GRUB access)*
### Case: SSH Lockout / Lost Private Key
-   **Physical Server:** At boot, enter the GRUB password, select "Advanced options," and then "Recovery mode." This will give you a root shell to repair the system (e.g., add a new SSH key to `/home/your_user/.ssh/authorized_keys`).
-   **VPS:** Most providers offer a VNC/KVM console that simulates physical access. Use this to enter the GRUB password and access recovery mode as you would on a physical machine.

### Case: Lost GRUB Credentials / Have SSH Access
*(Requires ssh access and sudo)*
-   **Physical/VPS:** SSH into the system and:
    ```bash
    # Generate new GRUB password hash
    grub-mkpasswd-pbkdf2
    # Edit GRUB custom config
    sudo nano /etc/grub.d/40_custom
    # Update the password_pbkdf2 line with new hash
    sudo update-grub
    ```
