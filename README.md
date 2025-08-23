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

## Features
-   **Idempotent** - Safe to re-run multiple times without side effects in case something breaks.


## Run

### 0. Get a fresh OS installation
Install Ubuntu Server.

### 1. Clone the Repository
```bash
git clone https://github.com/benvigano/sturdy_ubuntu.git
cd sturdy_ubuntu
```

### 2. Configure Settings

Fill in the `config.sh` file.

If your user doesn't have sudo privileges, add them to the sudo group first:
```bash
sudo usermod -aG sudo your_username
```

### 3. Make Scripts Executable

From within the `ubuntu-hardening` directory, run the following command:

```bash
chmod +x *.sh
```

### 4. Run the Scripts

Execute the main script as root:

```bash
sudo ./run-all.sh
```

### 5. Review Lynis audit report
At the end of the process, a Lynis audit report sent via email.

### 6. Secure Access Credentials

⚠️ *Loosing **both** GRUB credentials **and** ssh keys will permanently lock you out of your your system.*

1. **Store credentials:**
   - SSH port number
   - SSH private key correspondant to the public key used in setup
   - GRUB superuser name and password

2. **Remove Configuration File:**
   ```bash
   shred -u config.sh
   ```
   This securely deletes the configuration file containing sensitive information.

### 7. Reboot the system

```bash
sudo reboot
```


## NOT covered

### Because not automatable (but manual setup **highly  recommended**)
- **Physical Security:** BIOS/UEFI passwords, disabling boot from external devices etc.
- **Installation Choices:** Full Disk Encryption (LUKS), ZFS, secure installation media verification etc.
- **LAN Security:** Wifi, router configuration, network segmentation.

### For Design Choices
- **Disabling GRUB Recovery Mode:** Recovery mode is intentionally left enabled (password protected) as disabling it would cause permanent lockout in case access to the system is accidentally lost (lost ssh key, removed user from sudoers...).

### Possible changes/enhancements
- MFA for SSH
- Livepatch
- SELinux instead of AppArmor
- grsecurity
- HSMs
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
