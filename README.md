> [!IMPORTANT] 
> This configuration is intended **for fresh Ubuntu Server installations only**. Running this on existing production systems will almost certainly cause severe service disruption.

## Description
- Sets all **kernel**, **OS** and **OpenSSH Server** configuration for top security.
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

### 6. Reboot the system

```bash
sudo reboot
```


## NOT covered

What the configuration **doesn't cover**:
- **Physical security** - BIOS/UEFI passwords, disable boot from external devices, blocking all password login (including physical)
- **Installation choices** - LUKS, ZFS, secure installation media verification
- **GRUB security** - Bootloader password, secure boot configuration, kernel parameter hardening
- **LAN security** - Wifi, router configuration, network segmentation
- **Advanced hardening** - SELinux instead of AppArmor, grsecurity kernel patches, hardware security modules (HSM), container runtime security, MFA for SSH authentication, Ubuntu Livepatch for zero-downtime kernel updates


In case of **outside-facing services**:
- **Internet exposure** - IP filtering, geo-blocking, VPN detection
- **Service-specific hardening** - Web servers, databases, application-level security
