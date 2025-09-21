# 🛡️ Homelab SOC Project: Proxmox + Windows Server + Wazuh + Discord Alerts

This project sets up a fully functional **Security Operations Center (SOC) lab** using:

- 🖥️ **Proxmox 8** for virtualization
- 🪟 **Windows Server 2025** as Domain Controller
- 🧠 **Wazuh SIEM** on Ubuntu 22
- 🧪 **Kali Linux** for offensive simulation
- 🔔 **Discord alerts** via Webhook integration

---

## 🧰 Lab Infrastructure

| Role             | OS/Platform         | Notes                        |
|------------------|---------------------|------------------------------|
| Hypervisor       | Proxmox 8           | Installed on bare metal      |
| Domain Controller| Windows Server 2025 | DC01, homelab.local domain   |
| SIEM             | Ubuntu 22 LTS       | Wazuh all-in-one             |
| Attacker Machine | Kali Linux (VM)     | Used for brute-force test    |
| Client VM        | Windows 10/11       | Joins domain for GPO tests   |

---

## 📦 Setup Steps Overview

### 1. Install Proxmox VE 8

- Burn ISO to USB using Rufus
- Install Proxmox on host machine
- Expand root volume:
```bash
lvremove /dev/pve/data
lvextend -l +100%FREE /dev/pve/root
resize2fs /dev/pve/root
```

- Update sources to no-subscription repo

- Edit Ceph and APT sources

Run apt-get update && apt-get upgrade -y

📸 Screenshot Placeholder: Proxmox Console After Boot

2. Install Windows Server 2025

- Download from Microsoft Evaluation Center
- Create VM in Proxmox (8GB RAM, 64GB disk)
- Rename to DC01
- Assign static IP (e.g., 10.0.0.2)
- Disable IPv6

📸 Screenshot Placeholder: DC01 Network Settings

3. Promote to Domain Controller

- Add AD DS role → Promote this server → New Forest → Domain: homelab.local
- Set DSRM password (save it)

📸 Screenshot Placeholder: AD DS Promotion Wizard

4. Create Organizational Units and Users

Use this PowerShell script on DC01:

```bash
# === CONFIG ===
$domain = "homelab.local"
$defaultPassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
$baseDN = "DC=homelab,DC=local"

# === OUs ===
$OUs = @("Homelab-HR", "Homelab-IT", "Homelab-Users", "Homelab-Admins")
foreach ($ou in $OUs) {
    New-ADOrganizationalUnit -Name $ou -Path $baseDN -ErrorAction SilentlyContinue
}

# === Users ===
$users = @(
    @{First="John"; Last="Doe"; Department="IT"},
    @{First="Alice"; Last="Smith"; Department="HR"},
    ...
)
foreach ($user in $users) {
    # logic here
}
```

📸 Screenshot Placeholder: ADUC with Users Created

5. Configure Password + Lockout Policies

- Run gpmc.msc → Default Domain Policy
- Set:
    - Min password length: 8
    - Complexity: Enabled
    - Max age: 30 days
    - Lockout threshold: 5
    - Lockout duration: 15 mins
    - Reset counter: 15 mins

📸 Screenshot Placeholder: GPO Password Policy

6. Join Client VM to the Domain

- Set DNS to DC01's IP (e.g., 10.0.0.2)
- Join homelab.local
- Reboot → Login as homelab\john.doe

📸 Screenshot Placeholder: Domain Join Prompt + Login

🧠 Wazuh SIEM Setup
7. Deploy Wazuh (Ubuntu 22)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install curl unzip net-tools gnupg apt-transport-https -y
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```
Access UI at https://10.0.0.80

Username: admin, Password: admin

📸 Screenshot Placeholder: Wazuh Dashboard

🔓 Phase 1: Brute Force Attack Simulation
On Kali:

```bash
sudo apt update && sudo apt install hydra ncrack -y
nmap -p 3389 10.0.0.2
echo -e 'password1\npassword2\nP@ssw0rd123!' > mini-rdp.txt
hydra -t 1 -V -l john.doe -P mini-rdp.txt rdp://10.0.0.2
```

Confirm Detection in Wazuh

Search for:

```bash
data.win.system.eventID:4625
```

📢 Discord Notification Integration
1. Create Discord Webhook

Go to Discord → Channel Settings → Integrations → Webhooks → Create New

📸 Screenshot Placeholder: Webhook Settings

2. Create Notification Script

/var/ossec/active-response/bin/discord_notify.sh

```bash
#!/bin/bash
read alert
username=$(echo "$alert" | grep -oP '"targetUserName":"\K[^"]+')
srcip=$(echo "$alert" | grep -oP '"ipAddress":"\K[^"]+')
ruleid=$(echo "$alert" | grep -oP '"rule"\s*:\s*\{[^}]*"id"\s*:\s*"\K[^"]+')

WEBHOOK_URL="https://discord.com/api/webhooks/XXXX/YYYY"
json_payload=$(cat <<EOF
{
  "content": "🚨 **Wazuh Alert** 🚨\n**Rule ID:** $ruleid\n**User:** $username\n**Source IP:** $srcip"
}
EOF
)
curl -X POST -H "Content-Type: application/json" -d "$json_payload" "$WEBHOOK_URL"
```

3. Register in ossec.conf

```bash
<command>
  <name>discord-notify</name>
  <executable>discord_notify.sh</executable>
  <expect>user</expect>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>discord-notify</command>
  <location>all</location>
  <rules_ids>60204</rules_ids>
</active-response>
```
📸 Screenshot Placeholder: Discord Alert Message

🚀 Extra

 - Add response playbook to block IPs

 - Create email or SMS fallback alerts

 - Deploy Graylog for log retention

 - Set up SIEM rules for phishing detection

🧾 Credits

Built by AtypicalSysAdmin as a home lab SOC learning project.


