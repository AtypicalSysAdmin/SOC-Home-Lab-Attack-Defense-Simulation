### Home lab SOC Simulation Proxmox + Windows server + Kali + Wazuh + Discord channel notifciations

# Proxomx

Download Proxmox 8 iOS, use Rufus to burn it to a USB, and install it on a machine.

# Increase Proxmox Storage:

Datacenter > Storage > Remove LVM-Thin

Click on node (pve) > shell

```bash
lvremove /dev/pve/data
lvextend -l +100%FREE /dev/pve/root
resize2fs /dev/pve/root 
```

Datacenter > storage > select root > edit > content > add all

# Change enterprise license for Proxmox updates:

```bash
nano /etc/apt/sources.list.d/pve-enterprise.list
```

Comment out the existing line and add

```bash
deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription
```

Edit Ceph (required for Proxmox 8+)

```bash
nano /etc/apt/sources.list.d/ceph.list
```

Comment out the existing line and add

```bash
deb http://download.proxmox.com/debian/ceph-quincy bookworm no-subscription
```

Ctrl + x & ctrl + o save and close, then run updates

```bash
apt-get update -y && apt-get upgrade -y
```

Configuring No Subscription Repository in Proxmox VE 8.x Part - 6

# Windows Server 2025

Download Windows Server 2025 iso: Windows Server 2025 | Microsoft Evaluation Center

Create a Windows Server VM on Proxmox or Hyper-V (8GB RAM, 64GB Storage for Desktop experience)

# Update Windows using the task scheduler or manually

```bash
  $session=new-pssession 10.0.0.2 -Credential (Get-Credential)
  copy-item -ToSession $session -Path "F:\IT-F\Security Operations Centre\Scripts" -Recurse -Destination C:\script
  Invoke-Command -Session $session -ScriptBlock {
   
      $time = ([datetime]'2023-10-20 20:00:00')
      $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '-ExecutionPolicy bypass -File C:\Script\Install-WindowsUpdate.ps1' 
      $trigger = New-ScheduledTaskTrigger -Once -At $time 
      $principal = New-ScheduledTaskPrincipal  -RunLevel Highest -UserID "NT AUTHORITY\SYSTEM" -LogonType S4U
   
     if (! (Get-ScheduledTask -TaskName "Install-WindowsUpdate" -ErrorAction SilentlyContinue))
     {
         Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "Install-WindowsUpdate"
     }
     else
     {
         Set-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "Install-WindowsUpdate"
     }
  
     Get-ScheduledTaskInfo -TaskName Install-WindowsUpdate
 }
  
 Invoke-Command -Session $session -ScriptBlock {
  Start-ScheduledTask -TaskName Install-WindowsUpdate
 }
  
 Invoke-Command -Session $session -ScriptBlock {
  Get-ScheduledTaskInfo -TaskName Install-WindowsUpdate
 }
```

wait for a restart or

Rename the server to DC01

# Promote to Domain Controller

Manage > Add roles and features > Active Directory and Domain Services
 
Click on Promote > Add a new forest > root domain: homelab.local

Set the DSRM password and store it somewhere important

During Active Directory setup, a DNS delegation warning appeared, indicating that the authoritative parent zone for the domain homelab.local could not be found. Since this is a standalone lab environment using an internal .local domain, this warning is expected and was safely ignored.

Assign a static IPv4 address to the DC01 network adapter and disable IPv6
 
Click on Next until the end of the wizard > finish 

# Enable Advanced Feature in Active Directory Users

Use this script to create fake users:

```bash
   # === CONFIG ===
  $domain = "homelab.local"
  $defaultPassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
  $baseDN = "DC=homelab,DC=local"
   
  # === Organizational Units ===
  $OUs = @("Homelab-HR", "Homelab-IT", "Homelab-Users", "Homelab-Admins")
  foreach ($ou in $OUs) {
      $ouPath = "OU=$ou,$baseDN"
     if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$ou)" -SearchBase $baseDN -ErrorAction SilentlyContinue)) {
         New-ADOrganizationalUnit -Name $ou -Path $baseDN
         Write-Host "Created OU: $ou"
     } else {
         Write-Host "OU already exists: $ou"
     }
 }
  
 # === Users to Create ===
 $users = @(
     @{First="John"; Last="Doe"; Department="IT"},
     @{First="Alice"; Last="Smith"; Department="HR"},
     @{First="Bob"; Last="Taylor"; Department="Users"},
     @{First="Eve"; Last="Jackson"; Department="Admins"},
     @{First="Charlie"; Last="Brown"; Department="IT"},
     @{First="Diana"; Last="Prince"; Department="HR"},
     @{First="Frank"; Last="Miller"; Department="Users"},
     @{First="Grace"; Last="Hopper"; Department="IT"},
     @{First="Hank"; Last="Pym"; Department="Admins"},
     @{First="Ivy"; Last="Wells"; Department="Users"}
 )
  
 # === Create Users ===
 foreach ($user in $users) {
     $username = ($user.First + "." + $user.Last).ToLower()
     $ouPath = "OU=Homelab-$($user.Department),$baseDN"
     $name = "$($user.First) $($user.Last)"
  
     if (-not (Get-ADUser -Filter { SamAccountName -eq $username } -ErrorAction SilentlyContinue)) {
         try {
             New-ADUser `
                 -Name $name `
                 -SamAccountName $username `
                 -UserPrincipalName "$username@$domain" `
                 -AccountPassword $defaultPassword `
                 -Enabled $true `
                 -DisplayName $name `
                 -GivenName $user.First `
                 -Surname $user.Last `
                 -Path $ouPath `
                 -Department $user.Department `
                 -EmailAddress "$username@$domain"
  
             Write-Host "✅ Created user: $username in $ouPath"
         } catch {
             Write-Host "❌ Error creating user $username : $_"
         }
     } else {
         Write-Host "⚠️ User $username already exists. Skipping."
     }
 }
  #the end
```

Edit group policy

Run ```bash gpmc.msc``` from the Run or PowerShell

Expand your forest → Domains → homelab.local

Right-click Default Domain Policy → Click Edit

    Computer Configuration →

    Policies →

     Windows Settings →
    
       Security Settings →
      
         Account Policies →
        
           Password Policy 

           Account Lockout policy
 

# Join a client computer to the domain:

Set the DNS to be the DC01 IP address (i.e. 10.0.0.2) > join the domain Homelab
 
Login as Homelab\John.doe 

With the domain credential
 
Verify the applied group policy

```bash
gpresult /r
```

# Wazuh:

Download Ubuntu 22 LTS ISO and boot up a VM, then run the following to install Wazuh

```bash
sudo apt update && sudo apt upgrade -y
#Install Basic dependencies:
sudo apt install curl unzip net-tools gnupg apt-transport-https -y
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Access through browser:

https://10.0.0.80

Login with default:

•	Username: admin
•	Password: read Wazuh documentation

# Kali

Download Kali iso

Create a vm on hyper v

Enable Kali Enhanced session for Hyper-V

Terminal: 

```kali-teaks ``` > virtualization > configure hyper-v enhanced session > logout

Host: 

```bash
1. Set-VM "(YOUR VM NAME HERE)" -EnhancedSessionTransportType HVSocket

```

Installing Hyper-V Enhanced Session Mode (Guest Tools) | Kali Linux Documentation

# Phase 1: Brute force John.Doe on DC01

```bash
sudo apt update
sudo apt install hydra ncrack -y
#cofrim installation
hydra -h
ncrack -h

#scan rdp port open
nmap -p 3389 10.0.0.2/24  

#add word list
echo -e '123456\npassword\nqwerty\nwelcome\nPassw0rd\nadmin123\nletmein\n12345678\nPassword!\nP@ssw0rd123!' > mini-rdp.txt

#run the attack
hydra -t 1 -V -l john.doe -P mini-rdp.txt rdp://10.0.0.2
```

•	-t 1 = 1 thread to avoid lockout burst
•	-V = verbose (see each attempt)
•	-P = wordlist (does NOT contain the real password)
 
# Confirm detection: Go to your Wazuh dashboard → Security Events

•	Event ID: 4625
•	Username: john.doe
•	Source IP: <Kali IP>

Search for Failed Logins (Event ID 4625)

DQL:

```bash
 data.win.system.eventID:4625
```

Search for Account Lockouts (Event ID 4740)

DQL:

```bash
 data.win.system.eventID:4740
```

Search for successful login attempts with Kali’s IP address:

DQL:

```bash
 data.win.system.eventID:4624
```

Wazuh ui > Management > Administration > Rules

•	18107 → Windows failed login (Event ID 4625)
•	1002 → Linux authentication failed

# Add a notification to the Discord channel:

Create a Discord Webhook

1.	Go to your Discord server settings.
2.	Select the channel you want alerts in.
3.	Click the ⚙️ settings icon → go to Integrations → Webhooks.
4.	Click "New Webhook", name it (e.g., "Wazuh Alerts"), and copy the Webhook URL (e.g., https://discord.com/api/webhooks/...).

Keep this URL safe.

Create the Wazuh Discord Notification Script

```bash
 sudo nano /var/ossec/active-response/bin/discord_notify.sh
```

Paste the following:

 ```bash
  #!/bin/bash
   
  # Read alert input from Wazuh
  read alert
   
  # Extract details (basic example — you can make this more detailed)
  username=$(echo "$alert" | grep -oP '"targetUserName":"\K[^"]+')
  srcip=$(echo "$alert" | grep -oP '"ipAddress":"\K[^"]+')
  ruleid=$(echo "$alert" | grep -oP '"rule":{"id":"\K[0-9]+')
  
 # Fallbacks
 username=${username:-"Unknown"}
 srcip=${srcip:-"Unknown"}
 ruleid=${ruleid:-"Unknown"}
  
 # Discord webhook
 WEBHOOK_URL="https://discord.com/api/webhooks/xxxxxxxxx/yyyyyyyyyyyyyy"
  
 # Compose message
 json_payload=$(cat <<EOF
 {
   "content": "🚨 **Wazuh Alert** 🚨\n**Rule ID:** $ruleid\n**User:** $username\n**Source IP:** $srcip"
 }
 EOF
 )
  
 # Send to Discord
 curl -X POST -H "Content-Type: application/json" -d "$json_payload" "$WEBHOOK_URL"
```
modify permissions:

```bash
	chmod 750 /var/ossec/active-response/bin/discord_notify.sh
	chown root:wazuh /var/ossec/active-response/bin/discord_notify.sh
```

Register the Script in ossec.conf

```bash
 sudo nano /var/ossec/etc/ossec.conf
```

Add the following under the <command> section:

```bash
 <command>
   <name>discord-notify</name>
   <executable>discord_notify.sh</executable>
   <expect>user</expect>
   <timeout_allowed>no</timeout_allowed>
 </command>
```

Then add the <active-response> block:

```bash
 <active-response>
   <command>discord-notify</command>
   <location>all</location>
   <rules_id>60204</rules_id> <!-- Brute-force rule -->
 </active-response>
```
 
Restart Wazuh Manager

```bash
 sudo systemctl restart wazuh-manager
```

Test by running the brute force step again 
