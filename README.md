#Home lab SOC Simulation Proxmox + Windows server + Kali + Wazuh + Discord channel notifciations

Proxomx
Download Proxmox 8 iOS, use Rufus to burn it to usb, and install it on a machine.
Increase Proxmox Storage:
Datacenter>Storage>Remove LVM-Thin
Click on node (pve)>shell
```bash
1. lvremove /dev/pve/data
2. lvextend -l +100%FREE /dev/pve/root
3. resize2fs /dev/pve/root 
```
Datacenter > storage > select root > edit > content > add all
Change enterprise license for proxmox updates:
```bash
1. nano /etc/apt/sources.list.d/pve-enterprise.list
```
Comment out the existing line and add
```bash
1. deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription
```
Edit Ceph (required for proxmox 8+)
```bash
1. nano /etc/apt/sources.list.d/ceph.list
```
Comment out the existing line and add
```bash
1. deb http://download.proxmox.com/debian/ceph-quincy bookworm no-subscription
```
Ctrl + x & ctrl + o save and close, then run updates
```bash
1. apt-get update -y && apt-get upgrade -y
```
Configuring No Subscription Repository in Proxmoxm VE 8.x Part - 6
Windows Server 2025
download Windows server 2025 iso: Windows Server 2025 | Microsoft Evaluation Center
Create a Windows Server VM on Proxmox or Hyper-V (8GB RAM 64GB Storage for Desktop experience)
Update
```bash
 1. $session=new-pssession 10.0.0.2 -Credential (Get-Credential)
 2. copy-item -ToSession $session -Path "F:\IT-F\Security Operations Centre\Scripts" -Recurse -Destination C:\script
 3. Invoke-Command -Session $session -ScriptBlock {
 4.  
 5.     $time = ([datetime]'2023-10-20 20:00:00')
 6.     $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '-ExecutionPolicy bypass -File C:\Script\Install-WindowsUpdate.ps1' 
 7.     $trigger = New-ScheduledTaskTrigger -Once -At $time 
 8.     $principal = New-ScheduledTaskPrincipal  -RunLevel Highest -UserID "NT AUTHORITY\SYSTEM" -LogonType S4U
 9.  
10.     if (! (Get-ScheduledTask -TaskName "Install-WindowsUpdate" -ErrorAction SilentlyContinue))
11.     {
12.         Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "Install-WindowsUpdate"
13.     }
14.     else
15.     {
16.         Set-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "Install-WindowsUpdate"
17.     }
18.  
19.     Get-ScheduledTaskInfo -TaskName Install-WindowsUpdate
20. }
21.  
22. Invoke-Command -Session $session -ScriptBlock {
23.  Start-ScheduledTask -TaskName Install-WindowsUpdate
24. }
25.  
26. Invoke-Command -Session $session -ScriptBlock {
27.  Get-ScheduledTaskInfo -TaskName Install-WindowsUpdate
28. }
```
wait for a restart or
Rename the server to DC01
Promote to Domain Controller
Manage > Add roles and features > Active Directory and Domain Services
 

 
Click on Promote > Add a new forest > root domain: homelab.local
Set the DSRM password and store it somewhere important
During Active Directory setup, a DNS delegation warning appeared, indicating that the authoritative parent zone for the domain homelab.local could not be found. Since this is a standalone lab environment using an internal .local domain, this warning is expected and was safely ignored.
Assign a static IPv4 address to the DC01 network adapter and disable IPv6
 
Click on Next until the end of the wizard > finish
 

Enable Advanced Feature in Active Directory Users
 

Use this script to create fake users:
```bash
 1.  # === CONFIG ===
 2. $domain = "homelab.local"
 3. $defaultPassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
 4. $baseDN = "DC=homelab,DC=local"
 5.  
 6. # === Organizational Units ===
 7. $OUs = @("Homelab-HR", "Homelab-IT", "Homelab-Users", "Homelab-Admins")
 8. foreach ($ou in $OUs) {
 9.     $ouPath = "OU=$ou,$baseDN"
10.     if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$ou)" -SearchBase $baseDN -ErrorAction SilentlyContinue)) {
11.         New-ADOrganizationalUnit -Name $ou -Path $baseDN
12.         Write-Host "Created OU: $ou"
13.     } else {
14.         Write-Host "OU already exists: $ou"
15.     }
16. }
17.  
18. # === Users to Create ===
19. $users = @(
20.     @{First="John"; Last="Doe"; Department="IT"},
21.     @{First="Alice"; Last="Smith"; Department="HR"},
22.     @{First="Bob"; Last="Taylor"; Department="Users"},
23.     @{First="Eve"; Last="Jackson"; Department="Admins"},
24.     @{First="Charlie"; Last="Brown"; Department="IT"},
25.     @{First="Diana"; Last="Prince"; Department="HR"},
26.     @{First="Frank"; Last="Miller"; Department="Users"},
27.     @{First="Grace"; Last="Hopper"; Department="IT"},
28.     @{First="Hank"; Last="Pym"; Department="Admins"},
29.     @{First="Ivy"; Last="Wells"; Department="Users"}
30. )
31.  
32. # === Create Users ===
33. foreach ($user in $users) {
34.     $username = ($user.First + "." + $user.Last).ToLower()
35.     $ouPath = "OU=Homelab-$($user.Department),$baseDN"
36.     $name = "$($user.First) $($user.Last)"
37.  
38.     if (-not (Get-ADUser -Filter { SamAccountName -eq $username } -ErrorAction SilentlyContinue)) {
39.         try {
40.             New-ADUser `
41.                 -Name $name `
42.                 -SamAccountName $username `
43.                 -UserPrincipalName "$username@$domain" `
44.                 -AccountPassword $defaultPassword `
45.                 -Enabled $true `
46.                 -DisplayName $name `
47.                 -GivenName $user.First `
48.                 -Surname $user.Last `
49.                 -Path $ouPath `
50.                 -Department $user.Department `
51.                 -EmailAddress "$username@$domain"
52.  
53.             Write-Host "✅ Created user: $username in $ouPath"
54.         } catch {
55.             Write-Host "❌ Error creating user $username : $_"
56.         }
57.     } else {
58.         Write-Host "⚠️ User $username already exists. Skipping."
59.     }
60. }
61.  #the end
```

Edit group policy
Run ```bash gpmc.msc``` from Run window or PowerShell
Expand your forest → Domains → homelab.local
Right-click Default Domain Policy → Click Edit
Computer Configuration →
  Policies →
    Windows Settings →
      Security Settings →
        Account Policies →
          Password Policy 

Account Lockout policy
 

Join a client computer to the domain:
Set the DNS to be the DC01 IP address (i.e. 10.0.0.2) > join the domain Homelab
 
Login as Homelab\John.doe 
With the domain credential
 

Verify the applied group policy
```bash
1. gpresult /r
```
Wazuh:
Download Ubuntu 22 LTS ISO
```bash
1. sudo apt update && sudo apt upgrade -y
2. #Install Basic dependencies:
3. sudo apt install curl unzip net-tools gnupg apt-transport-https -y
4. curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
5. sudo bash ./wazuh-install.sh -a
```
#Access through browser:
https://10.0.0.80
Login with default:
•	Username: admin
•	Password: admin


Kali
Download Kali iso
Create a vm on hyper v
Enable Kali Enhanced session for Hyper-V
Terminal: 
```bash kali-teaks ``` > virtualization > configure hyper-v enhanced session > logout
Host: 
```bash
1. Set-VM "(YOUR VM NAME HERE)" -EnhancedSessionTransportType HVSocket
```
Installing Hyper-V Enhanced Session Mode (Guest Tools) | Kali Linux Documentation
Phase 1: Brute force John.Doe on DC01
```bash
1. sudo apt update
2. sudo apt install hydra ncrack -y
#cofrim installation
1. hydra -h
2. ncrack -h

#scan rdp port open
1. nmap -p 3389 10.0.0.2/24  

#add word list
1. echo -e '123456\npassword\nqwerty\nwelcome\nPassw0rd\nadmin123\nletmein\n12345678\nPassword!\nP@ssw0rd123!' > mini-rdp.txt

#run the attack
1. hydra -t 1 -V -l john.doe -P mini-rdp.txt rdp://10.0.0.2
•	-t 1 = 1 thread to avoid lockout burst
•	-V = verbose (see each attempt)
•	-P = wordlist (does NOT contain the real password)
```
 
Confirm detection: Go to your Wazuh dashboard → Security Events
•	Event ID: 4625
•	Username: john.doe
•	Source IP: <Kali IP>
Search for Failed Logins (Event ID 4625)
DQL:
```bash
1. data.win.system.eventID:4625
```
Search for Account Lockouts (Event ID 4740)
DQL:
```bash
1. data.win.system.eventID:4740
```
Search for successful login attempts with Kali’s IP
 address:
DQL:
```bash
1. data.win.system.eventID:4624
```
Add Discord channel alerts:
```bash
1. sudo nano /var/ossec/active-response/bin/discord_notify.sh

 1. #!/bin/bash
 2.  
 3. # Read alert input from Wazuh
 4. read alert
 5.  
 6. # Extract details (basic example — you can make this more detailed)
 7. username=$(echo "$alert" | grep -oP '"targetUserName":"\K[^"]+')
 8. srcip=$(echo "$alert" | grep -oP '"ipAddress":"\K[^"]+')
 9. ruleid=$(echo "$alert" | grep -oP '"rule":{"id":"\K[0-9]+')
10.  
11. # Fallbacks
12. username=${username:-"Unknown"}
13. srcip=${srcip:-"Unknown"}
14. ruleid=${ruleid:-"Unknown"}
15.  
16. # Discord webhook
17. WEBHOOK_URL="https://discord.com/api/webhooks/xxxxxxxxx/yyyyyyyyyyyyyy"
18.  
19. # Compose message
20. json_payload=$(cat <<EOF
21. {
22.   "content": "🚨 **Wazuh Alert** 🚨\n**Rule ID:** $ruleid\n**User:** $username\n**Source IP:** $srcip"
23. }
24. EOF
25. )
26.  
27. # Send to Discord
28. curl -X POST -H "Content-Type: application/json" -d "$json_payload" "$WEBHOOK_URL"
```
modify permissions:
```bash
1.	chmod 750 /var/ossec/active-response/bin/discord_notify.sh
2.	chown root:wazuh /var/ossec/active-response/bin/discord_notify.sh
```
Wazuh ui > Management > Administration > Rules
•	18107 → Windows failed login (Event ID 4625)
•	1002 → Linux authentication failed
 

Add a notification to the Discord channel:
Create a Discord Webhook
1.	Go to your Discord server settings.
2.	Select the channel you want alerts in.
3.	Click the ⚙️ settings icon → go to Integrations → Webhooks.
4.	Click "New Webhook", name it (e.g., "Wazuh Alerts"), and copy the Webhook URL (e.g., https://discord.com/api/webhooks/...).
Keep this URL safe.
Create the Wazuh Discord Notification Script
```bash
1. sudo nano /var/ossec/active-response/bin/discord_notify.sh
```
Paste the following:
 ```bash
 1. #!/bin/bash
 2.  
 3. # Read alert input from Wazuh
 4. read alert
 5.  
 6. # Extract details (basic example — you can make this more detailed)
 7. username=$(echo "$alert" | grep -oP '"targetUserName":"\K[^"]+')
 8. srcip=$(echo "$alert" | grep -oP '"ipAddress":"\K[^"]+')
 9. ruleid=$(echo "$alert" | grep -oP '"rule":{"id":"\K[0-9]+')
10.  
11. # Fallbacks
12. username=${username:-"Unknown"}
13. srcip=${srcip:-"Unknown"}
14. ruleid=${ruleid:-"Unknown"}
15.  
16. # Discord webhook
17. WEBHOOK_URL="https://discord.com/api/webhooks/xxxxxxxxx/yyyyyyyyyyyyyy"
18.  
19. # Compose message
20. json_payload=$(cat <<EOF
21. {
22.   "content": "🚨 **Wazuh Alert** 🚨\n**Rule ID:** $ruleid\n**User:** $username\n**Source IP:** $srcip"
23. }
24. EOF
25. )
26.  
27. # Send to Discord
28. curl -X POST -H "Content-Type: application/json" -d "$json_payload" "$WEBHOOK_URL"
```
Register the Script in ossec.conf
```bash
1. sudo nano /var/ossec/etc/ossec.conf
```

Add the following under the <command> section:
```bash
1. <command>
2.   <name>discord-notify</name>
3.   <executable>discord_notify.sh</executable>
4.   <expect>user</expect>
5.   <timeout_allowed>no</timeout_allowed>
6. </command>
```
Then add the <active-response> block:
```bash
1. <active-response>
2.   <command>discord-notify</command>
3.   <location>all</location>
4.   <rules_id>60204</rules_id> <!-- Brute-force rule -->
5. </active-response>
```
 
Restart Wazuh Manager
```bash
1. sudo systemctl restart wazuh-manager
```

Go back to simulating the brute force attack step and run it again to receive Discord messages.
 
