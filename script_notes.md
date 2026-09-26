# Normalized events script
## 1. Restart Interface loopback
### On Router or L3 SW
```
interface loopback0
sh
no sh
```
### Normalized event:
- {"@timestamp": "2026-09-23T21:20:14.559Z", "ecs": {"version": "9.3.0"}, "log": {"level": "notice"}, "event": {"id": "c0c326bc6a6b4f95", "kind": "event", "category": ["network"], "type": ["info"], "sequence": 42, "severity": 5, "created": "2026-09-23T21:20:14.559Z", "ingested": "2026-09-23T21:20:14.584988+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<141>42: *Sep 23 21:20:14.559: %LINEPROTO-5-UPDOWN: Line protocol on Interface Loopback0, changed state to up"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.100.44"}, "message": "Line protocol on Interface Loopback0, changed state to up", "parser": {"version": "1.3.0", "name": "cisco_ios"}}

## 2. Interfaces type mismatch
### interfaces between Router and L2 SW
```
It's created automatically
but, if you want to fix this issue:
intereface e0/0
duplex full
end
```
### Normalized event:
- {"@timestamp": "2026-09-23T21:23:52.887Z", "ecs": {"version": "9.3.0"}, "log": {"level": "warning"}, "event": {"id": "4a23e77bb8e4c65c", "kind": "event", "category": ["network"], "type": ["info"], "sequence": 44, "severity": 4, "created": "2026-09-23T21:23:52.887Z", "ingested": "2026-09-23T21:23:52.509209+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<140>44: *Sep 23 21:23:52.887: %CDP-4-DUPLEX_MISMATCH: duplex mismatch discovered on Ethernet0/0 (not full duplex), with R1 FastEthernet1/0 (full duplex)."}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.100.44"}, "message": "duplex mismatch discovered on Ethernet0/0 (not full duplex), with R1 FastEthernet1/0 (full duplex).", "parser": {"version": "1.3.0", "name": "cisco_ios"}}

## 3. Conf t mode
### conf t mode from Router or SW
```
It's created automatically when done configuring something and then exit from conf t
end OR exit to enable mode
```
### Normalized event:
- {"@timestamp": "2026-09-23T21:28:37.267Z", "ecs": {"version": "9.3.0"}, "log": {"level": "notice"}, "event": {"id": "414d99c493d4b4e9", "kind": "event", "category": ["network"], "type": ["info"], "sequence": 51, "severity": 5, "created": "2026-09-23T21:28:37.267Z", "ingested": "2026-09-23T21:28:37.402828+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<141>51: *Sep 23 21:28:37.267: %SYS-5-CONFIG_I: Configured from console by console"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.100.44"}, "message": "Configured from console by console", "parser": {"version": "1.3.0", "name": "cisco_ios"}}

## 4. ICMP packet flooding (DoS attack)
### command from linux server sends to windows server passing through Router and L3 SW
```
sudo ping -f -c 500 192.168.177.100
```
### Normalized event:
- {"@timestamp": "2026-09-24T03:30:32.659Z", "ecs": {"version": "9.3.0"}, "log": {"level": "info"}, "event": {"id": "b41199533a929494", "kind": "event", "category": ["intrusion_detection"], "type": ["alert"], "sequence": 171, "severity": 6, "created": "2026-09-24T03:30:32.659Z", "ingested": "2026-09-24T03:30:33.174692+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<142>171: *Sep 24 03:30:32.659: %SEC-6-IPACCESSLOGDP: list log-attacks permitted icmp 192.168.141.100 (Ethernet0/0 ca01.0971.001c) -> 192.168.177.100 (0/0), 499 packets"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.141.100"}, "message": "list log-attacks permitted icmp 192.168.141.100 (Ethernet0/0 ca01.0971.001c) -> 192.168.177.100 (0/0), 499 packets", "parser": {"version": "1.3.0", "name": "cisco_ios"}, "destination": {"ip": "192.168.177.100"}, "network": {"transport": "icmp"}}

## 5. TCP SYN Port Scan (Reconnaissance): Attacker mapping out open ports and vulnerabilities on the Windows Server
### command from linux server sends to windows server passing through Router and L3 SW
```
Original: sudo dnf install nmap -y / sudo nmap -sS -p 21,22,80,443,3389 192.168.177.100 
Worked: python3 -c "import socket; [socket.socket().connect_ex(('192.168.177.100', p)) for p in [21, 22, 80, 443, 3389]]"
```
### Normalized event:
- {"@timestamp": "2026-09-24T03:37:08.259Z", "ecs": {"version": "9.3.0"}, "log": {"level": "info"}, "event": {"id": "eb477af65077ea7d", "kind": "event", "category": ["intrusion_detection"], "type": ["alert"], "sequence": 172, "severity": 6, "created": "2026-09-24T03:37:08.259Z", "ingested": "2026-09-24T03:37:08.698617+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<142>172: *Sep 24 03:37:08.259: %SEC-6-IPACCESSLOGP: list log-attacks permitted tcp 192.168.141.100(0) (Ethernet0/0 ca01.0971.001c) -> 192.168.177.100(0), 1 packet"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.141.100(0)"}, "message": "list log-attacks permitted tcp 192.168.141.100(0) (Ethernet0/0 ca01.0971.001c) -> 192.168.177.100(0), 1 packet", "parser": {"version": "1.3.0", "name": "cisco_ios"}, "destination": {"ip": "192.168.177.100(0),"}, "network": {"transport": "tcp"}}

## 6. Network Infrastructure Brute Force (Cisco Authentication): Attacker attempting to breach the network perimeter by guessing credentials on the router's management interfaces
### Linux terminal use router's SSH or Telnet port with invalid credentials
```
IOU1: hostname IOU1
ip domain-name gns3.lab
crypto key generate rsa modulus 2048
username admin secret adminpass
line vty 0 4
login local
transport input all
exit
login block-for 60 attempts 2 within 30
login on-failure log
end

Linux Original: ssh fakeuser@192.168.177.100
Worked: 
python3 -c "
import socket, time
for _ in range(4):
    try:
        s = socket.socket()
        s.connect(('192.168.177.1', 23))
        time.sleep(0.5)
        s.send(b'fakeuser\r\n')
        time.sleep(0.5)
        s.send(b'badpass\r\n')
        time.sleep(0.5)
        s.close()
    except Exception:
        pass
"
```
### Normalized event:
- {"@timestamp": "2026-09-24T18:44:15.055Z", "ecs": {"version": "9.3.0"}, "log": {"level": "warning"}, "event": {"id": "d1ce50b5051e50ed", "kind": "event", "category": ["authentication"], "type": ["denied"], "sequence": 108, "severity": 4, "created": "2026-09-24T18:44:15.055Z", "ingested": "2026-09-24T18:44:15.820944+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<140>108: *Sep 24 18:44:15.055: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: fakeuser] [Source: 192.168.141.100] [localport: 23] [Reason: Login Authentication Failed - BadUser] at 18:44:15 UTC Thu Sep 24 2026"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.141.100"}, "message": "Login failed [user: fakeuser] [Source: 192.168.141.100] [localport: 23] [Reason: Login Authentication Failed - BadUser] at 18:44:15 UTC Thu Sep 24 2026", "parser": {"version": "1.3.0", "name": "cisco_ios"}, "user": {"name": "fakeuser"}}
- {"@timestamp": "2026-09-24T18:44:16.583Z", "ecs": {"version": "9.3.0"}, "log": {"level": "warning"}, "event": {"id": "117d9744963f99ed", "kind": "event", "category": ["authentication"], "type": ["denied"], "sequence": 109, "severity": 4, "created": "2026-09-24T18:44:16.583Z", "ingested": "2026-09-24T18:44:17.344128+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<140>109: *Sep 24 18:44:16.583: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: fakeuser] [Source: 192.168.141.100] [localport: 23] [Reason: Login Authentication Failed - BadUser] at 18:44:16 UTC Thu Sep 24 2026"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.141.100"}, "message": "Login failed [user: fakeuser] [Source: 192.168.141.100] [localport: 23] [Reason: Login Authentication Failed - BadUser] at 18:44:16 UTC Thu Sep 24 2026", "parser": {"version": "1.3.0", "name": "cisco_ios"}, "user": {"name": "fakeuser"}}
- {"@timestamp": "2026-09-24T18:44:18.103Z", "ecs": {"version": "9.3.0"}, "log": {"level": "warning"}, "event": {"id": "508331b8f59b9765", "kind": "event", "category": ["authentication"], "type": ["denied"], "sequence": 110, "severity": 4, "created": "2026-09-24T18:44:18.103Z", "ingested": "2026-09-24T18:44:17.849392+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<140>110: *Sep 24 18:44:18.103: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: fakeuser] [Source: 192.168.141.100] [localport: 23] [Reason: Login Authentication Failed - BadUser] at 18:44:18 UTC Thu Sep 24 2026"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.141.100"}, "message": "Login failed [user: fakeuser] [Source: 192.168.141.100] [localport: 23] [Reason: Login Authentication Failed - BadUser] at 18:44:18 UTC Thu Sep 24 2026", "parser": {"version": "1.3.0", "name": "cisco_ios"}, "user": {"name": "fakeuser"}}
- {"@timestamp": "2026-09-24T18:44:18.103Z", "ecs": {"version": "9.3.0"}, "log": {"level": "alert"}, "event": {"id": "3b7db066d07cd016", "kind": "event", "category": ["network"], "type": ["info"], "sequence": 111, "severity": 1, "created": "2026-09-24T18:44:18.103Z", "ingested": "2026-09-24T18:44:18.836789+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<137>111: *Sep 24 18:44:18.103: %SEC_LOGIN-1-QUIET_MODE_ON: Still timeleft for watching failures is 1 secs, [user: fakeuser] [Source: 192.168.141.100] [localport: 23] [Reason: Login Authentication Failed - BadUser] [ACL: sl_def_acl] at 18:44:18 UTC Thu Sep 24 2026"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.100.44"}, "message": "Still timeleft for watching failures is 1 secs, [user: fakeuser] [Source: 192.168.141.100] [localport: 23] [Reason: Login Authentication Failed - BadUser] [ACL: sl_def_acl] at 18:44:18 UTC Thu Sep 24 2026", "parser": {"version": "1.3.0", "name": "cisco_ios"}}
- {"@timestamp": "2026-09-24T18:44:19.615Z", "ecs": {"version": "9.3.0"}, "log": {"level": "warning"}, "event": {"id": "df0d77d99ffaa337", "kind": "event", "category": ["authentication"], "type": ["denied"], "sequence": 112, "severity": 4, "created": "2026-09-24T18:44:19.615Z", "ingested": "2026-09-24T18:44:19.378727+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<140>112: *Sep 24 18:44:19.615: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: fakeuser] [Source: 192.168.141.100] [localport: 23] [Reason: Login Authentication Failed - BadUser] at 18:44:19 UTC Thu Sep 24 2026"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.141.100"}, "message": "Login failed [user: fakeuser] [Source: 192.168.141.100] [localport: 23] [Reason: Login Authentication Failed - BadUser] at 18:44:19 UTC Thu Sep 24 2026", "parser": {"version": "1.3.0", "name": "cisco_ios"}, "user": {"name": "fakeuser"}}
- {"@timestamp": "2026-09-24T18:44:19.615Z", "ecs": {"version": "9.3.0"}, "log": {"level": "alert"}, "event": {"id": "1c8eb54fd4c84ff9", "kind": "event", "category": ["network"], "type": ["info"], "sequence": 113, "severity": 1, "created": "2026-09-24T18:44:19.615Z", "ingested": "2026-09-24T18:44:20.354147+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<137>113: *Sep 24 18:44:19.615: %SEC_LOGIN-1-QUIET_MODE_ON: Still timeleft for watching failures is 0 secs, [user: fakeuser] [Source: 192.168.141.100] [localport: 23] [Reason: Login Authentication Failed - BadUser] [ACL: sl_def_acl] at 18:44:19 UTC Thu Sep 24 2026"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.100.44"}, "message": "Still timeleft for watching failures is 0 secs, [user: fakeuser] [Source: 192.168.141.100] [localport: 23] [Reason: Login Authentication Failed - BadUser] [ACL: sl_def_acl] at 18:44:19 UTC Thu Sep 24 2026", "parser": {"version": "1.3.0", "name": "cisco_ios"}}


## 7. Malicious Insider & Privilege Escalation (Linux Logs): Insider threat attempting unauthorized privilege elevation on the attacker node itself.
### All work on Linux terminal only
```
su - root -c "cat /etc/shadow"
Or
sudo cat /etc/shadow
```
### Normalized event:
- {"@timestamp": "2026-09-24T22:54:25.000Z", "ecs": {"version": "9.3.0"}, "log": {"level": "notice"}, "event": {"id": "831edf3e1e367f6e", "kind": "event", "category": ["system"], "type": ["info"], "severity": 5, "created": "2026-09-24T22:54:25.000Z", "ingested": "2026-09-24T19:54:24.349510+00:00", "dataset": "linux.unix_chkpwd", "module": "rsyslog", "original": "<85>Sep 24 22:54:25 localhost unix_chkpwd[2552]: password check failed for user (lobnaahmed)"}, "host": {"name": "localhost", "ip": "192.168.141.100", "os": {"family": "linux"}}, "source": {"ip": "192.168.141.100"}, "process": {"name": "unix_chkpwd"}, "message": "password check failed for user (lobnaahmed)", "parser": {"version": "1.3.0", "name": "linux_rsyslog"}}
- {"@timestamp": "2026-09-24T22:54:25.000Z", "ecs": {"version": "9.3.0"}, "log": {"level": "notice"}, "event": {"id": "69aa31f2f8dd442b", "kind": "event", "category": ["process", "privilege"], "type": ["info"], "severity": 5, "created": "2026-09-24T22:54:25.000Z", "ingested": "2026-09-24T19:54:24.375368+00:00", "dataset": "linux.sudo", "module": "rsyslog", "original": "<85>Sep 24 22:54:25 localhost sudo[2543]: pam_unix(sudo:auth): authentication failure; logname=lobnaahmed uid=1000 euid=0 tty=/dev/tty1 ruser=lobnaahmed rhost=  user=lobnaahmed"}, "host": {"name": "localhost", "ip": "192.168.141.100", "os": {"family": "linux"}}, "source": {"ip": "192.168.141.100"}, "process": {"name": "sudo"}, "message": "pam_unix(sudo:auth): authentication failure; logname=lobnaahmed uid=1000 euid=0 tty=/dev/tty1 ruser=lobnaahmed rhost=  user=lobnaahmed", "parser": {"version": "1.3.0", "name": "linux_rsyslog"}}
- {"@timestamp": "2026-09-24T22:54:30.000Z", "ecs": {"version": "9.3.0"}, "log": {"level": "notice"}, "event": {"id": "249ff73398c7389a", "kind": "event", "category": ["system"], "type": ["info"], "severity": 5, "created": "2026-09-24T22:54:30.000Z", "ingested": "2026-09-24T19:54:28.895189+00:00", "dataset": "linux.unix_chkpwd", "module": "rsyslog", "original": "<85>Sep 24 22:54:30 localhost unix_chkpwd[2554]: password check failed for user (lobnaahmed)"}, "host": {"name": "localhost", "ip": "192.168.141.100", "os": {"family": "linux"}}, "source": {"ip": "192.168.141.100"}, "process": {"name": "unix_chkpwd"}, "message": "password check failed for user (lobnaahmed)", "parser": {"version": "1.3.0", "name": "linux_rsyslog"}}
- {"@timestamp": "2026-09-24T22:54:45.000Z", "ecs": {"version": "9.3.0"}, "log": {"level": "notice"}, "event": {"id": "8bb012c5cb25d4a7", "kind": "event", "category": ["process", "privilege"], "type": ["info"], "severity": 5, "created": "2026-09-24T22:54:45.000Z", "ingested": "2026-09-24T19:54:44.264209+00:00", "dataset": "linux.sudo", "module": "rsyslog", "original": "<85>Sep 24 22:54:45 localhost sudo[2543]: lobnaahmed : TTY=tty1 ; PWD=/home/lobnaahmed ; USER=root ; COMMAND=/bin/cat /etc/shadow", "action": "privilege_elevation", "outcome": "success"}, "host": {"name": "localhost", "ip": "192.168.141.100", "os": {"family": "linux"}}, "source": {"ip": "192.168.141.100"}, "process": {"name": "sudo", "command_line": "/bin/cat /etc/shadow"}, "message": "lobnaahmed : TTY=tty1 ; PWD=/home/lobnaahmed ; USER=root ; COMMAND=/bin/cat /etc/shadow", "parser": {"version": "1.3.0", "name": "linux_rsyslog"}, "user": {"name": "lobnaahmed", "target": {"name": "root"}}}
- {"@timestamp": "2026-09-24T22:54:45.000Z", "ecs": {"version": "9.3.0"}, "log": {"level": "info"}, "event": {"id": "ed2a20f7258dd88c", "kind": "event", "category": ["process", "privilege"], "type": ["info"], "severity": 6, "created": "2026-09-24T22:54:45.000Z", "ingested": "2026-09-24T19:54:44.265741+00:00", "dataset": "linux.sudo", "module": "rsyslog", "original": "<86>Sep 24 22:54:45 localhost sudo[2543]: pam_unix(sudo:session): session opened for user root(uid=0) by lobnaahmed(uid=1000)"}, "host": {"name": "localhost", "ip": "192.168.141.100", "os": {"family": "linux"}}, "source": {"ip": "192.168.141.100"}, "process": {"name": "sudo"}, "message": "pam_unix(sudo:session): session opened for user root(uid=0) by lobnaahmed(uid=1000)", "parser": {"version": "1.3.0", "name": "linux_rsyslog"}}
- {"@timestamp": "2026-09-24T22:54:45.000Z", "ecs": {"version": "9.3.0"}, "log": {"level": "info"}, "event": {"id": "9dc6bc28180b229e", "kind": "event", "category": ["process", "privilege"], "type": ["info"], "severity": 6, "created": "2026-09-24T22:54:45.000Z", "ingested": "2026-09-24T19:54:44.267432+00:00", "dataset": "linux.sudo", "module": "rsyslog", "original": "<86>Sep 24 22:54:45 localhost sudo[2543]: pam_unix(sudo:session): session closed for user root"}, "host": {"name": "localhost", "ip": "192.168.141.100", "os": {"family": "linux"}}, "source": {"ip": "192.168.141.100"}, "process": {"name": "sudo"}, "message": "pam_unix(sudo:session): session closed for user root", "parser": {"version": "1.3.0", "name": "linux_rsyslog"}}


## 8. Rogue Account Creation (Windows Event Logs)
### PowerShell as adminstrator on windows server
```
net user SysAdmin BackdoorPass123! /add
net localgroup Administrators SysAdmin /add
```
### Normalized event:
- {"@timestamp": "2026-09-24T23:10:09.691726+00:00", "ecs": {"version": "9.3.0"}, "log": {"level": "info"}, "event": {"id": "07cc86bbcbce941c", "kind": "event", "category": ["iam"], "type": ["group", "change"], "code": "4728", "severity": 6, "created": "2026-09-24T23:10:09.691726+00:00", "ingested": "2026-09-24T23:10:09.691726+00:00", "dataset": "windows.security", "module": "python-udp-collector", "original": "<14>Sep 24 16:10:07 WIN-3CQEUENQDJ9 MSWinEventLog\t1\tSecurity\t37\tThu Sep 24 16:10:07 2026\t4728\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tWIN-3CQEUENQDJ9\tSecurity Group Management\t\tA member was added to a security-enabled global group.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    Member:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  -    Group:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-513   Group Name:  None   Group Domain:  WIN-3CQEUENQDJ9    Additional Information:   Privileges:  -\t4199", "action": "member-added-to-local-group"}, "host": {"name": "WIN-3CQEUENQDJ9", "ip": "192.168.177.100", "os": {"family": "windows"}}, "source": {"ip": "192.168.177.100"}, "message": "Group Management\t\tA member was added to a security-enabled global group.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    Member:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  -    Group:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-513   Group Name:  None   Group Domain:  WIN-3CQEUENQDJ9    Additional Information:   Privileges:  -\t4199", "parser": {"version": "1.3.0", "name": "windows_powershell"}, "group": {"name": "None"}}
- {"@timestamp": "2026-09-24T23:10:09.730986+00:00", "ecs": {"version": "9.3.0"}, "log": {"level": "info"}, "event": {"id": "626a988324116526", "kind": "event", "category": ["iam"], "type": ["creation"], "code": "4720", "severity": 6, "created": "2026-09-24T23:10:09.730986+00:00", "ingested": "2026-09-24T23:10:09.730986+00:00", "dataset": "windows.security", "module": "python-udp-collector", "original": "<14>Sep 24 16:10:07 WIN-3CQEUENQDJ9 MSWinEventLog\t1\tSecurity\t38\tThu Sep 24 16:10:07 2026\t4720\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tWIN-3CQEUENQDJ9\tUser Account Management\t\tA user account was created.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    New Account:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  ServiceAcc   Account Domain:  WIN-3CQEUENQDJ9    Attributes:   SAM Account Name: ServiceAcc   Display Name:  <value not set>   User Principal Name: -   Home Directory:  <value not set>   Home Drive:  <value not set>   Script Path:  <value not set>   Profile Path:  <value not set>   User Workstations: <value not set>   Password Last Set: <never>   Account Expires:  <never>   Primary Group ID: 513   Allowed To Delegate To: -   Old UAC Value:  0x0   New UAC Value:  0x15   User Account Control:     Account Disabled    'Password Not Required' - Enabled    'Normal Account' - Enabled   User Parameters: <value not set>   SID History:  -   Logon Hours:  All    Additional Information:   Privileges  -\t4200", "action": "user-account-created"}, "host": {"name": "WIN-3CQEUENQDJ9", "ip": "192.168.177.100", "os": {"family": "windows"}}, "source": {"ip": "192.168.177.100"}, "message": "Account Management\t\tA user account was created.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    New Account:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  ServiceAcc   Account Domain:  WIN-3CQEUENQDJ9    Attributes:   SAM Account Name: ServiceAcc   Display Name:  <value not set>   User Principal Name: -   Home Directory:  <value not set>   Home Drive:  <value not set>   Script Path:  <value not set>   Profile Path:  <value not set>   User Workstations: <value not set>   Password Last Set: <never>   Account Expires:  <never>   Primary Group ID: 513   Allowed To Delegate To: -   Old UAC Value:  0x0   New UAC Value:  0x15   User Account Control:     Account Disabled    'Password Not Required' - Enabled    'Normal Account' - Enabled   User Parameters: <value not set>   SID History:  -   Logon Hours:  All    Additional Information:   Privileges  -\t4200", "parser": {"version": "1.3.0", "name": "windows_powershell"}, "user": {"name": "ServiceAcc"}}
- {"@timestamp": "2026-09-24T23:10:09.732811+00:00", "ecs": {"version": "9.3.0"}, "log": {"level": "info"}, "event": {"id": "e0f76a9d9a8ad734", "kind": "event", "category": ["iam"], "type": ["change"], "code": "4722", "severity": 6, "created": "2026-09-24T23:10:09.732811+00:00", "ingested": "2026-09-24T23:10:09.732811+00:00", "dataset": "windows.security", "module": "python-udp-collector", "original": "<14>Sep 24 16:10:07 WIN-3CQEUENQDJ9 MSWinEventLog\t1\tSecurity\t39\tThu Sep 24 16:10:07 2026\t4722\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tWIN-3CQEUENQDJ9\tUser Account Management\t\tA user account was enabled.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    Target Account:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  ServiceAcc   Account Domain:  WIN-3CQEUENQDJ9\t4201", "action": "user-account-enabled"}, "host": {"name": "WIN-3CQEUENQDJ9", "ip": "192.168.177.100", "os": {"family": "windows"}}, "source": {"ip": "192.168.177.100"}, "message": "Account Management\t\tA user account was enabled.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    Target Account:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  ServiceAcc   Account Domain:  WIN-3CQEUENQDJ9\t4201", "parser": {"version": "1.3.0", "name": "windows_powershell"}, "user": {"name": "ServiceAcc"}}
- {"@timestamp": "2026-09-24T23:10:09.734220+00:00", "ecs": {"version": "9.3.0"}, "log": {"level": "info"}, "event": {"id": "1501c749d5d50e83", "kind": "event", "category": ["iam"], "type": ["change"], "code": "4738", "severity": 6, "created": "2026-09-24T23:10:09.734220+00:00", "ingested": "2026-09-24T23:10:09.734220+00:00", "dataset": "windows.security", "module": "python-udp-collector", "original": "<14>Sep 24 16:10:07 WIN-3CQEUENQDJ9 MSWinEventLog\t1\tSecurity\t40\tThu Sep 24 16:10:07 2026\t4738\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tWIN-3CQEUENQDJ9\tUser Account Management\t\tA user account was changed.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    Target Account:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  ServiceAcc   Account Domain:  WIN-3CQEUENQDJ9    Changed Attributes:   SAM Account Name: ServiceAcc   Display Name:  <value not set>   User Principal Name: -   Home Directory:  <value not set>   Home Drive:  <value not set>   Script Path:  <value not set>   Profile Path:  <value not set>   User Workstations: <value not set>   Password Last Set: 9/24/2026 4:10:07 PM   Account Expires:  <never>   Primary Group ID: 513   AllowedToDelegateTo: -   Old UAC Value:  0x15   New UAC Value:  0x10   User Account Control:     Account Enabled    'Password Not Required' - Disabled   User Parameters: -   SID History:  -   Logon Hours:  All    Additional Information:   Privileges:  -\t4202"}, "host": {"name": "WIN-3CQEUENQDJ9", "ip": "192.168.177.100", "os": {"family": "windows"}}, "source": {"ip": "192.168.177.100"}, "message": "Account Management\t\tA user account was changed.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    Target Account:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  ServiceAcc   Account Domain:  WIN-3CQEUENQDJ9    Changed Attributes:   SAM Account Name: ServiceAcc   Display Name:  <value not set>   User Principal Name: -   Home Directory:  <value not set>   Home Drive:  <value not set>   Script Path:  <value not set>   Profile Path:  <value not set>   User Workstations: <value not set>   Password Last Set: 9/24/2026 4:10:07 PM   Account Expires:  <never>   Primary Group ID: 513   AllowedToDelegateTo: -   Old UAC Value:  0x15   New UAC Value:  0x10   User Account Control:     Account Enabled    'Password Not Required' - Disabled   User Parameters: -   SID History:  -   Logon Hours:  All    Additional Information:   Privileges:  -\t4202", "parser": {"version": "1.3.0", "name": "windows_powershell"}, "user": {"name": "ServiceAcc"}}
- {"@timestamp": "2026-09-24T23:10:09.735735+00:00", "ecs": {"version": "9.3.0"}, "log": {"level": "info"}, "event": {"id": "6896dc60f49ba5b9", "kind": "event", "category": ["iam"], "type": ["change"], "code": "4724", "severity": 6, "created": "2026-09-24T23:10:09.735735+00:00", "ingested": "2026-09-24T23:10:09.735735+00:00", "dataset": "windows.security", "module": "python-udp-collector", "original": "<14>Sep 24 16:10:07 WIN-3CQEUENQDJ9 MSWinEventLog\t1\tSecurity\t41\tThu Sep 24 16:10:07 2026\t4724\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tWIN-3CQEUENQDJ9\tUser Account Management\t\tAn attempt was made to reset an account's password.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    Target Account:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  ServiceAcc   Account Domain:  WIN-3CQEUENQDJ9\t4203"}, "host": {"name": "WIN-3CQEUENQDJ9", "ip": "192.168.177.100", "os": {"family": "windows"}}, "source": {"ip": "192.168.177.100"}, "message": "Account Management\t\tAn attempt was made to reset an account's password.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    Target Account:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  ServiceAcc   Account Domain:  WIN-3CQEUENQDJ9\t4203", "parser": {"version": "1.3.0", "name": "windows_powershell"}, "user": {"name": "ServiceAcc"}}
- {"@timestamp": "2026-09-24T23:10:09.737116+00:00", "ecs": {"version": "9.3.0"}, "log": {"level": "info"}, "event": {"id": "efe6035b1a7d4116", "kind": "event", "category": ["iam"], "type": ["group", "change"], "code": "4732", "severity": 6, "created": "2026-09-24T23:10:09.737116+00:00", "ingested": "2026-09-24T23:10:09.737116+00:00", "dataset": "windows.security", "module": "python-udp-collector", "original": "<14>Sep 24 16:10:07 WIN-3CQEUENQDJ9 MSWinEventLog\t1\tSecurity\t42\tThu Sep 24 16:10:07 2026\t4732\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tWIN-3CQEUENQDJ9\tSecurity Group Management\t\tA member was added to a security-enabled local group.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    Member:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  -    Group:   Security ID:  S-1-5-32-545   Group Name:  Users   Group Domain:  Builtin    Additional Information:   Privileges:  -\t4204", "action": "member-added-to-local-group"}, "host": {"name": "WIN-3CQEUENQDJ9", "ip": "192.168.177.100", "os": {"family": "windows"}}, "source": {"ip": "192.168.177.100"}, "message": "Group Management\t\tA member was added to a security-enabled local group.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    Member:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  -    Group:   Security ID:  S-1-5-32-545   Group Name:  Users   Group Domain:  Builtin    Additional Information:   Privileges:  -\t4204", "parser": {"version": "1.3.0", "name": "windows_powershell"}, "group": {"name": "Users"}}
- {"@timestamp": "2026-09-24T23:10:24.915424+00:00", "ecs": {"version": "9.3.0"}, "log": {"level": "info"}, "event": {"id": "415814c1410dd4b7", "kind": "event", "category": ["iam"], "type": ["group", "change"], "code": "4732", "severity": 6, "created": "2026-09-24T23:10:24.915424+00:00", "ingested": "2026-09-24T23:10:24.915424+00:00", "dataset": "windows.security", "module": "python-udp-collector", "original": "<14>Sep 24 16:10:23 WIN-3CQEUENQDJ9 MSWinEventLog\t1\tSecurity\t43\tThu Sep 24 16:10:23 2026\t4732\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tWIN-3CQEUENQDJ9\tSecurity Group Management\t\tA member was added to a security-enabled local group.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    Member:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  -    Group:   Security ID:  S-1-5-32-544   Group Name:  Administrators   Group Domain:  Builtin    Additional Information:   Privileges:  -\t4205", "action": "member-added-to-local-group"}, "host": {"name": "WIN-3CQEUENQDJ9", "ip": "192.168.177.100", "os": {"family": "windows"}}, "source": {"ip": "192.168.177.100"}, "message": "Group Management\t\tA member was added to a security-enabled local group.    Subject:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-500   Account Name:  Administrator   Account Domain:  WIN-3CQEUENQDJ9   Logon ID:  0x390F3    Member:   Security ID:  S-1-5-21-614154248-3464031764-2899765364-1006   Account Name:  -    Group:   Security ID:  S-1-5-32-544   Group Name:  Administrators   Group Domain:  Builtin    Additional Information:   Privileges:  -\t4205", "parser": {"version": "1.3.0", "name": "windows_powershell"}, "group": {"name": "Administrators"}}

## 9. HSRP Hijacking (Gateway Takeover Detection)
### Working on Router and L3 SW
```
IOU1:
interface Ethernet0/0
 ip address 10.0.0.2 255.255.255.248
 standby 1 ip 10.0.0.6
 standby 1 priority 105
 standby 1 preempt
end
R1:
interface FastEthernet1/0
 ip address 10.0.0.1 255.255.255.248
 standby 1 ip 10.0.0.6
 standby 1 priority 100
end
R1 attack:
interface FastEthernet1/0
 standby 1 priority 150
 standby 1 preempt
end
```
### Normalized event:
- {"@timestamp": "2026-09-24T23:28:43.691Z", "ecs": {"version": "9.3.0"}, "log": {"level": "notice"}, "event": {"id": "16584d09716f4657", "kind": "event", "category": ["network", "routing"], "type": ["change"], "sequence": 27, "severity": 5, "created": "2026-09-24T23:28:43.691Z", "ingested": "2026-09-24T23:28:41.153747+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<133>27: *Sep 24 23:28:43.691: %HSRP-5-STATECHANGE: FastEthernet1/0 Grp 1 state Standby -> Active"}, "host": {"name": "unknown-cisco-device", "ip": "10.0.0.1"}, "source": {"ip": "10.0.0.1"}, "message": "FastEthernet1/0 Grp 1 state Standby -> Active", "parser": {"version": "1.3.0", "name": "cisco_ios"}}
- {"@timestamp": "2026-09-24T23:28:42.791Z", "ecs": {"version": "9.3.0"}, "log": {"level": "notice"}, "event": {"id": "9cf03d1080b046dd", "kind": "event", "category": ["network", "routing"], "type": ["change"], "sequence": 71, "severity": 5, "created": "2026-09-24T23:28:42.791Z", "ingested": "2026-09-24T23:28:41.622331+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<141>71: *Sep 24 23:28:42.791: %HSRP-5-STATECHANGE: Ethernet0/0 Grp 1 state Active -> Speak"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.100.44"}, "message": "Ethernet0/0 Grp 1 state Active -> Speak", "parser": {"version": "1.3.0", "name": "cisco_ios"}}
- {"@timestamp": "2026-09-24T23:28:54.527Z", "ecs": {"version": "9.3.0"}, "log": {"level": "notice"}, "event": {"id": "343ffff89539b3c5", "kind": "event", "category": ["network", "routing"], "type": ["change"], "sequence": 73, "severity": 5, "created": "2026-09-24T23:28:54.527Z", "ingested": "2026-09-24T23:28:53.500104+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<141>73: *Sep 24 23:28:54.527: %HSRP-5-STATECHANGE: Ethernet0/0 Grp 1 state Speak -> Standby"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.100.44"}, "message": "Ethernet0/0 Grp 1 state Speak -> Standby", "parser": {"version": "1.3.0", "name": "cisco_ios"}}

## 10. RIPv2 Rogue Route Injection: Attacker attempts to inject rogue routes into the network using RIPv2, but lacks the MD5 hash
### Working on Router and L3 SW
```
L3 SW:
key chain RIP_AUTH
 key 1
 key-string SOC_Secret_123
 exit
exit
interface Ethernet0/0
 ip rip authentication mode md5
 ip rip authentication key-chain RIP_AUTH
 exit
router rip
 version 2
 network 10.0.0.0
 no auto-summary
 exit
logging trap debugging
end
debug ip rip events

R1 attacker:
router rip
 version 2
 network 10.0.0.0
 no auto-summary
 end
 interface FastEthernet1/0
shutdown
no shutdown
```
### Normalized event:
- {"@timestamp": "2026-09-24T23:47:40.219Z", "ecs": {"version": "9.3.0"}, "log": {"level": "info"}, "event": {"id": "28233618acc31921", "kind": "event", "category": ["network", "routing"], "type": ["info"], "action": "routing-update", "severity": 6, "created": "2026-09-24T23:47:40.219Z", "ingested": "2026-09-24T23:47:39.256143+00:00", "dataset": "gns3.debug", "module": "python-udp-collector", "original": "<143>139: *Sep 24 23:47:40.219: RIP: sending v2 update to 224.0.0.9 via Ethernet0/0 (10.0.0.2) - suppressing null update"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "192.168.100.44"}, "message": "RIP: sending v2 update to 224.0.0.9 via Ethernet0/0 (10.0.0.2) - suppressing null update", "parser": {"version": "1.3.0", "name": "cisco_debug"}}
- {"@timestamp": "2026-09-24T23:53:15.891Z", "ecs": {"version": "9.3.0"}, "log": {"level": "warning"}, "event": {"id": "40148944acebc179", "kind": "event", "category": ["network", "intrusion_detection"], "type": ["denied"], "action": "routing-auth-failure", "severity": 4, "created": "2026-09-24T23:53:15.891Z", "ingested": "2026-09-24T23:53:15.001734+00:00", "dataset": "gns3.debug", "module": "python-udp-collector", "original": "<143>166: *Sep 24 23:53:15.891: RIP: ignored v2 packet from 10.0.0.1 (invalid authentication)"}, "host": {"name": "unknown-cisco-device", "ip": "192.168.100.44"}, "source": {"ip": "10.0.0.1"}, "message": "RIP: ignored v2 packet from 10.0.0.1 (invalid authentication)", "parser": {"version": "1.3.0", "name": "cisco_debug"}}
- {"@timestamp": "2026-09-24T23:53:18.747Z", "ecs": {"version": "9.3.0"}, "log": {"level": "error"}, "event": {"id": "51a4547f35ccb685", "kind": "event", "category": ["network"], "type": ["info"], "sequence": 38, "severity": 3, "created": "2026-09-24T23:53:18.747Z", "ingested": "2026-09-24T23:53:16.509490+00:00", "dataset": "gns3.syslog", "module": "python-udp-collector", "original": "<131>38: *Sep 24 23:53:18.747: %LINK-3-UPDOWN: Interface FastEthernet1/0, changed state to up"}, "host": {"name": "unknown-cisco-device", "ip": "10.0.0.1"}, "source": {"ip": "10.0.0.1"}, "message": "Interface FastEthernet1/0, changed state to up", "parser": {"version": "1.3.0", "name": "cisco_ios"}}


# Load Generator Script 
## 100 EPS for 300s
```
run logic.py
run load_generator.py
results -> load_generator_sent_log.jsonl
run measure_latency.py
Sent: 27545, Matched/Indexed: 27545, Lost: 0 (0.00%)
Latency (ms) — min: 0.1, median: 0.2, p95: 0.2, max: 403.6
```
## 300 EPS for 300s
```
Sent: 73959, Matched/Indexed: 73927, Lost: 32 (0.04%)
Latency (ms) — min: 0.1, median: 0.1, p95: 78.8, max: 1923.3
```
