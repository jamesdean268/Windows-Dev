# Windows-Dev
Ansible Playbook to provision my Windows 10 environment

# Setup
## Win-32 OpenSSh Setup
Follow instructions here: https://docs.ansible.com/ansible/latest/user_guide/windows_setup.html#windows-ssh-setup

Use the latest version of OpenSSH from Github:
https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH

Don't forget to set Powershell as the DefaultShell:
https://github.com/PowerShell/Win32-OpenSSH/wiki/DefaultShell
```
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShellCommandOption -Value "/c" -PropertyType String -Force
net stop sshd
net start sshd
```

Ensure sshd is enabled upon start up:

`Set-Service sshd -StartupType Automatic`

## Ansible Host Setup
On the Ansible host, create your ssh keys:

`ssh-keygen`

Copy the public ssh key to the windows host administrator_authorized_keys file:

`scp ~/.ssh/rsa_id.pub user@windowsip:"C:\ProgramData\ssh\administrators_authorized_keys`

Set permissions using the script below to allow the remote user to run in powershell admin:

```
$acl = Get-Acl C:\ProgramData\ssh\administrators_authorized_keys
$acl.SetAccessRuleProtection($true, $false)
$administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
$systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
$acl.SetAccessRule($administratorsRule)
$acl.SetAccessRule($systemRule)
$acl | Set-Acl
```

Refer for details:
https://superuser.com/questions/1342411/setting-ssh-keys-on-windows-10-openssh-server

# Usage
To run the Ansible Playbook, use the following command:

`ansible-playbook -i ./inventory -u james win_dev.yml -v`


