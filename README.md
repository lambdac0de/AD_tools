# AD_tools
Simple scripts and tools dealing with MS Active Directory<br><br>
<b>NOTE</b>: Most of the tools in here were created using PowerShell version 2. There are likely more effective cmdlets and classes for some of the things achieved here.
## users_status_monitor
#### What is this?
This is a utility to monitor mission critical user accounts and service accounts in Active Directory<br>
`Get-ADUsersStatus.ps1` queries attributes of your Active Directory users, generates an HTML report, and sends the report to specified email recipients
#### How do I use this?
1. List all mission critical (important) Active Directory accounts you want to monitor in `accounts.txt`
2. Check `config.ini` and fill in required (AD and SMTP details) and preferred (user attributes to monitor) settings
3. Set the PowerShell script `Get-ADUsersStatus.ps1` to run at your preferred schedule
#### Sample Html report
![Alt text](/relative/path/to/img.jpg?raw=true "User Status Monitor")
