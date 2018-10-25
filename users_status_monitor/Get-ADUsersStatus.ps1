<#
    Get-ADUsersStatus.ps1
    Queries attributes of your Active Directory users, generates an HTML report, and sends the report to specified email recipients
    This is created to serve both as an audit tool, and as a monitoring/ alerting tool
    v1.0 
#>

param(
    [bool]$Silent = $false # Set to true to suppress console output
) 

# This was originally created in PowerShell v2, the line below is no longer needed in v3+
# Import-Module ActiveDirectory > $null

# This was originally created in PowerShell v2, the line below is no longer needed in v3+
# $scriptPath = split-path -parent $MyInvocation.MyCommand.Definition

###################  Constant variables
$searchBase = $null
$global:outparams = @()
$global:paramBuilder = @()
[string]$global:domain = ""
[string]$global:userListFile = ""
$global:properties = @()
[string]$global:Errors = ""
[string]$global:Success = ""
[string]$global:emailto = ""
[string]$global:emailcc = ""
[string]$global:emailfrom = ""
[string]$global:emailsubject = ""
[string]$global:smtpserver = ""
[string]$global:smtpport = ""
[string]$global:alertcriteria = ""
[string]$global:DCs = ""
$global:reportsHistory
[bool]$global:emailReport = $true
[bool]$global:errorEncountered = $false
$REPORTPATH = "$PSScriptRoot\Reports"
$ReportFileName = "Reports_" + (Get-Date -F 'MMddyyyyhhmmss') + ".html"
###################

################### CSS style for HTML Reports; Edit as needed depending on your teste
$headingstyle = "<style>"
$headingstyle = $headingstyle + "H2{font-family:Tahoma;font-size:16px;padding-bottom:0px;margin:0}" 
$headingstyle = $headingstyle + "BODY{background-color:white;font-family:Tahoma;font-size:14px}"
$headingstyle = $headingstyle + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
$headingstyle = $headingstyle + "TH{border-width: 1px;padding-left: 10px;padding-right: 10px;border-style: solid;border-color: black;background-color:midnightblue;white-space: pre-wrap;font-family:Tahoma;color:white}"
$headingstyle = $headingstyle + "TD{border-width: 1px;padding-left: 10px;padding-right: 10px;border-style: solid;border-color: black;background-color:white;white-space: pre-wrap}"
$headingstyle = $headingstyle + "Table.courier TD{border-width: 1px;padding-left: 10px;padding-right: 10px;border-style: solid;border-color: black;background-color:white;white-space: pre-wrap; font-family: courier new}"
$headingstyle = $headingstyle + "</style>"
###################

###################  Program variables
#  Do NOT change anything below, use config.ini instead
$settings = Get-Content "$PSScriptRoot\config.ini"
foreach ($line in $settings)
{
    if ((($line -like "*#*") -eq $false) -or $line -ne $null)
    {
        if ($line -like "*accountsfile*")
        {
            $global:userListFile = $line.Split('=')[1]
        }
        if ($line -like "*domain*")
        {
            $global:domain = $line.Split('=')[1]
        }
        if ($line -like "*yes*")
        {
            $global:properties += $line.Split('=')[0]
        }
        if ($line -like "*emailto*")
        {
            $global:emailto = $line.Split('=')[1]
        }
        if ($line -like "*emailcc*")
        {
            $global:emailcc = $line.Split('=')[1]
        }
        if ($line -like "*emailsubject*")
        {
            $global:emailsubject = $line.Split('=')[1]
        }
        if ($line -like "*smtpserver*")
        {
            $global:smtpserver = $line.Split('=')[1]
        }
        if ($line -like "*smtpport*")
        {
            $global:smtpport = $line.Split('=')[1]
        }
        if ($line -like "*emailfrom*")
        {
            $global:emailfrom = $line.Split('=')[1]
        }
        if ($line -like "*alertcriteria*")
        {
            $global:alertcriteria = $line.Split('=')[1]
        }
        if ($line -like "*DCs*")
        {
            $global:DCs = $line.Split('=')[1]
        }
        if ($line -like "*reportshistory*")
        {
            $global:reportsHistory = $line.Split('=')[1]
        }
    }
}
###################

################### HELPER functions
function Get-PasswordExpirationDate {
    param(
        [string]$User
    )

    $success = $true
    $temp_path = "c:\netuser.txt"
    try {
        Invoke-WmiMethod -Path "Win32_Process" -Name Create -ArgumentList "cmd /c net user $User /domain > $temp_path" -ErrorAction Stop > $null
        Start-Sleep -Seconds 1

        # Repeat until net user command completes
        # Start-Process -Wait might be a better way of implementing this
        do {
            $result = Get-Content "c:\netuser.txt"
            foreach ($line in $result) {
                if ($line -like "*Password expires*") {
                    $passwordexpiredate = ($line -replace 'Password expires','').Trim()
                    break
                }
            }
            Start-Sleep -Seconds 1
        } while ($result -eq $null)

        # Cleanup
        if (Test-Path $temp_path) {
            Remove-Item -Path $temp_path -Force -ErrorAction SilentlyContinue > $null
        }
        return $passwordexpiredate
    }
    catch {
        if ($Silent -eq $false) {
            Write-Host -ForegroundColor Red "Unable to query $User expiration date."
            Write-Host -ForegroundColor Red "ERROR: $_`n"
        }
        return "Unable to determine password expiration"
    }
}

# Get attributes of users in AD
# Each attribute specified in config.ini is processed
function Get-UserStatus {
    $userList = Get-Content "$PSScriptRoot\$global:userListFile"
    $CNcol = $global:domain.Split('.')
    $CNcolcounter = 1
    foreach ($CN in $CNcol) {
        $searchBase += "DC=" + $CN
        if ($CNcolcounter -lt $CNcol.Count) {
            $searchBase += ','
        }
        $CNcolcounter++
    }

    foreach ($user in $userList) {
        $usrObject = Get-ADUser -filter {SamAccountName -eq $user} -searchbase $searchBase -Properties *
        $objProperties = @{}

        if ($usrObject.SamAccountName -eq "$user") {
            if ($properties -contains "AccountName") {
                if ($Silent -eq $false) {
                    Write-Host Name: $usrObject.SamAccountName
                }
                $objProperties.Add('Account Name',$usrObject.SamAccountName)
            }
            if ($global:properties -contains "GivenName") {
                if ($Silent -eq $false) { 
                    Write-Host Given Name: $usrObject.GivenName
                }
                if ($usrObject.GivenName -eq $null) {
                    $objProperties.Add('First Name',"Not set" )
                }
                else {
                    $objProperties.Add('First Name',$usrObject.GivenName)
                }
            }
            if ($global:properties -contains "Surname") {
                if ($Silent -eq $false) { 
                    Write-Host Last Name: $usrObject.Surname
                }
                if ($usrObject.Surname -eq $null) {
                    $objProperties.Add('Last Name',"Not set" )
                }
                else {
                    $objProperties.Add('Last Name',$usrObject.Surname)
                }
            }
            if ($global:properties -contains "UserPrincipalName") {
                if ($Silent -eq $false) { 
                    Write-Host User Principal Name: $usrObject.UserPrincipalName
                }
                if ($usrObject.UserPrincipalName -eq $null) {
                    $objProperties.Add('User Principal Name',"Not set" )
                }
                else {
                    $objProperties.Add('User Principal Name',$usrObject.UserPrincipalName)
                }
            }
            if ($global:properties -contains "Description") {
                if ($Silent -eq $false) {
                    Write-Host Description: $usrObject.Description
                }
                if ($usrObject.Description -eq $null) {
                    $objProperties.Add('Description',"Not set")
                }
                else {
                    $objProperties.Add('Description',$usrObject.Description)
                }
            }
            if ($global:properties -contains "Enabled") {
                if ($Silent -eq $false) {
                    Write-Host Enabled: $usrObject.Enabled
                }
                if ($usrObject.Enabled -eq $true) {
                    $objProperties.Add('Enabled','<td style="background-color: darkgreen;">Yes</td>')
                }
                else {
                    $objProperties.Add('Enabled','<td style="background-color: red;">No</td>')
                    if ($global:alertcriteria -like "*enabled*") {
                        $global:errorEncountered = $true
                    }
                }
            }
            if ($global:properties -contains "AccountExpirationDate") {
                if ($Silent -eq $false) {
                    Write-Host Account Expiration Date: $usrObject.AccountExpirationDate
                }
                if ($usrObject.AccountExpirationDate -eq $null) {
                    $objProperties.Add('Account Expiration Date',"Does not expire")
                }
                else {
                    $objProperties.Add('Account Expiration Date',$usrObject.AccountExpirationDate)
                }
            }
            if ($global:properties -contains "LockedOut") {
                if ($Silent -eq $false) {
                    Write-Host Locked Out: $usrObject.LockedOut
                }
                if ($usrObject.LockedOut -eq $true) {
                    $objProperties.Add('Locked Out','<td style="background-color: red;">Yes</td>')
                    if ($global:alertcriteria -like "*lockedout*") {
                        $global:errorEncountered = $true
                    }
                    try {
                        $unlockedAccount = $usrObject.SamAccountName
                        if ($Silent -eq $false) {
                            Write-Host "Unlocking account $unlockedAccount"
                        }
                        Unlock-ADAccount -Identity $usrObject
                        $displaydate = date
                        $global:Success += "Successfully unlocked account $unlockedAccount on $displaydate"
                    }
                    catch {
                        $unlockedAccount = $usrObject.SamAccountName
                        $global:Errors += "Autocorrect action failed. Unable to unlock $unlockedAccount. Please unlock manually"
                    }
                }
                else {
                    $objProperties.Add('Locked Out','<td style="background-color: darkgreen;">No</td>')
                }
            }
            if ($global:properties -contains "AccountLockoutTime") {
                if ($usrObject.LockedOut -eq $true) {
                    if ($Silent -eq $false) {
                        Write-Host Lock Out Time: $usrObject.AccountLockoutTime
                    }
                    if ($usrObject.AccountLockoutTime -eq $null) {
                        $objProperties.Add('Lockout Time',"N/A")
                    }
                    else {
                        $objProperties.Add('Lockout Time',$usrObject.AccountLockoutTime)
                    }
                }
                else {
                    $objProperties.Add('Lockout Time',"N/A")
                }
            }
            if ($global:properties -contains "LockoutSource") {
                if ($usrObject.LockedOut -eq $true) {
                    $LockoutSource = Get-LockOutSource -UserSID $usrObject.SID.Value
                    if ($Silent -eq $false) {
                        Write-Host Lock Out Source: $LockoutSource
                    }
                    if ($LockoutSource -eq $null -or $LockoutSource -eq "") {
                        $objProperties.Add('Lockout Source',"No information on Event Logs")
                    }
                    else {
                        $objProperties.Add('Lockout Source', $LockoutSource)
                    }
                }
                else {
                    $objProperties.Add('Lockout Source',"N/A")
                }
            }
            if ($global:properties -contains "PasswordExpired") {
                if ($Silent -eq $false) {
                    Write-Host Password Expired: $usrObject.PasswordExpired
                }
                if ($usrObject.PasswordNeverExpires -eq $true) {
                    $objProperties.Add('Password Expired','<td style="background-color: darkgreen;">N/A</td>')
                }
                else {
                    if ($usrObject.PasswordExpired -eq $true) {
                        $objProperties.Add('Password Expired','<td style="background-color: red;">Yes</td>')
                        if ($global:alertcriteria -like "*passwordexpired*") {
                            $global:errorEncountered = $true
                        }
                    }
                    else {
                        $objProperties.Add('Password Expired','<td style="background-color: darkgreen;">No</td>')
                    }
                }
            }
            if ($global:properties -contains "PasswordNeverExpires") {
                if ($Silent -eq $false) {
                    Write-Host Password Never Expires: $usrObject.PasswordNeverExpires
                }
                if ($usrObject.PasswordNeverExpires -eq $true) {
                    $objProperties.Add('Password Never Expires',"Yes" )
                }
                else {
                    $objProperties.Add('Password Never Expires',"No")
                }
            }
            if ($global:properties -contains "PasswordExpiration") {
                $userPasswordExpiration = Get-PasswordExpirationDate -User $user
                if ($usrObject.PasswordNeverExpires -eq $true) {
                    $objProperties.Add('Password Expiration',"N/A" )
                }
                else {
                    if ($Silent -eq $false) {
                        Write-Host Password Expiration: $userPasswordExpiration
                    }
                    if ($userPasswordExpiration -eq "Never") {
                        $objProperties.Add('Password Expiration',"N/A" )
                    }
                    elseif ($userPasswordExpiration -eq $null) {
                        $objProperties.Add('Password Expiration',"No data")
                    }
                    else {
                        $objProperties.Add('Password Expiration',$userPasswordExpiration)
                    }
                }
                $userPasswordExpiration = $null
            }
            if ($global:properties -contains "PasswordLastSet") {
                if ($Silent -eq $false) {
                    Write-Host Password Last Set: $usrObject.PasswordLastSet
                }
                if ($usrObject.PasswordLastSet -eq $null) {
                    $objProperties.Add('Password Last Set',"N/A" )
                }
                else {
                    $objProperties.Add('Password Last Set',$usrObject.PasswordLastSet)
                }
            }
            if ($global:properties -contains "Modified") {
                if ($Silent -eq $false) {
                    Write-Host Last Modified: $usrObject.Modified
                }
                if ($usrObject.Modified -eq $null) {
                    $objProperties.Add('Account Last Modified',"No data" )
                }
                else {
                    $objProperties.Add('Account Last Modified',$usrObject.Modified)
                }
            }
            if ($global:properties -contains "Created") {
                if ($Silent -eq $false) {
                    Write-Host Created: $usrObject.Created
                }
                if ($usrObject.Created -eq $null) {
                    $objProperties.Add('Account Created',"Unknown" )
                }
                else {
                    $objProperties.Add('Account Created',$usrObject.Created)
                }
            }
            if ($global:properties -contains "HomeDirectory") {
                if ($Silent -eq $false) {
                    Write-Host Home Directory: $usrObject.HomeDirectory
                }
                if ($usrObject.HomeDirectory -eq $null) {
                    $objProperties.Add('Home Directory',"Not set" )
                }
                else {
                    $objProperties.Add('Home Directory',$usrObject.HomeDirectory)
                }
            }
            if ($global:properties -contains "LastLogonDate") {
                if ($Silent -eq $false) {
                    Write-Host Last Logon Date: $usrObject.LastLogonDate
                }
                if ($usrObject.LastLogonDate -eq $null) {
                    $objProperties.Add('Last Logon Date',"Unknown" )
                }
                else {
                    $objProperties.Add('Last Logon Date',$usrObject.LastLogonDate)
                }
            }
            if ($global:properties -contains "LastBadPasswordAttempt") {
                if ($Silent -eq $false) {
                    Write-Host Last Bad Password Attempt: $usrObject.LastBadPasswordAttempt
                }
                if ($usrObject.LastBadPasswordAttempt -eq $null) {
                    $objProperties.Add('Last Bad Password Attempt',"No recent bad password attempt" )
                }
                else {
                    $objProperties.Add('Last Bad Password Attempt',$usrObject.LastBadPasswordAttempt)
                }
            }
            if ($global:properties -contains "LogonWorkstations") {
                if ($Silent -eq $false) {
                    Write-Host Logged on Workstation: $usrObject.LogonWorkstations
                }
                if ($usrObject.LogonWorkstations -eq $null) {
                    $objProperties.Add('Logged on Workstations',"Unknown" )
                }
                else {
                    $objProperties.Add('Logged on Workstations',$usrObject.LogonWorkstations)
                }
            }
            if ($global:properties -contains "SID") {
                if ($Silent -eq $false) {
                    Write-Host SID: $usrObject.SID
                }
                if ($usrObject.SID -eq $null) {
                    $objProperties.Add('SID',"Unknown" )
                }
                else {
                    $objProperties.Add('SID',$usrObject.SID)
                }
            }

            $objBuilder = New-Object -TypeName psobject -Property $objProperties
            $global:outparams += $objBuilder
        }
        else {
            $global:Errors += "Error finding user $user in $global:domain <br>"
        }
    }

    #Parameter Builder for HTML Report
    foreach ($property in $global:properties)
    {
        if ($property -eq "AccountName") {
            $global:paramBuilder += "Account Name"
        }
        if ($property -eq "GivenName") {
            $global:paramBuilder += "First Name"
        }
        if ($property -eq "Surname") {
            $global:paramBuilder += "Last Name"
        }
        if ($property -eq "UserPrincipalName") {
            $global:paramBuilder += "User Principal Name"
        }
        if ($property -eq "Description") {
            $global:paramBuilder += "Description"
        }
        if ($property -eq "Enabled") {
            $global:paramBuilder += "Enabled"
        }
        if ($property -eq "AccountExpirationDate") {
            $global:paramBuilder += "Account Expiration Date"
        }
        if ($property -eq "LockedOut") {
            $global:paramBuilder += "Locked Out"
        }
        if ($property -eq "AccountLockoutTime") {
            $global:paramBuilder += "Lockout Time"
        }
        if ($property -eq "LockOutSource") {
            $global:paramBuilder += "Lockout Source"
        }
        if ($property -eq "PasswordExpired") {
            $global:paramBuilder += "Password Expired"
        }
        if ($property -eq "PasswordExpiration") {
            $global:paramBuilder += "Password Expiration"
        }
        if ($property -eq "PasswordNeverExpires") {
            $global:paramBuilder += "Password Never Expires"
        }
        if ($property -eq "PasswordLastSet") {
            $global:paramBuilder += "Password Last Set"
        }
        if ($property -eq "Created") {
            $global:paramBuilder += "Account Created"
        }
        if ($property -eq "Modified") {
            $global:paramBuilder += "Account Last Modified"
        }
        if ($property -eq "LastLogonDate") {
            $global:paramBuilder += "Last Logon Date"
        }
        if ($property -eq "LastBadPasswordAttempt") {
            $global:paramBuilder += "Last Bad Password Attempt"
        }
        if ($property -eq "HomeDirectory") {
            $global:paramBuilder += "Home Directory"
        }
        if ($property -eq "LogonWorkstations") {
            $global:paramBuilder += "Logged on Workstations"
        }
        if ($property -eq "SID") {
            $global:paramBuilder += "SID"
        }
    }
}

function Get-LockOutSource {
    param( 
      [string]$UserSID      
    ) 

    $LockoutLocations = @()
    [string]$Sources = ""

    foreach ($DC in $global:DCs.Split(',')) {
        try  {   
            if ($Silent -eq $false) {
                Write-Host "Querying event log on $DC"
            }
            $LockedOutEvents = Get-WinEvent -ComputerName $DC -FilterHashtable @{LogName='Security';Id=4740} -ErrorAction Stop | Sort-Object -Property TimeCreated -Descending 
        } 
        catch  {           
            # No need to prompt alert, just skip current DC
            continue
        }                    
        foreach ($event in $LockedOutEvents) {             
            if ($event | Where-Object {$_.Properties[2].value -match $UserSID})  {  
                $LockoutLocations += ($event | Select-Object -Property @(@{Label = 'LockedOutLocation';  Expression = {$_.Properties[1].Value}}) | Select-Object -ExpandProperty 'LockedOutLocation')
            }
        }
    }

    $Count = 1
    $UniqueLocations = $LockoutLocations | Sort-Object | Get-Unique
    foreach ($location in $UniqueLocations) {
        $Sources += $location
        if ($Count -lt $LockoutLocations.Count) {
            $Sources += "`n"
        }
    }
    return $Sources
}

# Build the report header
function Set-Header {
    param(
        [string]$Header,
        [string]$Subheader
    )

    $datestamp = "Generated on " + (Get-Date -Format 'HH:mm MM/dd/yyyy')
    $strHeader = $headingstyle + "<H2>" + $header + "</H2>"

    if ($PSBoundParameters.ContainsKey('Subheader')) {
        $strHeader = $strHeader + ($datestamp + '</p>')
        $strHeader = $strHeader + '<p style="margin-top:-0px;padding:0px;color:midnightblue;font-family:calibri;font-size:3;line-height:3px">' + $subheader + '<br>'   
    }
    else {
        $strHeader = $strHeader + '<p style="margin-top:-0px;padding:0px;color:midnightblue;font-family:calibri;font-size:3">' + $datestamp + '</p>'
    }
    # Return header string
    $strHeader
}

function Set-Report {
    # Set HTML Header
    $reportraw = Write-Output $global:outparams | Select-Object $global:paramBuilder | ConvertTo-HTML -head (Set-Header -Header "Critical Accounts Status - $global:domain" -Subheader " " )
 
    # Fix encoding issues from ConvertTo-HTML command
    $reportraw = $reportraw -replace '<td>&lt;td style=&quot;background-color: darkgreen;&quot;&gt;Yes&lt;/td&gt;</td>','<td style="background-color: darkgreen;">Yes</td>'
    $reportraw = $reportraw -replace '<td>&lt;td style=&quot;background-color: red;&quot;&gt;No&lt;/td&gt;</td>','<td style="background-color: red;">No</td>'
    $reportraw = $reportraw -replace '<td>&lt;td style=&quot;background-color: darkgreen;&quot;&gt;No&lt;/td&gt;</td>','<td style="background-color: darkgreen;">No</td>'
    $reportraw = $reportraw -replace '<td>&lt;td style=&quot;background-color: darkgreen;&quot;&gt;N/A&lt;/td&gt;</td>','<td style="background-color: darkgreen;">N/A</td>'
    $reportraw = $reportraw -replace '<td>&lt;td style=&quot;background-color: red;&quot;&gt;Yes&lt;/td&gt;</td>','<td style="background-color: red;">Yes</td>'
    $reportraw | Out-File -Append "$REPORTPATH\$ReportFileName"

    if ($global:Success -ne "") {
        $addAction = '<p style="margin-top:-0px;padding:0px;color:darkgreen;font-family:calibri;font-size:14;line-height:14px"><br><b> Corrective Action: </b><br>'  
        $addAction += $global:Success + '<br></p>'
        $addAction | Out-File -Append "$REPORTPATH\$ReportFileName"
    }

    if ($global:Errors -ne "") {
        $addError = '<p style="margin-top:-0px;padding:0px;color:red;font-family:calibri;font-size:14;line-height:14px"><br><b> Error Log: </b><br>'  
        $addError += $global:Errors + '<br></p>'
        $addError | Out-File -Append "$REPORTPATH\$ReportFileName"
    }

    $output_report = "$REPORTPATH\$ReportFileName"
    if ($Silent -eq $false) {
        & $output_report
    }
}

Function Send-Report
{
    [CmdletBinding()]
    param(
        [string[]]$To = $global:emailto,
        [string]$CC = $global:emailcc,
        [string[]]$From = $global:emailfrom,
        [string]$SMTPServer = $global:smtpserver,
        [string]$SMTPPort = $global:smtpport,
        [string]$Subject = $global:emailsubject
    )

    # Set up email message
    if ($Silent -eq $false) {
        Write-Host "Creating email message"
    }
    $SMTPmessage = New-Object Net.Mail.MailMessage($From,$To)
    foreach ($address in $CC.Split(',')) {
        $SMTPmessage.CC.Add($address)    
    }
    $SMTPmessage.Subject = $Subject
    $SMTPmessage.IsBodyHtml = $True
    if ($global:errorEncountered -eq $True) {
        $SMTPmessage.Priority = [System.Net.Mail.MailPriority]::High
    }
    $SMTPmessage.Body = Get-Content "$REPORTPATH\$ReportFileName"
    if ($Silent -eq $false) {
        Write-Host "Email message created. Attaching report and logs (optional)"
    }
    $SMTPClient = New-Object Net.Mail.SmtpClient($SMTPServer,$SMTPPort)

    # Send Email with HTML report as inline message
    try {
        if ($Silent -eq $false) { Write-Host "Sending email message..." }
        $SMTPClient.Send($SMTPmessage)
        if ($Silent -eq $false) { Write-Host "Email sent!" }
    }
    catch [Exception] {
        if ($Silent -eq $false) { Write-Host -ForegroundColor Red "Unable to send email. The error message is: $_" }
    }

    # Dispose smtp object
    $SMTPmessage.Dispose()
}

function Remove-OldReports {
    $reportsList = Get-ChildItem -Path "$PSScriptRoot\Reports" | Sort-Object -Property 'LastWriteTime' -Descending | Select-Object -ExpandProperty Name
    if ($reportsList.Count -ge $global:reportsHistory) {
        $reportCounter = 1
        foreach ($report in $reportsList) {
            if ($reportCounter -gt $global:reportsHistory) {
                Remove-Item -Path "$PSScriptRoot\Reports\$report" -Force > $null
            }
            $reportCounter++
        }
    }
}
###################

################### MAIN: Actual program flow
function Invoke-Program {
    # Get status of user accounts in domain
    try {
        if ($Silent -eq $false) {
            Write-Output "Obtaining User status for $global:domain"
        }
        Get-UserStatus
    }
    catch {
        if ($Silent -eq $false) {
            Write-Host -ForegroundColor Red "Unable to obtain status for one or more users"
            Write-Host -ForegroundColor Red "ERROR: $_"
        }
    }

    # Generate report
    try {
        if ($Silent -eq $false) {
            Write-Output "Generating report..."
        }
        Set-Report
    }
    catch {
        if ($Silent -eq $false) {
            Write-Host -ForegroundColor Red "Unable to generate report"
            Write-Host -ForegroundColor Red  "ERROR: $_"
         }
    }

    #Send email report
    if ((($global:properties -contains "emailonalertonly") -eq $false) -or $global:errorEncountered -eq $true) {
        try {
            if ($Silent -eq $false) {
                Write-Output "Sending Email"
            }
            Send-Report
        }
        catch [Exception] {
            if ($Silent -eq $false) {
                Write-Host -ForegroundColor Red "Unable to email report."
                Write-Host -ForegroundColor Red  "ERROR: $_"
            }
        }
    }

    #Clean Old Reports
    try {
        if ($Silent -eq $false) {
            Write-Host "Cleaning up old reports"
        }
        Remove-OldReports
    }
    catch {
        if ($Silent -eq $false) {
            Write-Host -ForegroundColor Red "Unable to clean old reports."
            Write-Host -ForegroundColor Red  "ERROR: $_"
         }
    }
}
###################

# Call the program!
Invoke-Program