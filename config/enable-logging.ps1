# Logging changes made on win-lab (VM name win11-lab) before running the techniques.
# Run in an elevated PowerShell session.

# Event 4625: failed logons (usually on by default; set explicitly to be sure)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Event 4698: scheduled task created (off by default)
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

# Event 4104: PowerShell Script Block Logging (off by default)
$key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name EnableScriptBlockLogging -Value 1

# Check: both subcategories should show "Success and Failure"
auditpol /get /subcategory:"Logon","Other Object Access Events"
