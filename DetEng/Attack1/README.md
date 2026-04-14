# Detection Engineering Attack Scenario 1

This attack:
* Spins up a python web server on the Windows victim VM
* Uses the Kali attacker VM to scan the web server using Nmap, Nikto & ZAP
* Logs are collected by the Ubuntu VM running Zeek

## Attack Walkthrough
1. In the Ubuntu VM, start the Zeek service: <br>
in **/opt/zeek/bin** run: 
```
./zeekctl
deploy 
```
2. Spin up the web server on the Windows victim VM:
```
python -m http.server
```

3. Ensure the Windows victim webserver is accessible by Kali attacker VM:
```
http://[Windows victim VM IP]:8000/
```

4. Launch the Nmap, Nikto and ZAP scans on the Kali attacker VM pointed to the Windows web server:
```
nmap -sV -p 8000 [Windows victim VM IP]

nikto -h [Windows victim VM IP]:8000
```

Install zaproxy if needed: **sudo apt install zaproxy** <br>
Start a new automated scan against **[Windows victim VM IP]:8000** <br>
![zapScan](../../Images/AttScen1_zap)

## Rule & Alert Creation

### Create the Rule
Open the Elastic logs, use the **event.dataset: zeek.http** data source and use the search query: <br>
```
user_agent.original: *Nmap* or user_agent.original:"[user agent of Kali Attacker VM]"
```

Create the new rule for this activity: <br>
![attScen1_rule](../../Images/AttScen1_rule)

* Suppress the rule by **destination.ip** and per time period of **5 minutes**
* Schedule the rule to run every **5 minutes** with a lookback time of **5 minutes** (ensures all traffic is checked even though the rule doesn't run constantly)

### Create a Threshold Alert
In case that large amounts of network traffic do not come from either Nmap, Nikto or ZAP scans, create a new threshold alert: <br>
![attScen1_threshold](../../Images/AttScen1_threshold)
* The custom query to use is: **event.dataset: "zeek.http"**
* Group traffic by **source.ip** and **destination.ip**
* Set the threshold to **1000**

## Confirm the Alert Works
Re-launch the attacks as given in the **Attack Walkthrough** section
