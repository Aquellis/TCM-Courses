# This script iterates through our detections folder, extracting data from the TOML files
# and writes the data to markdown tables based on when the alerts were created

import os
import tomllib
import datetime
from dateutil.relativedelta import relativedelta
# May need to run pip install python-dateutil for the above to resolve

# Create an empty list object
list = {}

# We want to place alerts into a markdown table based on the month they were created
# Find today's date, then calculate one month & two months in the past
# But first convert the date string from the TOML file to a format dateutil can use
# (YYYY/MM/DD --> YYYY-MM-DD) we only want to use year & month for calculations, not day
today = datetime.date.today()
currentMonth = str(today).split("-")[0] + "-" + str(today).split("-")[1]
oneMonthAgo = str(today - relativedelta(months=1)).split("-")[0] + "-" + str(today - relativedelta(months=1)).split("-")[1]
twoMonthsAgo = str(today - relativedelta(months=2)).split("-")[0] + "-" + str(today - relativedelta(months=2)).split("-")[1]

# Create empty lists that will hold alert data based on when
# the alerts were created
currentList = {}
oneMonthList = {}
twoMonthList = {}
oldList = {}

for root, dirs, files in os.walk('DetEng/custom_detections'):
    for file in files:
                
        # For every file found, check if it has the .toml extension
        # If it is a toml file, load its contents
        if file.endswith(".toml"):

            # Programmatically create the full file path for the TOML files
            # by joining the directory and filename together 
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as loadedToml:
                alert = tomllib.load(loadedToml)
                
                # Extract fields from the TOML file that will be later added to the CSV file
                date = alert['metadata']['creation_date']
                name = alert['rule']['name']
                author = alert['rule']['author']
                risk_score = alert['rule']['risk_score']
                severity = alert['rule']['severity']

                # Create a new object including extracted metadata and rule data 
                obj = {'name': name, 'date': date, 'author': author, 'risk_score': risk_score, 'severity': severity}
                
                # Extract the date each alert was created and paste it in
                # a variable formatted to YYYY-MM
                year = date.split("/")[0]
                month = date.split("/")[1]
                dateCompare = year + "-" + month

                # Do date comparison calculations and add each alert to a list
                # based on the creation date
                if dateCompare == currentMonth: # If the alert was created this month
                    currentList[file] = obj
                elif dateCompare == oneMonthAgo: # If the alert was created one month ago
                    oneMonthList[file] = obj
                elif dateCompare == twoMonthsAgo:  # If the alert was created two months ago
                    twoMonthList[file] = obj
                else:
                    oldList[file] = obj # If the alert is older than two months
                
                list[file] = obj           

# Create an output CSV file
outputPath = "DetEng/metrics/detections.md"

# Open our new output file and write it's contents
outFile = open(outputPath, "w")

outFile.write("# Detections Report\n")

 # Start writing the headers of the markdown file
outFile.write("## Current Month\n")
outFile.write("### Alerts created:\n")
outFile.write("| Alert | Date | Author | Risk Score | Severity |\n") # Defines columns
outFile.write("| --- | --- | --- | --- | --- |\n") # Defines column sizes

# Iterate over the list of alerts created this month and write
# the contents to the output MD file.
for line in currentList.values():
    mdDate = line['date']
    mdName = line['name']
    # Convert the author list to string
    # Replace any commas with semicolons (helps when pasting data to spreadsheets)
    mdAuthor = str(line['author']).replace(",",";") 
    mdRiskScore = str(line['risk_score']) # Convert the risk score int to string
    mdSeverity = line['severity']

    outFile.write("|" + mdName + "|" + mdDate + "|" + mdAuthor + "|" + mdRiskScore + "|" + mdSeverity + "|\n")

outFile.write("## Last Month\n")
outFile.write("### Alerts created:\n")
outFile.write("| Alert | Date | Author | Risk Score | Severity |\n") # Defines columns
outFile.write("| --- | --- | --- | --- | --- |\n") # Defines column sizes

# Iterate over the alerts created last month and write them to the markdown file
for line in oneMonthList.values():
    mdDate = line['date']
    mdName = line['name']
    mdAuthor = str(line['author']).replace(",",";") 
    mdRiskScore = str(line['risk_score']) # Convert the risk score int to string
    mdSeverity = line['severity']

    outFile.write("|" + mdName + "|" + mdDate + "|" + mdAuthor + "|" + mdRiskScore + "|" + mdSeverity + "|\n")

outFile.write("## Two Months Ago\n")
outFile.write("### Alerts created:\n")
outFile.write("| Alert | Date | Author | Risk Score | Severity |\n") # Defines columns
outFile.write("| --- | --- | --- | --- | --- |\n") # Defines column sizes

# Iterate over the alerts created two months ago and write them to the markdown file
for line in twoMonthList.values():
    mdDate = line['date']
    mdName = line['name']
    mdAuthor = str(line['author']).replace(",",";") 
    mdRiskScore = str(line['risk_score']) # Convert the risk score int to string
    mdSeverity = line['severity']

    outFile.write("|" + mdName + "|" + mdDate + "|" + mdAuthor + "|" + mdRiskScore + "|" + mdSeverity + "|\n")

outFile.write("## Oldest Alerts\n")
outFile.write("### Alerts created:\n")
outFile.write("| Alert | Date | Author | Risk Score | Severity |\n") # Defines columns
outFile.write("| --- | --- | --- | --- | --- |\n") # Defines column sizes

# Iterate over the alerts created last month and write them to the markdown file
for line in oldList.values():
    mdDate = line['date']
    mdName = line['name']
    mdAuthor = str(line['author']).replace(",",";") 
    mdRiskScore = str(line['risk_score']) # Convert the risk score int to string
    mdSeverity = line['severity']

    outFile.write("|" + mdName + "|" + mdDate + "|" + mdAuthor + "|" + mdRiskScore + "|" + mdSeverity + "|\n")

# Close the output file
outFile.close()