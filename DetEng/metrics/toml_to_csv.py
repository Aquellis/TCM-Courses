# This script iterates through our detections folder, extracting data from the TOML files
# and writes the data to a CSV file

import os
import tomllib

# Create an empty list object
list = {}

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

                # Create an array object to account for multiple MITRE techniques/subtechniques
                mitObjArr = []

                # Paste code from create_mitre.py to iterate through MITRE fields
                # Must provide the index 0 to grab the framework string
                if alert['rule']['threat'][0]['framework'] == "MITRE ATT&CK":

                    # Gather the TTP data from our TOML files:
                    for threat in alert['rule']['threat']:
                        techniqueID = threat['technique'][0]['id']
                        techniqueName = threat['technique'][0]['name']

                        # Check if the 'tactic' field exists, extract it if it does
                        if 'tactic' in threat:
                            tactic = threat['tactic']['name']
                        #If the field doesn't exist, assign it to 'none'
                        else:
                            tactic = "none" 

                        # Check if the 'subtechnique' field exists, extract it if it does
                        if 'subtechnique' in threat['technique'][0]:
                            subtechID = threat['technique'][0]['subtechnique'][0]['id']
                            subtechName = threat['technique'][0]['subtechnique'][0]['name']
                         #If the field doesn't exist, assign subtechnique fields to 'none'
                        else:
                            subtechID = "none"
                            subtechName = "none"
                        
                        # Mash technique/subtechnique names & IDs together
                        technique = techniqueID + " - " + techniqueName
                        subtech = subtechID + " - " + subtechName

                        # Create a new object including extracted MITRE Tactic/Technique/Subtechnique
                        # Append this data to the array
                        mitObj = {'tactic': tactic, 'technique': technique, 'subtech': subtech, 'subtech': subtech}
                        mitObjArr.append(mitObj)

                # Create a new object including extracted metadata, rule data and MITRE data
                obj = {'name': name, 'date': date, 'author': author, 'risk_score': risk_score, 'severity': severity, 'mitre': mitObjArr}
                list[file] = obj           

# Create an output CSV file
outputPath = "DetEng/metrics/converted_files/detections.csv"

# Open our new output file and write it's contents
outFile = open(outputPath, "w")
# Start by writing the CSV headers to the file (followed by a newline)
outFile.write("Name,Date,Author,Risk_Score,Severity,Tactic,Technique,Subtechnique\n")

# Create a separator value to join TTP data together in a single CSV field
separator = "; "

# Iterate over the list object created for each TOML file and write
# the contents to the output CSV file.
# Extract the field values to place in the correct CSV cell
for line in list.values():
    csvDate = line['date']
    csvName = line['name']
    # Convert the author list to string
    # Replace any commas with semicolons (helps when pasting data to spreadsheets)
    csvAuthor = str(line['author']).replace(",",";") 
    csvRiskScore = str(line['risk_score']) # Convert the risk score int to string
    csvSeverity = line['severity']

    # Create arrays to hold the MITRE TTPs (considering multiple values can exist for each)
    tacticArr = []
    techArr = []
    subtechArr = []

    # Iterate over the MITRE data in the list object and 
    # create arrays for Tactic, Technique and Subtechnique fields
    for ttp in line['mitre']:
        tacticArr.append(ttp['tactic'])
        techArr.append(ttp['technique'])
        subtechArr.append(ttp['subtech'])

    # Start writing values to the CSV file
    # Join multiple TTPs together and write them in one field
    outFile.write(csvName + "," + csvDate + "," + csvAuthor + "," + csvRiskScore  + "," + csvSeverity  + "," + separator.join(tacticArr)  + "," + separator.join(techArr)  + "," + separator.join(subtechArr) + "\n")

# Close the output file
outFile.close()