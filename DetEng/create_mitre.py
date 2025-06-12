# This script pulls all JSON data from MITRE's enterprise attack matrix, parses it and
# collects certain fields of attack techniques listed

import requests
import os
import tomllib
import sys

url = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/enterprise-attack/enterprise-attack.json"
headers = {
    'accept': 'application/json'
}

# Grab the full JSON file of attack matrix data from MITRE
mitreData = requests.get(url, headers=headers).json()

# Create an empty object used to hold a MITRE technique/sub-technique
mitreObj = {}

# Create a variable to track whether the assoicated GitHub action is passed or failed
failure = 0

# Loop through the data pulled from MITRE, specifically through objects[] where each 
# technique/sub-technique in the attack matrix:
#   1 - Has an entry in the list of attack-patterns
#   2 - Is created by MITRE (external ID begins with a 'T')
#   3 - Has a Tactic associated with the technique
#   3 - Has a field for deprecation status

for object in mitreData['objects']:
    # Create an array in case the technique has multiple associated kill-chain phases
    tactics = []

    # Only look at listings that are techniques/sub-techniques
    if object['type'] == 'attack-pattern':

        # Verify that the technique/sub-technique includes the external_references section
        if 'external_references' in object:
            for reference in object['external_references']:

                # If the technique/sub-technique contains the field 'external_id', ensure the object came from Mitre 
                # and not CAPEC for example (we know it's MITRE if the ID starts with T)
                if 'external_id' in reference:

                    # Confirm the technique's/sub-technique's external ID starts with a T
                    # If it does, then grab its name, ID and URL   
                    if ((reference['external_id'].startswith("T"))):
       
                        name = object['name']
                        technique = reference['external_id']
                        mitreUrl = reference['url'] 

                        # Ensure the technique's/sub-technique's Tactic is listed
                        # If there are multiple Tactics listed, create a list of them
                        if 'kill_chain_phases' in object:
                                for tactic in object['kill_chain_phases']:
                                     tactics.append(tactic['phase_name'])

                        # Confirm that the technique's/sub-technique's deprecation status field exists
                        # If it does, take the value of x_mitre_deprecated
                        # If not, assign the value to 'False'
                        if 'x_mitre_deprecated' in object:
                            deprecated = object['x_mitre_deprecated']

                            # Create an object to hold the values of all extracted fields (based on existence of 'x_mitre_deprecated' field)
                            tempObject = {'technique': technique, 'name': name, 'tactics': str(tactics), 'deprecated': deprecated, 'url': url}
                            mitreObj[technique] = tempObject
                        else:
                             tempObject = {'technique': technique, 'name': name, 'tactics': str(tactics), 'deprecated': "False", 'url': url}
                             mitreObj[technique] = tempObject

# We can now create filters to print specific fields of MITRE techniques
#print(mitreObj['T1123']['name'])
mitreObject = {}

# Search in the root directory provided, any/all subsdirectories within it and 
# the files found in those directories (double \\ needed in the path)
for root, dirs, files in os.walk("custom_detections/"):

    # For every file found, check if it has the .toml extension
    # If it is a toml file, load its content
    for file in files:
        if file.endswith(".toml"):
    
            # Programmatically create the full file path for the TOML files
            # by joining the directory and filename together 
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as loadedToml:
                alert = tomllib.load(loadedToml)
               
                #Start each file iteration with an empty array storing MITRE fields
                tempObject_array = []

                # First confirm the data is collected from the MITRE ATT&CK framwwork before continuing
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

                        tempObject2 = {'tactic': tactic, 'techniqueID': techniqueID, 'techniqueName': techniqueName, 'subtechID': subtechID, 'subtechName': subtechName}
                       
                        # Append these new subtechnique fields to the existing list to not overwrite any values
                        tempObject_array.append(tempObject2)
                        mitreObject[file] = tempObject_array

# Create an array of all MITRE tactics to use for data validation
tactic_list = ['none', 'reconnaissance', 'resource development', 'initial access', 'execution', 'persistence', 'privilege escalation', 'defense evasion', 'credential access', 'discovery', 'lateral movement', 'collection', 'command and control', 'exfiltration', 'impact']

# Parse through the created object and for every unique TOML file we validated,
# extract the TTP data fields 
for file in mitreObject:
    for line in mitreObject[file]:
        tactic = line['tactic'].lower()
        techniqueID = line['techniqueID']
        techniqueName = line['techniqueName']
        subtechID = line['subtechID']
        subtechName = line['subtechName']
                         
        # Now we want to run some data validation against the information we've gathered:
        #
        # 1 - Ensure the MITRE Tactic listed exists
        # 2 - Verify that the MITRE technique ID is valid
        # 3 - Verify that the MITRE technique ID & name combination is valid
        # 4 - Verify that the MITRE subtechnique ID & name combination is valid
        # 5 - Check the technique's deprecation status

        # Data validation Step 1 - Ensure the MITRE Tactic listed exists
        if tactic not in tactic_list:
            print("The MITRE Tactic listed in " + file + " does not exist: " + tactic)
            failure = 1

        # Data validation Step 2 - Verify that the MITRE technique ID is valid
        # Look in the mitreObj which holds all the extracted techniqueID's as Keys and confirm 
        # if the field found in the file matches the existing Key
        try:
            # If the values match, do nothing
            if mitreObj[techniqueID]:
                pass
        # If the values don't match, throw a KeyError (key doesn't exist)
        except KeyError:
            print("Invalid MITRE Technique ID found in " + file + " : " + techniqueID)

            # If the file fails the validation check, set the failure variable to 1 so
            # the GitHub action knows the validation check failed
            failure = 1

        # Data validation Step 3 - Verify that the MITRE technique ID & name combination is valid
        # Look in the mitreObj which holds the extracted techniqueID and confirm
        # if the field found in the file matches
        try:
            mitre_name = mitreObj[techniqueID]['name']
            extracted_name = line['techniqueName']

            # If the values don't match, throw an error message
            if extracted_name != mitre_name:
                print("MITRE Technique ID and Name Mismatch discovered in " + file + ". \n Expected: " + mitre_name + " and file contains " + extracted_name)
                failure = 1
        # Skip if the Key doesn't exist
        except KeyError:
            pass

        # Data validation Step 4 - MITRE subtechnique ID & name combination is valid
        # Look in the mitreObj which holds the extracted subtechID and confirm
        # if the field found in the file matches.
        # Only run this validation check if the value of this exists (subtechID is NOT none)
        try:
            if subtechID != "none":
                mitre_name = mitreObj[subtechID]['name']
                extracted_name = line['subtechName']

                # If the values don't match, throw an error message
                if extracted_name != mitre_name:
                    print("MITRE Subtechnique ID and Name Mismatch discovered in " + file + ". \n Expected: " + mitre_name + " and file contains " + extracted_name)  
                    failure = 1 
        # Skip if the Key doesn't exist
        except KeyError:
            pass

        # Data validation Step 5 - Check the technique's deprecation status
        # Look in the mitreObj which holds the extracted deprecated status and 
        # confirm that the technique/subtechnique isn't deprecated.
        try:
            if mitreObj[techniqueID]['deprecated'] == True:
                print("Deprecated MITRE Technique found in " + file + ": " + techniqueID + " " + techniqueName)
                failure = 1
        # Skip if the Key doesn't exist
        except KeyError:
            pass

# If the validation check has failed, exit the script with an exit code of 1
# (the script exited because of an error)
if failure != 0:
    sys.exit(1)