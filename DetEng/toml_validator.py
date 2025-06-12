# This script loads and validates the structre of TOML files by loading a TOML file then
# checking if it contains all of the required fields 

import tomllib
import sys
import os

# Create a variable to track whether the assoicated GitHub action is passed or failed
failure = 0

# Search in the root directory provided, any/all subsdirectories within it and 
# the files found in those directories (double \\ needed in the path)
for root, dirs, files in os.walk("custom_detections/"):

    # For every file found, check if it has the .toml extension
    # If it is a toml file, load its contents
    for file in files:
        print(file)
        if file.endswith(".toml"):
    
            # Programmatically create the full file path for the TOML files
            # by joining the directory and filename together 
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as loadedToml:
                alert = tomllib.load(loadedToml)

            # Create an array containing the fields found in the loaded TOML file (to compare against require_fields[])
            present_fields = []

            # Create an array containing the name(s) of items in required_fields[] not found in present_fields[]
            missing_fields = []

            # Create an array containing the required fields for an alert based on the alert type
            # Alert types = query, eql (evert correlation), threshold
            if alert['rule']['type'] == "query":
                required_fields = ['description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query']
            elif alert['rule']['type']  == "eql":
                required_fields = ['description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'language']
            elif alert['rule']['type']  == "threshold":
                required_fields = ['description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'threshold']
            else:
                # If an unsupported rule type is found, break the validation loop
                print("Unsupported rule type found in: " + file)
                break

            # Loop through the [tables] in the TOML file
            for table in alert:

                # Loop through each field of the current [table] and append each field to present_fields[]
                for field in alert[table]:
                    present_fields.append(field)

            # Loop through the list of required_fields[] and make sure it exists in present_fields[]
            # if not, add it to the list of missing_fields[]
            for field in required_fields:
                if field not in present_fields:
                    missing_fields.append(field)

            # If any required fields were NOT found in the TOML file, list them
            # Otherwise print that the file is valid
            if missing_fields:
                print("The following fields must be added to " + file + ": \n" + str(missing_fields))
               
                # If the file fails the validation check, set the failure variable to 1 so
                # the GitHub action knows the validation check failed
                failure = 1
            else:
                print(file + " is valid.")

# If the validation check has failed, exit the script with an exit code of 1
# (the script exited because of an error)
if failure != 0:
    sys.exit(1)
