import os
import tomllib

# Create an empty list object
ttps = {}

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

                # Gather the TTP data from our TOML files:
                for threat in alert['rule']['threat']:
                    techniqueID = str(threat['technique'][0]['id'])
                    tactic = str(threat['tactic']['name'])
                    
                    # If the technique ID extracted isn't already in our list,
                    # then create an object and add it to the list 
                    # technique counter is now 1
                    if techniqueID not in ttps:
                        obj = {'technique_id': techniqueID, 'tactic': tactic, 'count': 1}
                        ttps[techniqueID] = obj
                    else:
                        # If the technique was already found, add 1 to the technique's counter
                        # (tallying how many times each unique technique is included)
                        ttps[techniqueID]['count'] += 1
                    
                    # If the string 'subtechnique' is found (meaning a subtechnique is listed)
                    # then extract the subtechnique ID
                    if 'subtechnique' in threat['technique'][0]:
                        subtechID = threat['technique'][0]['subtechnique'][0]['id']

                        if subtechID not in ttps:
                            obj = {'technique_id': subtechID, 'tactic': tactic, 'count': 1}
                            ttps[subtechID] = obj
                        else:
                            # If the subtechnique was already found, add 1 to the subtechnique's counter
                            # (tallying how many times each unique subtechnique is included)
                            ttps[subtechID]['count'] += 1
                        
# Create variables for the beginning and end of the MITRE ATT&CK Navigator JSON file
# These portions of the file shouldn't change, so we can manually add them in
jsonBegin = """
{
	"name": "Custom Detections",
	"versions": {
		"attack": "17",
		"navigator": "5.1.0",
		"layer": "4.5"
	},
	"domain": "enterprise-attack",
	"description": "",
	"filters": {
		"platforms": [
			"Windows",
			"Linux",
			"macOS",
			"Network Devices",
			"ESXi",
			"PRE",
			"Containers",
			"IaaS",
			"SaaS",
			"Office Suite",
			"Identity Provider"
		]
	},
	"sorting": 0,
	"layout": {
		"layout": "side",
		"aggregateFunction": "average",
		"showID": false,
		"showName": true,
		"showAggregateScores": false,
		"countUnscored": false,
		"expandedSubtechniques": "none"
	},
	"hideDisabled": false,
    "techniques": [
"""

jsonEnd = """
],
	"gradient": {
		"colors": [
			"#ff6666ff",
			"#ffe766ff",
			"#8ec843ff"
		],
		"minValue": 0,
		"maxValue": 100
	},
	"legendItems": [],
	"metadata": [],
	"links": [],
	"showTacticRowBackground": false,
	"tacticRowBackground": "#dddddd",
	"selectTechniquesAcrossTactics": true,
	"selectSubtechniquesWithParent": false,
	"selectVisibleTechniques": false
}
"""

# Create a counter variable to track when to stop adding commas
# after the final technique object is written to the JSON file
comCount = 0
totalTTPs = 0

# Iterate through our list of techniques and count how many there are
for item in ttps:
    totalTTPs += 1

# Create an output JSON file
outputPath = "DetEng/metrics/converted_files/mitreNav.json"

# Open our new output file and write it's contents
outFile = open(outputPath, "w")

# Write the contents of the jsonBegin variable to the file 
outFile.write(jsonBegin)

# For every item found in our list of TTPS, add them to the JSON file
for key in ttps:
    # Increase our comma counter (prints commas after each technique is written to file)
    comCount += 1
    techniqueID = ttps[key]['technique_id']
    count = str(ttps[key]['count'])
    tactic = ttps[key]['tactic'].lower() # Force tactic names to lowercase

    # Each technique in the ATT&CK Navigator JSON file must have these fields
    #   "techniqueID": "T1037",
	# 	"tactic": "persistence",
	# 	"score": 10,
	# 	"color": "",
	# 	"comment": "",
	# 	"enabled": true,
	# 	"metadata": [],
	# 	"links": [],
	# 	"showSubtechniques": false
    # So we must write the values of each field for every technique found
    # (\t characters are tabs)
    outFile.write("\n\t\t{")
    outFile.write("\n\t\t\t\"techniqueID\": \"" + techniqueID + "\",")
    outFile.write("\n\t\t\t\"tactic\": \"" + tactic + "\",")
    outFile.write("\n\t\t\t\"score\": " + count + ",")
    outFile.write("\n\t\t\t\"color\": \"\""",")
    outFile.write("\n\t\t\t\"comment\": \"\""",")
    outFile.write("\n\t\t\t\"enabled\": true,")
    outFile.write("\n\t\t\t\"metadata\": [],")
    outFile.write("\n\t\t\t\"links\": [],")
    outFile.write("\n\t\t\t\"showSubtechniques\": false")

    # As long as we haven't reached the end of our technique list,
    # print }, to close the technique before extracting the next one
    if comCount != totalTTPs:
        outFile.write("\n\t\t},")
    else:
        outFile.write("\n\t\t}") # Don't add the comma (list is complete)

# Write the contents of the jsonEnd variable to the file
outFile.write(jsonEnd)
# Close the output file
outFile.close()