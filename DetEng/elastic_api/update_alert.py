# This script uses Elastic's API to edit an existing alert in our Elastic project given the rule's ID
# Documentation can be found here: https://www.elastic.co/docs/api/doc/kibana/operation/operation-updaterule?ztMi28bZRxRHcWR=3KUUIIIHDDW9bqd

import requests
import os
import tomllib

API_KEY = os.getenv('ELASTIC_API')
CHANGED_FILES = str(os.getenv('CHANGED_FILES'))

# Example request
# curl \
#  --request POST 'https://localhost:5601/api/detection_engine/rules' \
#  --header "Authorization: $API_KEY" \
#  --header "Content-Type: application/json" \
#  --data '{"from":"now-70m","name":"MS Office child process","tags":["child process","ms office"],"type":"query","query":"process.parent.name:EXCEL.EXE or process.parent.name:MSPUB.EXE or process.parent.name:OUTLOOK.EXE or process.parent.name:POWERPNT.EXE or process.parent.name:VISIO.EXE or process.parent.name:WINWORD.EXE","enabled":false,"filters":[{"query":{"match":{"event.action":{"type":"phrase","query":"Process Create (rule: ProcessCreate)"}}}}],"rule_id":"process_started_by_ms_office_program","interval":"1h","language":"kuery","severity":"low","risk_score":50,"description":"Process started by MS Office program - possible payload","required_fields":[{"name":"process.parent.name","type":"keyword"}],"related_integrations":[{"package":"o365","version":"^2.3.2"}]}'--data '{"name":"my Elasticsearch query ESQL rule","params":{"size":0,"esqlQuery":{"esql":"FROM kibana_sample_data_logs | KEEP bytes, clientip, host, geo.dest | where geo.dest != \"GB\" | STATS sumbytes = sum(bytes) by clientip, host | WHERE sumbytes \u003e 5000 | SORT sumbytes desc | LIMIT 10"},"threshold":[0],"timeField":"@timestamp","searchType":"esqlQuery","timeWindowSize":1,"timeWindowUnit":"d","thresholdComparator":"\u003e"},"actions":[{"id":"d0db1fe0-78d6-11ee-9177-f7d404c8c945","group":"query matched","params":{"level":"info","message":"Elasticsearch query rule '{{rule.name}}' is active:\n- Value: {{context.value}} - Conditions Met: {{context.conditions}} over {{rule.params.timeWindowSize}}{{rule.params.timeWindowUnit}} - Timestamp: {{context.date}} - Link: {{context.link}}"},"frequency":{"summary":false,"notify_when":"onActiveAlert"}}],"consumer":"stackAlerts","schedule":{"interval":"1d"},"rule_type_id":".es-query"}'

# Set the URL, headers, and alert JSON data to send to Elastic via POST request
url = "https://my-security-project-faf7f0.kb.eu-west-1.aws.elastic.cloud/api/detection_engine/rules"

# The kbn-xsrf header must be included
headers = {
    "Content-Type": "application/json",
    "kbn-xsrf": "true",
    "Authorization": "ApiKey " + API_KEY
}

# Search in the root directory provided, any/all subsdirectories within it and 
# the files found in those directories
for root, dirs, files in os.walk('DetEng/custom_detections'):

    # For every file found, check if it has the .toml extension
    # If it is a toml file, load its contents
    for file in files:

        # Add an extra step: Check if the file is listed in CHANGED_FILES
        # If it is, proceed to validate it and push to Elastic
        if file in CHANGED_FILES:
            print(file)

            # Create a data variable to store the JSON conversion. Initialize it with the beginning {
            data = "{\n"

            if file.endswith(".toml"):
        
                # Programmatically create the full file path for the TOML files
                # by joining the directory and filename together 
                full_path = os.path.join(root, file)
                with open(full_path, "rb") as loadedToml:
                    alert = tomllib.load(loadedToml)

                # Create an array containing the required fields for an alert based on the alert type
                # Alert types = query, eql (evert correlation), threshold
                if alert['rule']['type'] == "query":
                    required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query']
                elif alert['rule']['type']  == "eql":
                    required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'language']
                elif alert['rule']['type']  == "threshold":
                    required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'threshold']
                else:
                    # If an unsupported rule type is found, break the validation loop
                    print("Unsupported rule type found in: " + file)
                    break
                
                # Iterate over each gathered field and check if it's in the list of required fields
                # If so, then convert the format from TOML to JSON depending on the data type of the field
                for field in alert['rule']:
                    if field in required_fields:

                        # If the field's data type is a list, then convert the list into a string, replace
                        # single quotes with double quotes and append it to the JSON formatted data
                        # Appended data should look like: "field_name": ["item1", "item2"],\n
                        if type(alert['rule'][field]) == list:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"

                        # If the field's data type is a string, we convert the field depending on what it's storing
                        # Appended data should look like: "field_name": "field_value",\n
                        elif type(alert['rule'][field]) == str:

                            # For the description field, replace newlines with spaces, escape double quotes using \"
                            # and escape backslashes using \\
                            # Append this to the JSON formatted data
                            if field == 'description':
                                data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"").replace("\\","\\\\") + "\"," + "\n"
                            
                            # For the query field, escape double quotes using \" and escape backslashes using \\
                            # Also replace newlines with spaces
                            # Append this to the JSON formatted data
                            elif field == 'query':
                                data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\\","\\\\").replace("\"","\\\"").replace("\n"," ") + "\"," + "\n"
                            
                            # For all other string fields, replace newlines with spaces, escape double quotes using \"
                            # and escape backslashes using \\
                            # Append this to the JSON formatted data
                            else:
                                data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"") + "\"," + "\n"
                        
                        # If the field's data type is a integer, then convert the int into a string and append this to the JSON formatted data
                        # Appended data should look like: "field_name": 123,\n
                        elif type(alert['rule'][field]) == int:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]) + "," + "\n"

                        # If the field's data type is a dictionary, then convert the dict into a string and replace
                        # single quotes with double quotes
                        # Append this to the JSON formatted data
                        # Appended data should look like: "field_name": {"key": "value"},\n`
                        elif type(alert['rule'][field]) == dict:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
                
                # Append the field 'enabled' to the end of the JSON data and assign it to 'true'
                # (auto enables the newly created rule). Also append the closing } to the end of the file
                data += "  \"enabled\": true\n}"

            # Extract the rule IDs from each alert in the list and append that value to the URL 
            # before submitting the PUT request to Elastic
            ruleID = alert['rule']['rule_id']
            updateUrl = url + "?rule_id=" + ruleID

            # Send the PUT request to Elastic
            elastic_data = requests.put(updateUrl, headers=headers, data=data).json()
            print(elastic_data)

            # If a new TOML file is being sent to Elastic, the Rule ID doesn't exist.
            # Check for a 404 error code in the JSON data and search if a status code is included
            # If a 404 status code is found, change to a POST request rather than a PUT
            for key in elastic_data:
                if key == "status_code":
                    if 404 == elastic_data["status_code"]:
                        elastic_data = requests.post(url, headers=headers, data=data).json()
                        print(elastic_data)