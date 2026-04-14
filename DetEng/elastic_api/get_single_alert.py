# This script queries our Elastic project and prints the contents of a single alert based on the given alert ID

import requests
import os

API_KEY = os.getenv('ELASTIC_API')

# curl \
#  --request GET 'https://localhost:5601/api/alerting/rule/{id}' \
#  --header "Authorization: $API_KEY"

# RuleID taken from an existing rule within the Elastic project
ruleID = "5b0041ef-fe25-4a67-9c1b-b9598eee0eb2"

url = "https://my-security-project-faf7f0.kb.eu-west-1.aws.elastic.cloud/api/alerting/rule/" + ruleID
headers = {
    "Authorization": "ApiKey " + API_KEY
}
elastic_data = requests.get(url, headers=headers).json()
print(elastic_data)
