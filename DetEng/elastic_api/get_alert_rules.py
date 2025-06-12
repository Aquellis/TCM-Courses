# This script queries our Elastic project and prints the contents of all alert rules

import requests
import os

API_KEY = os.getenv('ELASTIC_API')

# curl \
#  --request GET 'https://localhost:5601/api/alerting/rules/_find' \
#  --header "Authorization: $API_KEY"

url = "https://my-security-project-faf7f0.kb.eu-west-1.aws.elastic.cloud/api/alerting/rules/_find"
headers = {
    "Authorization": "ApiKey " + API_KEY
}
elastic_data = requests.get(url, headers=headers).json()
print(elastic_data)
