# This script uses Elastic's API to create a new detection alert in our Elastic project 
# Documentation can be found here: https://www.elastic.co/docs/api/doc/kibana/operation/operation-createrule?ztMi28bZRxRHcWR=3KUUIIIHDDW9bqd

import requests
import os

API_KEY = os.getenv('ELASTIC_API')

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

# Example alert data provided by Elastic
data = """
{
  "from": "now-70m",
  "name": "MS Office child process",
  "tags": [
    "child process",
    "ms office"
  ],
  "type": "query",
  "query": "process.parent.name:EXCEL.EXE or process.parent.name:MSPUB.EXE or process.parent.name:OUTLOOK.EXE or process.parent.name:POWERPNT.EXE or process.parent.name:VISIO.EXE or process.parent.name:WINWORD.EXE",
  "enabled": false,
  "filters": [
    {
      "query": {
        "match": {
          "event.action": {
            "type": "phrase",
            "query": "Process Create (rule: ProcessCreate)"
          }
        }
      }
    }
  ],
  "rule_id": "process_started_by_ms_office_program",
  "interval": "1h",
  "language": "kuery",
  "severity": "low",
  "risk_score": 50,
  "description": "Process started by MS Office program - possible payload",
  "required_fields": [
    {
      "name": "process.parent.name",
      "type": "keyword"
    }
  ],
  "related_integrations": [
    {
      "package": "o365",
      "version": "^2.3.2"
    }
  ]
}
"""

# Send the POST request to Elastic
elastic_data = requests.post(url, headers=headers, data=data).json()
