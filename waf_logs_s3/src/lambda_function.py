import urllib.parse
import boto3
import io
import gzip
import os
import sys
import json
from requests_aws4auth import AWS4Auth
import requests
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
event_client = boto3.client('events')

region = os.environ.get('REGION')
os_endpoint = os.environ.get('OS_ENDPOINT')
update_dashboards = False
number_rows_in_batch = int(os.environ.get('NUMBER_ROWS_IN_BATCH'))


def getExistingWebACLIDsFromOpenSearch(os_endpoint, awsauth):
    """
    This function gets the existing web acl ids from the open search indices.
    
    """
    host = os_endpoint
    path = '/_cat/indices?format=json'


    url = "https://" + host + path
    r = requests.get(url, auth=awsauth)
    indices_json_details = r.json()
    indices_json = [i["index"].strip() for i in indices_json_details if i["index"].startswith('awswaf-') and i["status"] == "open"]
    webaclIdSet = set()
    payload = json.loads('{ "query": { "match_all": {}}, "collapse": { "field": "webaclId.keyword"},"_source": false}')
    for i  in indices_json:
        path = '/' + i.strip() +"/_search"
        url = "https://" + host.strip() + path.strip()
        r = requests.post(url, auth=awsauth, json=payload)
        r_json = r.json()
        for hit in r_json['hits']['hits']:
            webaclIdSet.update(hit['fields']['webaclId.keyword'])

    return webaclIdSet

def sendEventToEventBus():
    """
    This function sends an event to the event bus.
    
    """
    event = {
        "eventSource": ["sink.lambda"],
        "eventName": ["CreateWebACL"]
    }
    try:
        response = event_client.put_events(
            Entries=[
                {
                    'Source': 'sink.s3',
                    'DetailType': 'S3 Sink',
                    'Detail': json.dumps(event),
                    'EventBusName': 'default'  
                },
            ]
        ) 
    except Exception as e:
        print(e)
        raise e
    
    logger.info("Event sent to event bus successfully")


def bulkPutRecordsToOpenSearch(os_endpoint, awsauth, records, index_name):
    """
    This function puts a batch of records to the open search index.
    
    """
    host = os_endpoint
    path = '/'+ index_name.strip() + '/_bulk'
    url = "https://" + host + path
  
    try:
        #headers={'Content-Type': 'application/json'}
        headers = {'Accept-Encoding': 'gzip', 'Content-Type': 'application/json', 'Content-Encoding': 'gzip'}
        #data=records.encode('utf-8')
        data=gzip.compress(records.encode('utf-8'))

        r = requests.post(url, auth=awsauth, data=records.encode('utf-8'), headers=headers)
        logger.info("Response status code: %s", r.status_code)
    except Exception as e:
        logger.exception("Exception occurred while posting records to OpenSearch: %s", e)
        raise e



def lambda_handler(event, context):
    """
    This function gets the WAF ACL logs in .log.gz from the S3 bucket and pushes it to the Kinesis Data Stream.
    
    """
    update_dashboards = False
    service = 'es'
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(service=service, region=region, refreshable_credentials=credentials)
    webaclIdSet = getExistingWebACLIDsFromOpenSearch(os_endpoint, awsauth)
    index_name = 'awswaf-' + datetime.now().strftime("%Y-%m-%d")   

    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        content = response['Body'].read()
        fobj=io.BytesIO(content)
        l_cnt = 0
        records = ""
        with gzip.open(fobj, mode='rt') as fh:
            lines = fh.readlines()
            for l in lines:
                l_cnt += 1
                # detect only first new web acl id and update dashboards
                if update_dashboards == False:
                    l_json = json.loads(l)
                    if l_json['webaclId'] not in webaclIdSet:
                        logger.info("New web acl id detected")
                        update_dashboards = True
                records += '{"index": {}}\n' + l.strip() + '\n' 
                if l_cnt % number_rows_in_batch == 0:
                    bulkPutRecordsToOpenSearch(os_endpoint, awsauth, records, index_name)
                    records = ""
                    logger.info("Processed %s lines", l_cnt)

        if records != "":
            bulkPutRecordsToOpenSearch(os_endpoint, awsauth, records, index_name)
            records = ""
            
        logger.info("All records processed: %s", l_cnt)

        if update_dashboards == True:
            sendEventToEventBus()
 
    except Exception as e:
        logger.exception("Exception occurred while processing the file: %s", e)
        raise e