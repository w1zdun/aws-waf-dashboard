
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
import argparse


def getExistingIndexesFromOpenSearch(awsauth, host):
    """
    This function gets the existing web acl ids from the open search indices.
    
    """
    path = '/_cat/indices?format=json'
    url = "https://" + host + path
    r = requests.get(url, auth=awsauth)
    indices_json_details = r.json()
    indices_json = [i["index"].strip() for i in indices_json_details if i["index"].startswith('awswaf-')]
    return indices_json

def deleteAWSWAFindexes(indices_json, awsauth, host):
    """
    This function deletes the indices.
    
    """
    for i in indices_json:
        path = '/' + i.strip()
        url = "https://" + host.strip() + path.strip()
        logging.info("Deleting index: " + url)
        r = requests.delete(url, auth=awsauth)
        logging.info(r.text)

def main():
    #parse arguments from command line
    args = parse_args()

    logger = logging.getLogger(__name__)
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)


    os_endpoint = args.os_endpoint
    service = 'es'
    region = boto3.Session().region_name
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(service=service, region=region, refreshable_credentials=credentials)

    indexes = getExistingIndexesFromOpenSearch(awsauth, os_endpoint)
    deleteAWSWAFindexes(indexes, awsauth, os_endpoint)

    
# function to parse arguments from command line
def parse_args():
    parser = argparse.ArgumentParser(description='Delete AWS WAF Indexes')
    parser.add_argument('--os_endpoint', help='Open Search Endpoint', required=True)
    args = parser.parse_args()
    return args



# main function execution
if __name__ == "__main__":
    # call main function
    main()