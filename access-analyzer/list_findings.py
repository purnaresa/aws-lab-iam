import boto3
import json
import csv
import configparser

# Create an AWS Access Analyzer client
access_analyzer_client = boto3.client('accessanalyzer')

# Read the analyzer ARN from the configuration file
config = configparser.ConfigParser()
config.read('config.ini')
analyzer_arn = config.get('access_analyzer', 'analyzer_arn')

# Open a CSV file for writing
with open('findings.csv', 'w', newline='') as csvfile:
    fieldnames = ['id', 'resource', 'resourceType', 'status', 'findingType']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    # Write the header row
    writer.writeheader()

    # Initialize the nextToken to None
    next_token = None

    while True:
        # Call the list-findings-v2 command
        if next_token:
            response = access_analyzer_client.list_findings_v2(
                analyzerArn=analyzer_arn,
                maxResults=100,
                nextToken=next_token
            )
        else:
            response = access_analyzer_client.list_findings_v2(
                analyzerArn=analyzer_arn,
                maxResults=100
            )

        # Parse the response
        findings = response['findings']

        # Write each finding to the CSV file
        for finding in findings:
            writer.writerow({
                'id': finding['id'],
                'resource': finding['resource'],
                'resourceType': finding['resourceType'],
                'status': finding['status'],
                'findingType': finding['findingType']
            })

        # Check if there are more pages
        next_token = response.get('nextToken')
        if not next_token:
            break
