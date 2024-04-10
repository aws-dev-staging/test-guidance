import os
import time
import boto3
import requests
import csv
import re  # Import the regular expression module
from datetime import datetime
from dateutil import tz
import hashlib

# Environment Variables
codeartifact_domain = os.environ.get("ExampleDomain")
codeartifact_repo = os.environ.get("InternalRepository")
sns_topic_arn = os.environ.get("SNSTopic")

# Print environment variable values
print("CodeArtifact Domain: ", codeartifact_repo)
print("CodeArtifact Repo: ", codeartifact_repo)

def format_findings(findings):
    formatted_message = ""

    for index, finding in enumerate(findings, start=1):
        formatted_message += f"\n{index}. Vulnerability: {finding['title']}\n"
        formatted_message += f"   - Description: {finding['description']}\n"
        formatted_message += f"   - Severity: {finding['severity']}\n"
        formatted_message += f"   - Recommendation: {finding['remediation']['recommendation']['text']}\n"
        formatted_message += f"   - Path: {finding['vulnerability']['filePath']['path']}\n"
        
        reference_urls = finding.get('referenceUrls', [])
        if reference_urls:
            formatted_reference_urls = ', '.join(reference_urls)
        else:
            formatted_reference_urls = 'No reference URLs available'
            
        formatted_message += f"   - Reference URLs: {formatted_reference_urls}\n\n"
        
    return formatted_message

def format_private_package_response(response):

    parsed_response = {
        "format": response.get("format"),
        "namespace": response.get("namespace"),
        "package": response.get("package"),
        "version": response.get("version"),
        "versionRevision": response.get("versionRevision"),
        "status": response.get("status"),
        "asset": {
            "name": response["asset"]["name"],
            "size": response["asset"]["size"],
            "hashes": response["asset"]["hashes"]
        }
    }
    return parsed_response

def main():
    try:
        print("Initiating Security Scan for External Package Repositories")

        # Read CSV file to get external package information
        with open('external-package-request.csv', newline='') as csvfile:
            package_reader = csv.reader(csvfile)

            for row in package_reader:
                try:

                    external_package_name, external_package_url = row
                    external_package_name = re.sub(r'[^\x00-\x7F]+', '', external_package_name) # Remove non-ASCII characters from the package name
                    print(f"\nProcessing package '{external_package_name}' from {external_package_url}")

                    # Download external package repository
                    zip_file_name = f"{external_package_name}.zip"
                    download_response = requests.get(external_package_url)
                
                    with open(zip_file_name, "wb") as zip_file:
                        zip_file.write(download_response.content)                    
                    
                    print("Package downloaded successfully...")

                    # Perform CodeGuru Security Scans
                    try:
                        print("Initiating CodeGuru Security scan...")

                        # Instantiate boto3 clients
                        codeguru_security_client = boto3.client('codeguru-security')
                        codeartifact_client = boto3.client('codeartifact')
                        sns_client = boto3.client('sns')

                        print("Creating CodeGuru Security Upload URL...")

                        create_url_input = {"scanName": external_package_name}
                        create_url_response = codeguru_security_client.create_upload_url(**create_url_input)
                        url = create_url_response["s3Url"]
                        artifact_id = create_url_response["codeArtifactId"]

                        print("Uploading External Package Repository File...")

                        upload_response = requests.put(
                            url,
                            headers=create_url_response["requestHeaders"],
                            data=open(zip_file_name, "rb"),
                        )
                            
                        print("Performing CodeGuru Security and Quality Scans...")
                        
                        scan_input = {
                            "resourceId": {
                                "codeArtifactId": artifact_id,
                            },
                            "scanName": external_package_name,
                            "scanType": "Standard", # Express
                            "analysisType": "Security" # All
                        }
                        create_scan_response = codeguru_security_client.create_scan(**scan_input)
                        run_id = create_scan_response["runId"]

                        print("Retrieving Scan Results...")
                        
                        get_scan_input = {
                            "scanName": external_package_name,
                            "runId": run_id,
                        }

                        while True:
                            get_scan_response = codeguru_security_client.get_scan(**get_scan_input)
                            if get_scan_response["scanState"] == "InProgress":
                                time.sleep(1)
                            else:
                                break

                        if get_scan_response["scanState"] != "Successful":
                            raise Exception(f"CodeGuru Scan {external_package_name} failed")
                        else:

                            print("Analyzing Security and Quality Finding Severities...")

                            get_findings_input = {
                                "scanName": external_package_name,
                                "maxResults": 20,
                                "status": "Open",
                            }

                            get_findings_response = codeguru_security_client.get_findings(**get_findings_input)
                            if "findings" in get_findings_response:
                                # Check if any finding severity is medium or high
                                has_medium_or_high_severity = any(finding["severity"] in ["Medium", "High"] for finding in get_findings_response["findings"])

                                if not has_medium_or_high_severity:
                                    print("No medium or high severities found. Creating new package version asset...")
                                    
                                    # Calculate the SHA256 hash of the asset content
                                    with open(zip_file_name, "rb") as f:
                                        asset_content = f.read()
                                    asset_sha256 = hashlib.sha256(asset_content).hexdigest()

                                    # Publish the package version with CodeArtifact
                                    try:
                                        package_version_response = codeartifact_client.publish_package_version(
                                            domain=codeartifact_domain,
                                            repository=codeartifact_repo,
                                            format="generic",
                                            namespace=external_package_name,
                                            package=external_package_name,
                                            packageVersion=str(int(time.time())),  # Use current timestamp as version
                                            assetName=zip_file_name,
                                            assetContent=asset_content,
                                            assetSHA256=asset_sha256,
                                        )

                                        print("New private package version asset created successfully. An email has been sent to the requestor with additional details.")
                                        formatted_message = format_private_package_response(package_version_response)

                                        # Publish to SNS and capture response
                                        sns_response = sns_client.publish(
                                            TopicArn=sns_topic_arn,
                                            Subject=f"{external_package_name} Package Approved",
                                            Message=f"AWS CodeArtifact private package details: {external_package_name}\n\n{formatted_message}"
                                        )

                                    except Exception as error:
                                        print(f"Failed to publish package version: {error}")
                                else:
                                    print("Medium or high severities found. An email has been sent to the requestor with additional details.")
                                    subject = external_package_name + " Medium to High Severity Findings"
                                    formatted_message = format_findings(get_findings_response["findings"])

                                    # Publish to SNS and capture response
                                    sns_response = sns_client.publish(
                                        TopicArn=sns_topic_arn,
                                        Subject=f"{external_package_name} Security Findings Report",
                                        Message=f"Security findings report for external package repository: {external_package_name}\n\n{formatted_message}"
                                    )
                    except Exception as error:
                        raise Exception(f"Issue performing Amazon CodeGuru Security scan: {error}")

                except Exception as error:
                    raise Exception(f"Failed to download package: {error}")

    except Exception as error:
        print(f"Action Failed, reason: {error}")

if __name__ == "__main__":
    main()
