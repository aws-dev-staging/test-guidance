import os
import re
import csv
import time
import boto3
import requests
import subprocess
from datetime import datetime
from dateutil import tz

# Environment Variables
sns_topic_arn = os.environ.get("SNSTopic")
github_token = os.environ.get("PrivateGitHubToken")  # GitHub personal access token
github_repo = os.environ.get("PrivateGitHubRepo")  # GitHub repository name

# Function to fetch GitHub personal access token from Secrets Manager
def get_github_token():
    secret_name = "YourSecretName"
    region_name = "YourRegion"

    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)

    try:
        response = client.get_secret_value(SecretId=secret_name)
        secret = response['SecretString']
        github_token = json.loads(secret)['github_token']
        return github_token
    except Exception as e:
        print(f"Error fetching GitHub token from Secrets Manager: {e}")
        return None

# Function to execute shell commands
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return None

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

def sanitize_package_name(name):
    return re.sub(r'[^a-zA-Z0-9-_$:.]', '', name)

def main():
    approved_packages = []
    
    try:
        print("Initiating Security Scan for External Package Repositories")

        # Instantiate boto3 clients
        codeguru_security_client = boto3.client('codeguru-security')

        # Read CSV file to get external package information
        with open('external-package-request.csv', newline='') as csvfile:
            package_reader = csv.reader(csvfile)
            for row in package_reader:
                external_package_name, external_package_url = row
                external_package_name = sanitize_package_name(external_package_name)
                print(f"Processing package: {external_package_name} from {external_package_url}")

                # Download external package repository
                zip_file_name = f"{external_package_name}.zip"
                download_response = requests.get(external_package_url)
                if download_response.status_code == 200:
                    with open(zip_file_name, "wb") as zip_file:
                        zip_file.write(download_response.content)
                    
                    print("Package downloaded successfully")
                    # Perform CodeGuru Security Scans
                    try:
                        print("Initiating Security Scan for External Package Repository: " + external_package_name)

                        # Instantiate boto3 clients
                        codeguru_security_client = boto3.client('codeguru-security')
                        codeartifact_client = boto3.client('codeartifact')
                        sns_client = boto3.client('sns')
                        codebuild_client = boto3.client('codebuild')

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

                        if upload_response.status_code == 200:
                            
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

                                    # If the package passes the security checks, add it to the approved_packages list
                                    if not has_medium_or_high_severity:
                                        print("No medium or high severities found. Pushing to GitHub repository...")
                                        approved_packages.append(external_package_name)

                                        # Fetch GitHub personal access token from Secrets Manager
                                        github_token = get_github_token()
                                        headers = {"Authorization": f"token {github_token}"}

                                        # Logic to push the package file to a GitHub repository           
                                        for approved_package in approved_packages:
                                            if github_token:
                                                # Configure Git with the retrieved token
                                                run_command(f"git config --global user.name 'YourGitHubUsername'")
                                                run_command(f"git config --global user.email 'your-email@example.com'")
                                                run_command(f"git config --global credential.helper '!aws codebuild --profile YourAWSProfile secrets-manager get-secret-value --secret-id YourSecretId --query SecretString --output text | jq -r .github_token'")

                                                # Add, commit, and push changes to GitHub repository
                                                run_command("git add .")
                                                run_command("git commit -m 'CodeBuild project update'")
                                                run_command("git push origin master")  # Change 'master' to your branch name if needed
                                            else:
                                                print("GitHub personal access token not found in Secrets Manager.")

                                            zip_file_name = f"{approved_package}.zip"
                                            files = {"file": open(zip_file_name, "rb")}
                                            response = requests.post(f"https://api.github.com/repos/{github_repo}/contents/{zip_file_name}", headers=headers, files=files)

                                            if response.status_code == 201:
                                                print(f"Package file {approved_package} pushed to GitHub repository successfully.")
                                            else:
                                                print(f"Failed to push package file {approved_package} to GitHub repository with status code {response.status_code}.")
                                    else:
                                        print("Medium or high severities found. An email has been sent to the requestor with additional details.")
                                        subject = external_package_name + " Medium to High Severity Findings"
                                        formatted_message = format_findings(get_findings_response["findings"])

                                        sns_client.publish(
                                            TopicArn=sns_topic_arn,
                                            Subject=f"{external_package_name} Security Findings Report",
                                            Message=f"Security Findings Report for External Package Repository: {external_package_name}\n\n{formatted_message}"
                                        )
                        else:
                            raise Exception(f"Source failed to upload external package to CodeGuru Security with status {upload_response.status_code}")
                    except Exception as error:
                        print(f"Action Failed, reason: {error}")
                    
                    # End CodeGuru Security scan block

                else:
                    print(f"Failed to download package from {external_package_url}")

    except Exception as error:
        print(f"Action Failed, reason: {error}")

if __name__ == "__main__":
    main()