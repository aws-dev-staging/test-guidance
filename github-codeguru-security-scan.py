import os
import re
import csv
import json
import time
import boto3
import base64
import requests
from datetime import datetime
from dateutil import tz

# Environment Variables
sns_topic_arn = os.environ.get("SNSTopic")
github_repo = os.environ.get("PrivateGitHubRepo")
github_owner = os.environ.get("PrivateGitHubOwner")
github_username = os.environ.get("PrivateGitHubUsername")
github_email = os.environ.get("PrivateGitHubEmail")
github_token = os.environ.get("PrivateGitHubToken")
region_name = os.environ.get("AWS_REGION")

# Print environment variable values
print("SNSTopic: ", sns_topic_arn)
print("PrivateGitHubRepo: ", github_repo)
print("PrivateGitHubOwner: ", github_owner)
print("PrivateGitHubUsername: ", github_username)
print("PrivateGitHubEmail: ", github_email)
print("PrivateGitHubToken: ", github_token)
print("AWS_REGION: ", region_name)

# Instantiate boto3 clients
try:
    codeguru_security_client = boto3.client('codeguru-security')
    codeartifact_client = boto3.client('codeartifact')
    sns_client = boto3.client('sns')
    codebuild_client = boto3.client('codebuild')
    session = boto3.session.Session()
    secrets_manager_client = session.client(service_name='secretsmanager', region_name=region_name)
except Exception as error:
    print(f"Failed to instantiate boto3 clients: {error}")

# Method to push file to GitHub repo
def put_file_to_github(url, github_token, github_username, github_email, content_base64, commit_message, branch_name, existing_file_sha=None):

    # Define the path to the package file in the repository
    package_path = f"packages/{branch_name}"

    data = {
        "message": commit_message,
        "committer": {
            "name": github_username,
            "email": github_email
        },
        "content": content_base64,
        "branch": branch_name,
        "path": package_path
    }

    if existing_file_sha:
        print("put_file_to_github existing_file_sha = " + str(existing_file_sha))
        data["sha"] = existing_file_sha

    try:
        response = None
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        # Check if the branch exists
        print(f"Checking if the branch '{branch_name}' exists...")
        branch_url = f"https://api.github.com/repos/{github_owner}/{github_repo}/branches/{branch_name}"

        get_branch_response = requests.get(
            branch_url,
            headers=headers
        )

        # Branch does not exist, create it
        if get_branch_response.status_code == 404:
            print(f"Branch '{branch_name}' does not exist. Creating the branch...")

            try:
                # GitHub API endpoint for getting the reference of the default branch
                default_branch = "main"  # Replace with the name of your default branch
                default_branch_url = f"https://api.github.com/repos/{github_owner}/{github_repo}/git/ref/heads/{default_branch}"

                # Headers containing authorization token and specifying API version
                headers = {
                    "Authorization": f"token {github_token}",
                    "Accept": "application/vnd.github.v3+json"
                }

                # Send GET request to retrieve information about the default branch reference
                default_branch_response = requests.get(default_branch_url, headers=headers)
                default_branch_response.raise_for_status()

                # Extract the SHA of the default branch reference
                default_branch_data = default_branch_response.json()
                default_branch_sha = default_branch_data["object"]["sha"]
                print(f"SHA of the latest commit on '{default_branch}' branch: {default_branch_sha}")

                # Create the new branch based on the latest commit SHA
                create_branch_response = requests.post(
                    f"https://api.github.com/repos/{github_owner}/{github_repo}/git/refs",
                    headers=headers,
                    json={
                        "ref": f"refs/heads/{branch_name}",
                        "sha": default_branch_sha  # Specify the SHA of the commit for the new branch
                    }
                )
                create_branch_response.raise_for_status()
                print(f"Branch '{branch_name}' created successfully.")

            except requests.exceptions.RequestException as e:
                print(f"An error occurred: {e}")

        else:
            print(f"Branch '{branch_name}' already exists...")
            branch_info = get_branch_response.json()
            print("\n\nbranch_info = " + str(branch_info))

            if 'commit' in branch_info:
                # Access the 'sha' value from the 'parents' list
                existing_file_sha = branch_info['commit']['parents'][0]['sha']

                if 'commit' in branch_info['commit']:
                    if 'tree' in branch_info['commit']['commit']:
                        if 'sha' in branch_info['commit']['commit']['tree']:
                            print("Tree SHA")
                        else:
                            print("'sha' key does not exist in the 'tree' dictionary")
                    else:
                        print("'tree' key is not a dictionary")
                else:
                    print("'commit' key is not a dictionary")
            else:
                print("'commit' key does not exist")

        try:
            print(f"Pushing file to GitHub branch '{branch_name}'...")
            print("put_file_to_github existing_file_sha = " + str(existing_file_sha))
            response = requests.put(url, headers=headers, json=data)
            print(f"Private internal package '{branch_name}' pushed to matching GitHub branch successfully.")
        
        except requests.exceptions.RequestException as e:
            print(f"Failed to push file to GitHub branch due to an exception: {e}")

    except requests.exceptions.RequestException as e:
        print(f"GitHub exception: {error}")

    finally:
        return response

# Method to format findings for SNS email readability
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

# Method to adjust package name
def sanitize_package_name(name):
    return re.sub(r'[^a-zA-Z0-9-_$:.]', '', name)

def main():
    try:
        # Instantiate boto3 clients
        codeguru_security_client = boto3.client('codeguru-security')
        codeartifact_client = boto3.client('codeartifact')
        sns_client = boto3.client('sns')
        codebuild_client = boto3.client('codebuild')

        # Read CSV file to get external package information
        with open('external-package-request.csv', newline='') as csvfile:
            
            package_reader = csv.reader(csvfile)
            for row in package_reader:

                try:
                    external_package_name, external_package_url = row
                    external_package_name = sanitize_package_name(external_package_name)
                    print(f"Processing package: {external_package_name} from {external_package_url}")

                    # Download external package repository
                    zip_file_name = f"{external_package_name}.zip"
                    download_response = requests.get(external_package_url)
                
                    with open(zip_file_name, "wb") as zip_file:
                        zip_file.write(download_response.content)
                    
                    print("Package downloaded successfully")
                    # Perform CodeGuru Security Scans
                    try:
                        print("Initiating Security Scan for External Package Repository: " + external_package_name)
                        
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

                                    if not has_medium_or_high_severity:
                                        print("No medium or high severities found. Pushing to GitHub repository...")

                                        if github_token:
                                            try:
                                                print("GitHub token found. Attempting to push package to GitHub repository...")
                                                zip_file_name = f"{external_package_name}.zip"

                                                # Load file content
                                                with open(zip_file_name, "rb") as file:
                                                    content = file.read()

                                                # Encode content to base64
                                                content_base64 = base64.b64encode(content).decode('utf-8')

                                                # GitHub repository details
                                                commit_message = "Add private package - " +  zip_file_name
                                                url = f"https://api.github.com/repos/{github_owner}/{github_repo}/contents/packages/{zip_file_name}"

                                                # Send the request to GitHub API
                                                response = put_file_to_github(url, github_token, github_username, github_email, content_base64, commit_message, external_package_name, existing_file_sha)
                                                response_json = response.json()
                                                print("HERE3")
                                                
                                                # Extracting relevant information from the JSON response
                                                commit_message = response_json.get('commit', {}).get('message')
                                                commit_author = response_json.get('commit', {}).get('author', {}).get('name')
                                                commit_date = response_json.get('commit', {}).get('author', {}).get('date')
                                                content = response_json.get('content', {})
                                                file_name = content.get('name')
                                                file_size = content.get('size')
                                                file_download_url = content.get('download_url')

                                                print("HERE4")

                                                # Constructing a meaningful message
                                                message = f"New GitHub private package commit by {commit_author} on {commit_date}: {commit_message}. Uploaded file: {file_name}, Size: {file_size} bytes. Download URL: {file_download_url}"

                                                print("-- SNS Client Publish --")
                                                sns_response = sns_client.publish(
                                                    TopicArn=sns_topic_arn,
                                                    Subject=f"{external_package_name} Package Approved",
                                                    Message=message
                                                )
                                                print("New private package version asset created successfully. An email has been sent to the requestor with additional details.")

                                            except Exception as error:
                                                print(f"Failed to retrieve branch details from GitHub: {error}")

                                    else:
                                        formatted_message = format_findings(get_findings_response["findings"])

                                        # Publish to SNS and capture response
                                        sns_response = sns_client.publish(
                                            TopicArn=sns_topic_arn,
                                            Subject=f"{external_package_name} Security Findings Report",
                                            Message=f"Security findings report for external package repository: {external_package_name}\n\n{formatted_message}"
                                        )
                                        print("Medium or high severities found. An email has been sent to the requestor with additional details.")
                                
                                else:
                                    print("No findings found.")

                    except Exception as error:
                        print(f"Issue performing Amazon CodeGuru Security scan: {error}")

                except Exception as error:
                    print(f"Failed to download package: {error}")

    except Exception as error:
        print(f"Action Failed, reason: {error}")

if __name__ == "__main__":
    main()

