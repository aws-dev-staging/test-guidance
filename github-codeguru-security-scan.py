import os
import csv
import time
import base64
import requests
from github import Github

# Environment Variables
sns_topic_arn = os.environ.get("SNSTopic")
github_repo = os.environ.get("PrivateGitHubRepo")
github_owner = os.environ.get("PrivateGitHubOwner")
github_token = os.environ.get("PrivateGitHubToken")
region_name = os.environ.get("AWS_REGION")

# Instantiate GitHub instance
github = Github(github_token)

# Method to push file to GitHub repo
def push_file_to_github(file_path, branch_name, commit_message, content_base64):
    try:
        repo = github.get_repo(f"{github_owner}/{github_repo}")
        branch = repo.get_branch(branch_name)

        # Get the content of the file if it exists
        try:
            file_content = repo.get_contents(file_path, ref=branch_name)
            existing_file_sha = file_content.sha
            print(f"File '{file_path}' already exists in branch '{branch_name}'")
        except Exception as e:
            existing_file_sha = None
            print(f"File '{file_path}' does not exist in branch '{branch_name}'")

        # Encode content to base64
        encoded_content = base64.b64encode(content_base64.encode('utf-8')).decode('utf-8')

        # Push the file to the repository
        if existing_file_sha:
            # File already exists, update its content
            print("existing_file_sha")
            repo.update_file(file_path, commit_message, encoded_content, existing_file_sha, branch=branch_name)
            print(f"File '{file_path}' updated in branch '{branch_name}'")
        else:
            # File does not exist, create a new one
            print("no existing_file_sha")
            repo.create_file(file_path, commit_message, encoded_content, branch=branch_name)
            print(f"File '{file_path}' created in branch '{branch_name}'")

    except Exception as e:
        print(f"Error pushing file to GitHub: {e}")

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

def main():
    try:
        # Read CSV file to get external package information
        with open('external-package-request.csv', newline='') as csvfile:
            package_reader = csv.reader(csvfile)

            for row in package_reader:
                external_package_name, external_package_url = row
                print(f"Processing package: {external_package_name} from {external_package_url}...")

                # Download external package repository
                zip_file_name = f"{external_package_name}.zip"
                download_response = requests.get(external_package_url)
                
                with open(zip_file_name, "wb") as zip_file:
                    zip_file.write(download_response.content)
                
                print("Package downloaded successfully...")

                # Perform CodeGuru Security Scans
                print("Initiating Security Scan for External Package Repository:", external_package_name)
                create_url_input = {"scanName": external_package_name}
                create_url_response = codeguru_security_client.create_upload_url(**create_url_input)
                url = create_url_response["s3Url"]
                artifact_id = create_url_response["codeArtifactId"]

                print("Uploading External Package Repository File...")
                upload_response = requests.put(url, headers=create_url_response["requestHeaders"], data=open(zip_file_name, "rb"))

                if upload_response.status_code == 200:
                    print("Conducting CodeGuru Security Scans...")
                    
                    scan_input = {
                        "resourceId": {"codeArtifactId": artifact_id},
                        "scanName": external_package_name,
                        "scanType": "Standard",
                        "analysisType": "Security"
                    }
                    create_scan_response = codeguru_security_client.create_scan(**scan_input)
                    run_id = create_scan_response["runId"]

                    print("Retrieving Scan Results...")
                    get_scan_input = {"scanName": external_package_name, "runId": run_id}

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
                        get_findings_input = {"scanName": external_package_name, "maxResults": 20, "status": "Open"}
                        get_findings_response = codeguru_security_client.get_findings(**get_findings_input)
                        
                        if "findings" in get_findings_response:
                            # Check if any finding severity is medium or high
                            has_medium_or_high_severity = any(finding["severity"] in ["Medium", "High"] for finding in get_findings_response["findings"])

                            if not has_medium_or_high_severity:
                                print("No medium or high severities found. Pushing to GitHub repository...")
                                
                                # Prepare content for GitHub commit
                                with open(zip_file_name, "rb") as file:
                                    content = file.read()
                                content_base64 = base64.b64encode(content).decode('utf-8')
                                
                                # Specify the branch name and file path
                                branch_name = "main"
                                file_path = f"packages/{zip_file_name}"
                                commit_message = f"Add private package - {zip_file_name}"
                                
                                # Push the file to GitHub repository
                                push_file_to_github(file_path, branch_name, commit_message, content_base64)

                                print("New private package version asset created successfully.")

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
        print(f"Action Failed, reason: {error}")

if __name__ == "__main__":
    main()
