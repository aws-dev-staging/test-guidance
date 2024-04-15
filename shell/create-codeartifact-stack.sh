# If not already forked, fork the remote repository (https://github.com/aws-solutions-library-samples/guidance-for-secure-access-to-external-package-repositories-on-aws.git) and change working directory to shell folder
# cd guidance-for-secure-access-to-external-package-repositories-on-aws/shell/
# chmod u+x create-codeartifact-stack.sh
# source ./create-codeartifact-stack.sh

export UNIQUE_IDENTIFIER=$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-' | cut -c 1-5)
export PRIVATE_GITHUB_TOKEN_SECRET_NAME=$(aws secretsmanager create-secret --name $STACK_NAME-$UNIQUE_IDENTIFIER-git-pat --secret-string $PRIVATE_GITHUB_PAT --region $AWS_REGION --query Name --output text)
export ACCOUNT_ID=$(aws sts get-caller-identity --region $AWS_REGION --query Account --output text)
export S3_ARTIFACTS_BUCKET_NAME=$STACK_NAME-codeartifact-$UNIQUE_IDENTIFIER

aws s3 mb s3://$S3_ARTIFACTS_BUCKET_NAME --region $AWS_REGION

aws cloudformation create-stack \
--stack-name $STACK_NAME \
--template-body file://../cfn/codeartifact-private-repo.yaml \
--parameters \
ParameterKey=S3ArtifactsBucket,ParameterValue=$S3_ARTIFACTS_BUCKET_NAME \
ParameterKey=CodePipelineName,ParameterValue=$CODEPIPELINE_NAME \
ParameterKey=SNSEmail,ParameterValue=$SNS_EMAIL \
ParameterKey=PrivateGitHubBranch,ParameterValue=$PRIVATE_GITHUB_BRANCH \
ParameterKey=PrivateGitHubOwner,ParameterValue=$PRIVATE_GITHUB_OWNER \
ParameterKey=PrivateGitHubRepo,ParameterValue=$PRIVATE_GITHUB_REPO \
ParameterKey=PrivateGitHubToken,ParameterValue=$PRIVATE_GITHUB_TOKEN_SECRET_NAME \
ParameterKey=CodeServicesVpc,ParameterValue=$CODESERVICES_VPC_ID \
ParameterKey=CodeServicesSubnet,ParameterValue=$CODESERVICES_SUBNET_ID1\\,$CODESERVICES_SUBNET_ID2 \
--capabilities CAPABILITY_IAM \
--region $AWS_REGION

# --role-arn arn:aws:iam::991639198278:role/Guidance-CloudFormation-Role

# You can track the CloudFormation stack deployment status in AWS CloudFormation console or in your terminal with the following commands:
aws cloudformation describe-stacks --stack-name $STACK_NAME --region $AWS_REGION --query "Stacks[0].StackStatus"
aws cloudformation wait stack-create-complete --stack-name $STACK_NAME --region $AWS_REGION
aws cloudformation describe-stacks --stack-name $STACK_NAME --region $AWS_REGION --query "Stacks[0].StackStatus"
# After a successful stack deployment, the status changes from `CREATE_IN_PROGRESS` to `CREATE_COMPLETE`.