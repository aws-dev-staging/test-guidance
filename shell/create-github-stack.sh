# If not already forked, fork the remote repository (https://github.com/aws-samples/sagemaker-external-repository-security.git) and change working directory to shell folder
# cd sagemaker-external-repository-security/shell/
# chmod u+x create-github-stack.sh
# source ./create-github-stack.sh

export GITHUB_TOKEN_SECRET_NAME=$(aws secretsmanager create-secret --name $STACK_NAME-git-pat --secret-string $GITHUB_PAT --query Name --output text)
export GITHUB_EMAIL_SECRET_NAME=$(aws secretsmanager create-secret --name $STACK_NAME-git-email --secret-string $GITHUB_EMAIL  --query Name --output text)
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export S3_ARTIFACT_BUCKET_NAME=${STACK_NAME}-${ACCOUNT_ID}

aws s3 mb s3://${S3_ARTIFACT_BUCKET_NAME} --region us-east-1

aws cloudformation create-stack \
--stack-name ${STACK_NAME} \
--template-body file://../cfn/external-repo-github.yaml \
--parameters \
ParameterKey=ArtifactStoreBucket,ParameterValue=${S3_ARTIFACT_BUCKET_NAME} \
ParameterKey=CodePipelineName,ParameterValue=${CODEPIPELINE_NAME} \
ParameterKey=GitHubBranch,ParameterValue=${GITHUB_BRANCH} \
ParameterKey=GitHubOwner,ParameterValue=${GITHUB_OWNER} \
ParameterKey=GitHubRepo,ParameterValue=${GITHUB_REPO} \
ParameterKey=GitHubUser,ParameterValue=${GITHUB_USER} \
ParameterKey=GitHubToken,ParameterValue=${GITHUB_TOKEN_SECRET_NAME} \
ParameterKey=GitHubEmail,ParameterValue=${GITHUB_EMAIL_SECRET_NAME} \
ParameterKey=PublicGitHubUrl,ParameterValue=${PUBLIC_GITHUB_URL} \
ParameterKey=PrivateGitHubUrl,ParameterValue=${PRIVATE_GITHUB_URL} \
ParameterKey=CodeBuildLambdaVpc,ParameterValue=${CODEBUILD_VPC_ID} \
ParameterKey=CodeBuildLambdaSubnet,ParameterValue=${CODEBUILD_SUBNET_ID1}\\,${CODEBUILD_SUBNET_ID2} \
--capabilities CAPABILITY_IAM

aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].StackStatus"
aws cloudformation wait stack-create-complete --stack-name $STACK_NAME
