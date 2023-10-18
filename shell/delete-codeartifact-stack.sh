# cd sagemaker-external-repository-security/shell/
# chmod u+x delete-codeartifact-stack.sh
# ./delete-codeartifact-stack.sh

echo "Deleting CloudFormation Stack: $STACK_NAME"
echo "Deleting Secrets Manager Secret: $GITHUB_TOKEN_SECRET_NAME"
echo "Emptying and Deleting S3 Bucket: $S3_ARTIFACT_BUCKET_NAME"

aws s3 rm s3://${S3_ARTIFACT_BUCKET_NAME} --recursive
aws s3 rb s3://${S3_ARTIFACT_BUCKET_NAME}

aws cloudformation delete-stack --stack-name $STACK_NAME
aws cloudformation wait stack-delete-complete --stack-name $STACK_NAME

aws secretsmanager delete-secret --secret-id $GITHUB_TOKEN_SECRET_NAME
