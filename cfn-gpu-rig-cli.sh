#!/bin/bash -e
# debug options include -v -x
# cfn-gpu-rig-cli.sh 
# A hardened, hightly available, cloud gaming Windows
# server cloudformation template composition.


#!! COMMENT Construct Begins Here:
: <<'END'
#!! COMMENT BEGIN

#!! COMMENT END
END
#!! COMMENT Construct Ends Here:


#-----------------------------
# Record Script Start Execution Time
TIME_START_PROJ=$(date +%s)
TIME_STAMP_PROJ=$(date "+%Y-%m-%d %Hh%Mm%Ss")
echo "The Time Stamp ................................: $TIME_STAMP_PROJ"
#.............................

#-----------------------------
# Request Named Profile
AWS_PROFILE="default"
while true
do
  # -e : stdin from terminal
  # -r : backslash not an escape character
  # -p : prompt on stderr
  # -i : use default buffer val
  read -er -i "$AWS_PROFILE" -p "Enter Project AWS CLI Named Profile ...........: " USER_INPUT
  if aws configure list-profiles 2>/dev/null | grep -qw -- "$USER_INPUT"
  then
    echo "Project AWS CLI Named Profile is valid ........: $USER_INPUT"
    AWS_PROFILE=$USER_INPUT
    break
  else
    echo "Error! Project AWS CLI Named Profile invalid ..: $USER_INPUT"
  fi
done
#.............................

#-----------------------------
# Request Region
AWS_REGION=$(aws configure get region --profile "$AWS_PROFILE")
while true
do
  # -e : stdin from terminal
  # -r : backslash not an escape character
  # -p : prompt on stderr
  # -i : use default buffer val
  read -er -i "$AWS_REGION" -p "Enter Project AWS CLI Region ..................: " USER_INPUT
  if aws ec2 describe-regions --profile "$AWS_PROFILE" --query 'Regions[].RegionName' --output text 2>/dev/null | grep -qw -- "$USER_INPUT"
  then
    echo "Project AWS CLI Region is valid ...............: $USER_INPUT"
    AWS_REGION=$USER_INPUT
    break
  else
    echo "Error! Project AWS CLI Region is invalid ......: $USER_INPUT"
  fi
done
#.............................

#-----------------------------
# Request Project Name
PROJECT_NAME="cfn-gpu-rig-cli"
while true
do
  # -e : stdin from terminal
  # -r : backslash not an escape character
  # -p : prompt on stderr
  # -i : use default buffer val
  read -er -i "$PROJECT_NAME" -p "Enter the Name of this Project ................: " USER_INPUT
  if [[ "${USER_INPUT:=$PROJECT_NAME}" =~ (^[a-z0-9]([a-z0-9-]*(\.[a-z0-9])?)*$) ]]
  then
    echo "Project Name is valid .........................: $USER_INPUT"
    PROJECT_NAME=$USER_INPUT
    # Doc Store for this project
    PROJECT_BUCKET="proj-${PROJECT_NAME}"
    break
  else
    echo "Error! Project Name must be S3 Compatible .....: $USER_INPUT"
  fi
done
#.............................

#-----------------------------
# Request Email Address
USER_EMAIL="dh.info@posteo.net"
while true
do
  # -e : stdin from terminal
  # -r : backslash not an escape character
  # -p : prompt on stderr
  # -i : use default buffer val
  read -er -i "$USER_EMAIL" -p "Enter Email Address for SNS Notification ......: " USER_INPUT
  if [[ "${USER_INPUT:=$USER_EMAIL}" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$ ]]
  then
    echo "Email address is valid ........................: $USER_INPUT"
    USER_EMAIL=$USER_INPUT
    break
  else
    echo "Error! Entered Email address is invalid .......: $USER_INPUT"
  fi
done
#.............................

#-----------------------------
# Request Domain Name
AWS_DOMAIN_NAME="cloudemprise.net"
while true
do
  # -e : stdin from terminal
  # -r : backslash not an escape character
  # -p : prompt on stderr
  # -i : use default buffer val
  read -er -i "$AWS_DOMAIN_NAME" -p "Enter Domain Name Static Website ..............: " USER_INPUT
  if [[ "${USER_INPUT:=$AWS_DOMAIN_NAME}" =~ (^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}$) ]]
  then
    echo "Domain Name Static Website is valid ...........: $USER_INPUT"
    AWS_DOMAIN_NAME=$USER_INPUT
    break
  else
    echo "Error! Domain Name must be S3 Compatible ......: $USER_INPUT"
  fi
done
#.............................

#-----------------------------
# Get Route 53 Domain hosted zone ID
HOSTED_ZONE_ID=$(aws route53 list-hosted-zones-by-name --dns-name "$AWS_DOMAIN_NAME" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --query "HostedZones[].Id" --output text | awk -F "/" '{print $3}')
[[ -z "$HOSTED_ZONE_ID" ]] \
    && { echo "Invalid Hosted Zone!"; exit 1; } \
    || { echo "Route53 Hosted Zone ID ........................: $HOSTED_ZONE_ID"; }
#.............................

#-----------------------------
# Stipulate fully qualified domain name 
echo "FQDN Gaming Server ............................: ${PROJECT_NAME}.${AWS_DOMAIN_NAME}:3389"
#.............................

#-----------------------------
# Variable Creation
#-----------------------------
# Name given to Cloudformation Stack
STACK_NAME="$PROJECT_NAME-stack"
echo "The Stack Name ................................: $STACK_NAME"
# Get Account(ROOT) ID
AWS_ACC_ID=$(aws sts get-caller-identity --query Account --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
echo "The Root Account ID ...........................: $AWS_ACC_ID"
# Console Admin profile userid
#AWS_USER_ADMIN="user.admin.console"
AWS_USER_ADMIN="usr.console.admin"
AWS_USERID_ADMIN=$(aws iam get-user --user-name "$AWS_USER_ADMIN" --query User.UserId --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
echo "The Console Admin userid ......................: $AWS_USERID_ADMIN"
# CLI profile userid
AWS_USERID_CLI=$(aws sts get-caller-identity --query UserId --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
echo "The Script Caller userid ......................: $AWS_USERID_CLI"
#-----------------------------
# Script caller IP CIDR for SSH Bastion Host
SSH_ACCESS_CIDR="$(curl -s https://checkip.amazonaws.com/)/32"
echo "The Script Caller IP CIDR  ....................: $SSH_ACCESS_CIDR"
# Grab the latest AMI
AMI_NAME="/aws/service/ami-windows-latest/Windows_Server-2019-English-Full-Base"
AMI_LATEST=$(aws ssm get-parameters --output text --names "$AMI_NAME" \
    --query 'Parameters[0].[Value]' --profile "$AWS_PROFILE" --region "$AWS_REGION")
echo "The lastest AMI ...............................: $AMI_LATEST"
#.............................




#-----------------------------
# Check if SSM UpdateWindowsAmi is required
# USER_INPUT=valid AMI_ID bypass SSM UpdateWindowsAmi
# USER_INPUT=Execute to perform UpdateWindowsAmi 
AMI_UPDATE="Execute"
while true
do
  # -e : stdin from terminal
  # -r : backslash not an escape character
  # -p : prompt on stderr
  # -i : use default buffer val
  read -er -i "$AMI_UPDATE" -p "Enter PreUpdated SSM AMI ID or Execute ........: " USER_INPUT
  #-----------------------------
  if aws ec2 describe-images --owners self --query 'Images[].ImageId' --output text --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null | grep -qw -- "$USER_INPUT"
  then
    # A valid AMI ID was found. SSM UpdateWindowsAmi not needed
    AMI_UPDATE="$USER_INPUT"
    echo "PreUpdated SSM AMI ID is valid ................: $AMI_UPDATE"
    AMI_LATEST="$AMI_UPDATE"
    break
  #-----------------------------
  elif [[ "$USER_INPUT" == "$AMI_UPDATE" ]]; then
    # Execute SSM UpdateWindowsAmi Document
    echo "Will now perform SSM Update on the Latest AMI .: $AMI_LATEST"

      #-----------------------------
      # Execute Automation Document to Update AMI
      SSM_AUTO_DOC="AWS-UpdateWindowsAmi"
      EC2_PROFILE="role.ec2-usr-pwr"
      #SSM_SERVICE_ROLE="arn:aws:iam::${AWS_ACC_ID}:role/AutomationServiceRole"
      SSM_SERVICE_ROLE="arn:aws:iam::311674589786:role/role.ssm-automation.eu-central-1"
      #-----------------------------
      COMMAND_ID=$(aws ssm start-automation-execution --document-name="$SSM_AUTO_DOC" --output text --parameters \
        SourceAmiId="$AMI_LATEST",IamInstanceProfileName="$EC2_PROFILE",AutomationAssumeRole="$SSM_SERVICE_ROLE" \
        --query "AutomationExecutionId" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
        --tags Key=Name,Value=cfn-gpu-rig-cli-ami-update)
      #-----------------------------
      if [[ $? -eq 0 ]]; then
        echo "SSM Automation Execution Command ID ...........: $COMMAND_ID"
        CHECK_STATUS=$(aws ssm describe-automation-executions --filter "Key=ExecutionId,Values=$COMMAND_ID" --output text \
            --query "AutomationExecutionMetadataList[].AutomationExecutionStatus" --profile "$AWS_PROFILE" --region "$AWS_REGION")
        echo "SSM Automation Execution Status ...............: $CHECK_STATUS"
        while [[ $CHECK_STATUS == "InProgress" ]]
        do
            printf '.'
            sleep 10
            CHECK_STATUS=$(aws ssm describe-automation-executions --filter "Key=ExecutionId,Values=$COMMAND_ID" --output text \
            --query "AutomationExecutionMetadataList[].AutomationExecutionStatus" --profile "$AWS_PROFILE" --region "$AWS_REGION")
        done
        printf '\n'
        [[ $CHECK_STATUS == "Failed" ]] && { echo "SSM Failed to Execute Auto Update AMI .........: $COMMAND_ID"; exit 1; } \
        || { echo "SSM Automation Execution Status ...............: $CHECK_STATUS"; }
      fi
      #-----------------------------
      # Grab the resultant UpdateWindowsAmi AMI ID
      if [[ $CHECK_STATUS == "Success" ]]; then
        AMI_UPDATE=$(aws ssm describe-automation-executions --filter "Key=ExecutionId,Values=$COMMAND_ID" --output text \
          --query 'AutomationExecutionMetadataList[].Outputs.["CreateImage.ImageId"]' --profile "$AWS_PROFILE" --region "$AWS_REGION")
        echo "SSM Automation Updated AMI ....................: $AMI_UPDATE"
        #-----------------------------
        # Give AMI a Name Tag
        aws ec2 create-tags --resources "$AMI_UPDATE" --tags Key=Name,Value="${PROJECT_NAME}-ssm-update" \
          --profile "$AWS_PROFILE" --region "$AWS_REGION"
        #.............................
        AMI_LATEST="$AMI_UPDATE"
      else 
        echo "SSM Automation Update NOT Successful ..........: $CHECK_STATUS"
        exit 1
      fi
      #.............................

    break
  #-----------------------------
  else
    # Input not understood. Try again.
    echo "A Valid AMI was not found, try again ..........: $USER_INPUT"
  fi
done
#.............................




#----------------------------------------------
# Create S3 Bucket Policies from local templates
find -L ./policies/s3-buckets/template-proj* -type f -print0 |
  while IFS= read -r -d '' TEMPLATE
  do
    if [[ ! -s "$TEMPLATE" ]]; then
      echo "Invalid Template Stack Policy .................: $TEMPLATE"
      exit 1
    else
      # Copy/Rename template via parameter expansion
      cp "$TEMPLATE" "${TEMPLATE//template/$PROJECT_NAME}"
      # Replace appropriate variables
      sed -i "s/ProjectBucket/$PROJECT_BUCKET/" "$_"
      sed -i "s/RootAccount/$AWS_ACC_ID/" "$_"
      sed -i "s/ConsoleAdmin/$AWS_USERID_ADMIN/" "$_"
      sed -i "s/ScriptCallerUserId/$AWS_USERID_CLI/" "$_"
      echo "Creating S3 Bucket Policy .....................: $_"
    fi
  done
#.............................

#----------------------------------------------
# Create Cloudformation Stack Policies from local templates
find -L ./policies/cfn-stacks/template* -type f -print0 |
# -L : Follow symbolic links
  while IFS= read -r -d '' TEMPLATE
  do
    if [[ ! -s "$TEMPLATE" ]]; then
      echo "Invalid Template Stack Policy .................: $TEMPLATE"
      exit 1
    else
      # Copy/Rename template via parameter expansion
      cp "$TEMPLATE" "${TEMPLATE//template/$PROJECT_NAME}"
      echo "Creating Cloudformation Stack Policy ..........: $_"
    fi
  done
#.............................

#----------------------------------------------
# Create IAM inline Resource Policies from local templates
find -L ./policies/ec2-role/template* -type f -print0 |
# -L : Follow symbolic links
  while IFS= read -r -d '' TEMPLATE
  do
    if [[ ! -s "$TEMPLATE" ]]; then
      echo "Invalid Template Stack Policy .................: $TEMPLATE"
      exit 1
    else
      # Copy/Rename template via parameter expansion
      cp "$TEMPLATE" "${TEMPLATE//template/$PROJECT_NAME}"
      # Replace appropriate variables
      sed -i "s/ProjectBucket/$PROJECT_BUCKET/" "$_"
      sed -i "s/ProjectName/$PROJECT_NAME/" "$_"
      sed -i "s/Region/$AWS_REGION/" "$_"
      echo "Creating IAM inline Resource Policy ...........: $_"
    fi
  done
#.............................

#-----------------------------
# Stringify json Resource Inline Policies for awscli command input
ASSUME_ROLE_POLICY=$(tr -d " \t\n\r" < ./policies/ec2-role/assume-role-policy.json)
PRIV_SSM_EC2_POLICY=$(tr -d " \t\n\r" < ./policies/ec2-role/${PROJECT_NAME}-priv-ssm-access-policy.json)
PRIV_S3_EC2_POLICY=$(tr -d " \t\n\r" < ./policies/ec2-role/${PROJECT_NAME}-priv-s3-access-policy.json)
PUB_S3_EC2_POLICY=$(tr -d " \t\n\r" < ./policies/ec2-role/${PROJECT_NAME}-pub-s3-access-policy.json)
LT_S3_EC2_POLICY=$(tr -d " \t\n\r" < ./policies/ec2-role/${PROJECT_NAME}-lt-s3-access-policy.json)
# similar method using jq (preservers whitespace)
# jq '.' policy.json | jq -sR '.'

#-----------------------------
# Create EC2 Instance Profiles & IAM Role Polices for 
# Public, Private & Launch Templates
#-----------------------------
for PREFIX in PRIV PUB LT; do
  # --- Create (variable) IAM Role Name = Instance Profile Name
  declare "$PREFIX"_EC2_IAM_NAME="${PROJECT_NAME}"-"${PREFIX,,}"-iam-ec2-"${AWS_REGION}"
  VAR_NAME="$PREFIX"_EC2_IAM_NAME
  echo "Creating EC2 IAM Instance Profile .............: ${!VAR_NAME}"

  #--- Create EC2 Instance Profile
  declare "$PREFIX"_EC2_PROFILE_ID="$(aws iam create-instance-profile --output text \
      --instance-profile-name "${!VAR_NAME}"                                        \
      --query 'InstanceProfile.InstanceProfileId' --profile "$AWS_PROFILE" --region "$AWS_REGION")"
  VAR_PROFILE_ID="$PREFIX"_EC2_PROFILE_ID
  echo "The EC2 Instance Profile userid ...............: ${!VAR_PROFILE_ID}"
  # --- Create IAM Role
  echo "Creating Complementary EC2 IAM Role ...........: ${!VAR_NAME}"
  declare "$PREFIX"_EC2_ROLE_ID="$(aws iam create-role --role-name "${!VAR_NAME}" \
      --assume-role-policy-document "$ASSUME_ROLE_POLICY"                         \
      --output text --query 'Role.RoleId' --profile "$AWS_PROFILE" --region "$AWS_REGION")"
  VAR_ROLE_ID="$PREFIX"_EC2_ROLE_ID
  echo "The IAM Role userid ...........................: ${!VAR_ROLE_ID}"
  # --- Attaching IAM Role to Instance Profile
  aws iam add-role-to-instance-profile --instance-profile-name "${!VAR_NAME}" \
      --role-name "${!VAR_NAME}" --profile "$AWS_PROFILE" --region "$AWS_REGION"
  echo "Attaching IAM Role to Instance Profile ........: ${!VAR_NAME}"
  # Add new json element to Project S3 Bucket Policy for EC2 RoleId
  POLICY_DOC=$(find ./policies/s3-buckets/${PROJECT_NAME}* -type f)
  jq --arg var_role_id "${!VAR_ROLE_ID}:*" '.Statement[].Condition.StringNotLike[] += [ $var_role_id ]' < "${POLICY_DOC}" > "${POLICY_DOC}".tmp 
  mv "${POLICY_DOC}".tmp "$POLICY_DOC"
  # Embedd resource inline policy documents in IAM roles
  EC2_ROLE_SSM_NAME="${PROJECT_NAME}"-"${PREFIX,,}"-ec2-ssm-"${AWS_REGION}"
  EC2_ROLE_S3_NAME="${PROJECT_NAME}"-"${PREFIX,,}"-ec2-s3-"${AWS_REGION}"
  if [[ $PREFIX == "PRIV" ]]; then
      aws iam put-role-policy --role-name "${!VAR_NAME}"  \
          --policy-name "$EC2_ROLE_SSM_NAME"              \
          --policy-document "$PRIV_SSM_EC2_POLICY" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with SSM Access Policy : ${EC2_ROLE_SSM_NAME}"
      # ...
      aws iam put-role-policy --role-name "${!VAR_NAME}"  \
          --policy-name "$EC2_ROLE_S3_NAME"               \
          --policy-document "$PRIV_S3_EC2_POLICY" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with S3 Access Policy .: ${EC2_ROLE_S3_NAME}"
  elif [[ $PREFIX == "PUB" ]]; then
      aws iam put-role-policy --role-name "${!VAR_NAME}"  \
          --policy-name "$EC2_ROLE_S3_NAME"               \
          --policy-document "$PUB_S3_EC2_POLICY" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with S3 Access Policy .: ${EC2_ROLE_S3_NAME}"
  else 
      aws iam put-role-policy --role-name "${!VAR_NAME}"  \
          --policy-name "$EC2_ROLE_S3_NAME"               \
          --policy-document "$LT_S3_EC2_POLICY" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with S3 Access Policy .: ${EC2_ROLE_S3_NAME}"
      # ...
      # Cloudwatch Agent Managed Policy
      EC2_ROLE_CW_ARN="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
      aws iam attach-role-policy --role-name "${!VAR_NAME}" \
        --policy-arn "$EC2_ROLE_CW_ARN" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with Managed Policy ...: ${EC2_ROLE_CW_ARN}"
  fi
done
#.............................

#-----------------------------
# Create S3 Project Bucket with Encryption & Policy
if (aws s3 mb "s3://$PROJECT_BUCKET" --profile "$AWS_PROFILE" --region "$AWS_REGION" > /dev/null)
then 
  aws s3api put-bucket-encryption --bucket "$PROJECT_BUCKET"  \
      --server-side-encryption-configuration                \
      '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}' \
      --profile "$AWS_PROFILE" --region "$AWS_REGION"
      #.............................
  aws s3api put-bucket-policy --bucket "$PROJECT_BUCKET"  \
      --profile "$AWS_PROFILE" --region "$AWS_REGION"   \
      --policy "file://policies/s3-buckets/${PROJECT_NAME}-proj-s3-policy.json" \
      #.............................
  echo "S3 Project Bucket Created .....................: s3://$PROJECT_BUCKET"
else
  echo "Failed to Create S3 Project Bucket !!!!!!!!!!!!: s3://$PROJECT_BUCKET"
  exit 1
fi
#.............................

#----------------------------------------------
# Upload all created policy docs to S3
find ./policies -type f -name "${PROJECT_NAME}*.json" ! -path "*/scratch/*" -print0 |
  while IFS= read -r -d '' FILE
  do
    if [[ ! -s "$FILE" ]]; then
      echo "Error! Invalid Template Policy Document .......: $FILE"
      exit 1
    elif (aws s3 mv "$FILE" "s3://$PROJECT_BUCKET${FILE#.}" --profile "$AWS_PROFILE" --region "$AWS_REGION" > /dev/null); then
      echo "Uploading Policy Document to S3 Location ......: s3://$PROJECT_BUCKET${FILE#.}"
    else continue
    fi
  done
#.............................

#----------------------------------------------
# Upload Cloudformation Templates to S3
find -L ./cfn-templates -type f -name "*.yaml" ! -path "*/scratch/*" -print0 |
# -L : Follow symbolic links
  while IFS= read -r -d '' FILE
  do
    if [[ ! -s "$FILE" ]]; then
      echo "Invalid Cloudformation Template Document ......: $FILE"
      exit 1
    elif (aws s3 cp "$FILE" "s3://$PROJECT_BUCKET${FILE#.}" --profile "$AWS_PROFILE" --region "$AWS_REGION" > /dev/null); then
      echo "Uploading Cloudformation Template to S3 .......: s3://$PROJECT_BUCKET${FILE#.}"
    else continue
    fi
  done
#.............................

#-----------------------------
# Create CloudWatch Agent config from template
find -L ./logs/template*.json -type f -print0 |
# -L : Follow symbolic links
  while IFS= read -r -d '' TEMPLATE
  do
    # Copy/Rename template via parameter expansion
    cp "$TEMPLATE" "${TEMPLATE//template/$PROJECT_NAME}"
    # Update FQDN of gaming record set
    sed -i "s/ProjectName/$PROJECT_NAME/g" "$_"
    # Create archive of client configs
    tar -rf "$(dirname "$_")/${PROJECT_NAME}-amzn-cw-agent.json.tar" --remove-files -C "$(dirname "$_")" "$(basename "$_")"
    echo "Creating CloudWatch Agent Configuration .......: $_"
  done
#.............................

#-----------------------------
# Compress & Upload CloudWatch Agent config to S3
# Remove hierarchy from archives for more flexible extraction options.
S3_LOCATION="s3://$PROJECT_BUCKET/logs"
if [[ $(gzip -c ./logs/*.tar | aws s3 cp - ${S3_LOCATION}/${PROJECT_NAME}-amzn-cw-agent.json.tar.gz --profile "$AWS_PROFILE" --region "$AWS_REGION") -ne 0 ]]
then
  echo "CW Agent Config Failed to Uploaded to S3 ......: ${S3_LOCATION}"
  exit 1
else
  echo "CW Agent Config Uploaded to S3 Location .......: ${S3_LOCATION}"
  # archive no longer needed
  rm ./logs/${PROJECT_NAME}*.tar
fi
#.............................


#-----------------------------
#-----------------------------
# Stage1 Stack Creation Code Block
BUILD_COUNTER="stage1"
TEMPLATE_URL="https://${PROJECT_BUCKET}.s3.${AWS_REGION}.amazonaws.com/cfn-templates/${PROJECT_NAME}.yaml"
STACK_POLICY_URL="https://${PROJECT_BUCKET}.s3.${AWS_REGION}.amazonaws.com/policies/cfn-stacks/${PROJECT_NAME}-${BUILD_COUNTER}-cfn-stack-policy.json"

echo "Cloudformation Stack Creation Initiated .......: $TEMPLATE_URL"

#-----------------------------
STACK_ID=$(aws cloudformation create-stack --stack-name "$STACK_NAME" --parameters      \
                ParameterKey=ProjectName,ParameterValue="$PROJECT_NAME"                 \
                ParameterKey=BuildStep,ParameterValue="$BUILD_COUNTER"                  \
                ParameterKey=DomainName,ParameterValue="$AWS_DOMAIN_NAME"               \
                ParameterKey=DomainHostedZoneId,ParameterValue="$HOSTED_ZONE_ID"        \
                ParameterKey=SshAccessCIDR,ParameterValue="$SSH_ACCESS_CIDR"            \
                ParameterKey=CurrentAmi,ParameterValue="$AMI_LATEST"                    \
                ParameterKey=GamingEmailAddrSNS,ParameterValue="$USER_EMAIL"                  \
                --tags Key=Name,Value="$PROJECT_NAME"                                   \
                --stack-policy-url "$STACK_POLICY_URL" --template-url "$TEMPLATE_URL"   \
                --profile "$AWS_PROFILE" --region "$AWS_REGION"                         \
                --on-failure DO_NOTHING --capabilities CAPABILITY_NAMED_IAM --output text)
#-----------------------------
if [[ $? -eq 0 ]]; then
  # Wait for stack creation to complete
  echo "Cloudformation Stack Creation In Progress .....: $STACK_ID"
  CHECK_STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" --query 'Stacks[0].StackStatus' --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
  while [[ $CHECK_STATUS == "REVIEW_IN_PROGRESS" ]] || [[ $CHECK_STATUS == "CREATE_IN_PROGRESS" ]]
  do
      # Wait 1 seconds and then check stack status again
      sleep 2
      printf '.'
      CHECK_STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" --query 'Stacks[0].StackStatus' --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
  done
  printf '\n'
fi
#-----------------------------
# Validate stack creation has not failed
if (aws cloudformation wait stack-create-complete --stack-name "$STACK_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION")
then 
  echo "Cloudformation Stack Create Process Complete ..: $BUILD_COUNTER"
else 
  echo "Error: Stack Create Failed!"
  #printf 'Stack ID: \n%s\n' "$STACK_ID"
  exit 1
fi
#-----------------------------
# Calculate Stack Creation Execution Time
TIME_END_PT=$(date +%s)
TIME_DIFF_PT=$((TIME_END_PT - TIME_START_PROJ))
echo "$BUILD_COUNTER Finished Execution Time ................: \
$(( TIME_DIFF_PT / 3600 ))h $(( (TIME_DIFF_PT / 60) % 60 ))m $(( TIME_DIFF_PT % 60 ))s"
#.............................
#.............................


#-----------------------------
# Grab the IDs of the ec2 instances for further processing
INSTANCE_PUB_ID=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" --output text \
  --query "Stacks[].Outputs[?OutputKey == 'InstanceIdPublicBuild'].OutputValue"                  \
  --profile "$AWS_PROFILE" --region "$AWS_REGION")
echo "Public Subnet EC2 Instance ID .................: $INSTANCE_PUB_ID"
#.............................


#-----------------------------
# Validity Check. Wait for instance status ok before moving on.
echo "Waiting on Instance Status ok .................: $INSTANCE_PUB_ID"
CHECK_INSTANCE_STATUS=$(aws ec2 describe-instance-status --instance-ids "$INSTANCE_PUB_ID" --query 'InstanceStatuses[0].InstanceStatus.Status' --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
while [[ $CHECK_INSTANCE_STATUS != "ok" ]]
do
    # Wait 3 seconds and then check stack status again
    sleep 3
    printf '.'
    CHECK_INSTANCE_STATUS=$(aws ec2 describe-instance-status --instance-ids "$INSTANCE_PUB_ID" --query 'InstanceStatuses[0].InstanceStatus.Status' --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
done
printf '\n'
echo "Public Subnet EC2 Instance State ..............: OK"
#-----------------------------
# Previous Solution:
#aws ec2 wait instance-status-ok --instance-ids "$INSTANCE_PUB_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION" &
#P1=$!
#wait $P1
#.............................



#-----------------------------
# Detect SSM Agent (Wait)
CHECK_ID_SSM=""
CHECK_ID_SSM=$(aws ssm describe-instance-information --query "InstanceInformationList[].InstanceId" --output text \
  --filters "Key=tag:Name,Values=${PROJECT_NAME}-gpu-build" --profile "$AWS_PROFILE" --region "$AWS_REGION")
#.............................
if [[ $? -eq 0 ]]; then
  # Wait for detection to complete
  echo "Waiting for SSM Agent to be Dectected .........: "
  while [[ $CHECK_ID_SSM == "" ]]
  do
      # Wait 3 seconds and then check stack status again
      sleep 3
      printf '.'
      CHECK_ID_SSM=$(aws ssm describe-instance-information --query "InstanceInformationList[].InstanceId" --output text \
        --filters "Key=tag:Name,Values=${PROJECT_NAME}-gpu-build" --profile "$AWS_PROFILE" --region "$AWS_REGION")
  done
  printf '\n'
  echo "SSM Agent detected on Instance with ID ........: $CHECK_ID_SSM"
else
  echo "Error in SSM Agent Detection ..................: $INSTANCE_PUB_ID"
  exit 1
fi
#-----------------------------


#-----------------------------
# Grab the Admin Password
# Do local decryption on password later.
INSTANCE_PUB_PASSWD=$(aws ec2 get-password-data --instance-id "$INSTANCE_PUB_ID"          \
  --priv-launch-key ./ssh/aws.dev.ec2.win.ssh.key.eu-central-1.pem --query 'PasswordData' \
  --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
echo "Retrieving Public Instance Admin Password .....: $INSTANCE_PUB_PASSWD"
echo "$INSTANCE_PUB_PASSWD" > /tmp/password
#.............................


#-----------------------------
# Update SSM Agent 
echo "Update SSM Agent on Instance ..................: $INSTANCE_PUB_ID"
SSM_COMMAND_ID=$(aws ssm send-command --document-name "AWS-UpdateSSMAgent" --instance-ids "$INSTANCE_PUB_ID" \
  --output text --profile "$AWS_PROFILE" --region "$AWS_REGION" --query 'Command.CommandId')
echo "Waiting for SSM Agent Update with Command ID ..: $SSM_COMMAND_ID"
#.............................
aws ssm wait command-executed --command-id "$SSM_COMMAND_ID" --instance-id "$INSTANCE_PUB_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION" &
P1=$!
wait $P1
#.............................
if [[ $? -eq 0 ]]; then
  echo "Success! SSM Agent Updated with Command ID ....: $SSM_COMMAND_ID"
else
  echo "Error! SSM Agent Failed Update Command ID .....: $INSTANCE_PUB_ID"
  exit 1
fi
#-----------------------------


#-----------------------------
# Install EC2 Launch Agent
echo "Installing EC2 Launch Agent on Instance .......: $INSTANCE_PUB_ID"
#SSM_PARAMETERS='{"action":["Install"],"installationType":["Uninstall and reinstall"],"name":["AWSEC2Launch-Agent"],"version":[""],"additionalArguments":["{}"]}'
SSM_PARAMETERS='{"action":["Install"],"installationType":["Uninstall and reinstall"],"name":["AWSEC2Launch-Agent"]}'
SSM_COMMAND_ID=$(aws ssm send-command --document-name "AWS-ConfigureAWSPackage" --instance-ids "$INSTANCE_PUB_ID" \
  --parameters "$SSM_PARAMETERS" --output text --profile "$AWS_PROFILE" --region "$AWS_REGION" --query 'Command.CommandId')
echo "Waiting for EC2 Launch Agent Installation ID ..: $SSM_COMMAND_ID"
#.............................
aws ssm wait command-executed --command-id "$SSM_COMMAND_ID" --instance-id "$INSTANCE_PUB_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION" &
P1=$!
wait $P1
#.............................
if [[ $? -eq 0 ]]; then
  echo "Success! EC2 Launch Agent Installed ID ........: $SSM_COMMAND_ID"
else
  echo "Error! EC2 Launch Agent Failed Installation ...: $INSTANCE_PUB_ID"
  exit 1
fi
#-----------------------------



#-----------------------------
# Shuntdown instance for faster image creation
aws ec2 stop-instances --instance-ids "$INSTANCE_PUB_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION" > /dev/null
echo "Stopping Public Instances Initiated ...........: "
#.............................

#-----------------------------
# Wait for new AMIs to become available
aws ec2 wait instance-stopped --instance-ids "$INSTANCE_PUB_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION" &
P1=$!
wait $P1
echo "Public Instances have now stopped .............: $INSTANCE_PUB_ID "
#.............................



#-----------------------------
# Create Golden AMI
echo "Initiate AMI Creation Public EC2 Instance .....: "
AMI_IMAGE_PUB=$(aws ec2 create-image --instance-id "$INSTANCE_PUB_ID" --name "${PROJECT_NAME}-gpu-build" \
  --description "${PROJECT_NAME}-gpu-build-ami" --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
echo "Waiting for AMI Creation to complete ..........: $AMI_IMAGE_PUB"
#.............................
aws ec2 wait image-available --image-ids "$AMI_IMAGE_PUB" --profile "$AWS_PROFILE" --region "$AWS_REGION" &
P1=$!
wait $P1
#.............................
if [[ $? -eq 0 ]]; then
  echo "Public EC2 Instance AMI now available .........: $AMI_IMAGE_PUB "
else
  echo "Error! Public EC2 Instance AMI Creation Failed : $AMI_IMAGE_PUB"
  exit 1
fi
#-----------------------------


#-----------------------------
# Give AMIs a Name Tag
aws ec2 create-tags --resources "$AMI_IMAGE_PUB" --tags Key=Name,Value="${PROJECT_NAME}-gpu-build" --profile "$AWS_PROFILE" --region "$AWS_REGION"
#.............................

#-----------------------------
# Terminate the instances - no longer needed.
aws ec2 terminate-instances --instance-ids "$INSTANCE_PUB_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION" > /dev/null
#.............................

#-----------------------------
# Calculate AMI Creation Execution Time
TIME_END_PT=$(date +%s)
TIME_DIFF_PT=$((TIME_END_PT - TIME_START_PROJ))
echo "Build Instance Terminated AMI Creation Time ...: \
$(( TIME_DIFF_PT / 3600 ))h $(( (TIME_DIFF_PT / 60) % 60 ))m $(( TIME_DIFF_PT % 60 ))s"
#.............................
#.............................


#-----------------------------
#-----------------------------
# Stage3 Stack Creation Code Block
BUILD_COUNTER="stage3"
echo "Cloudformation Stack Update Initiated .........: "
#-----------------------------
aws cloudformation update-stack --stack-name "$STACK_ID" --parameters \
      ParameterKey=BuildStep,ParameterValue="$BUILD_COUNTER"          \
      ParameterKey=CurrentAmi,ParameterValue="$AMI_IMAGE_PUB"         \
      ParameterKey=ProjectName,UsePreviousValue=true                  \
      ParameterKey=DomainName,UsePreviousValue=true                   \
      ParameterKey=DomainHostedZoneId,UsePreviousValue=true           \
      ParameterKey=SshAccessCIDR,UsePreviousValue=true                \
      ParameterKey=GamingEmailAddrSNS,UsePreviousValue=true           \
      --stack-policy-url "$STACK_POLICY_URL" --use-previous-template  \
      --profile "$AWS_PROFILE" --region "$AWS_REGION"                 \
      --tags Key=Name,Value="$PROJECT_NAME" > /dev/null    
#-----------------------------
if [[ $? -eq 0 ]]; then
  # Wait for stack creation to complete
  echo "Cloudformation Stack Update In Progress .......: $STACK_ID"
  CHECK_STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" --query 'Stacks[0].StackStatus' --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
  while [[ $CHECK_STATUS == "UPDATE_IN_PROGRESS" ]] || [[ $CHECK_STATUS == "CREATE_IN_PROGRESS" ]]
  do
      # Wait 1 seconds and then check stack status again
      sleep 1
      printf '.'
      CHECK_STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" --query 'Stacks[0].StackStatus' --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
  done
  printf '\n'
fi
#.............................

#-----------------------------
# Validate stack creation has not failed
if (aws cloudformation wait stack-update-complete --stack-name "$STACK_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION")
then 
  echo "Cloudformation Stack Update Process Complete ..: $BUILD_COUNTER"
  #printf 'Stack ID: \n%s\n' "$STACK_ID"
else 
  echo "Error: Stack Update Failed!"
  #printf 'Stack ID: \n%s\n' "$STACK_ID"
  exit 1
fi
#.............................

#-----------------------------
# Calculate Stack Creation Execution Time
TIME_END_PT=$(date +%s)
TIME_DIFF_PT=$((TIME_END_PT - TIME_START_PROJ))
echo "$BUILD_COUNTER Finished Execution Time ................: \
$(( TIME_DIFF_PT / 3600 ))h $(( (TIME_DIFF_PT / 60) % 60 ))m $(( TIME_DIFF_PT % 60 ))s"
#.............................
#.............................


#-----------------------------
# Grab the IDs of the ec2 instances for further processing
#INSTANCE_PUB_ID=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" --output text \
#    --profile "$AWS_PROFILE" --region "$AWS_REGION"                                         \
#    --query "Stacks[].Outputs[?OutputKey == 'InstanceIdPublicLaunch'].OutputValue")
#echo "Gaming Server EC2 Instance ID .........................: $INSTANCE_PUB_ID"
#.............................


#-----------------------------
# Grab the IDs of the ec2 instances for further processing
#aws ec2 describe-instances --output text --query 'Reservations[].Instances[].[Tags[?Key==`Name`].Value|[0],InstanceId]'
#INSTANCE_PUB_ID=$(aws ec2 describe-instances --output text --profile "$AWS_PROFILE" --region "$AWS_REGION" \
# --query "Reservations[].Instances[]|[?Tags[?Value=='cfn-gpu-rig-cli-autoscale-grp']]|[?State.Name=='running'].InstanceId")
#...
INSTANCE_PUB_ID=$(aws ec2 describe-instances --output text --filters Name=instance-state-name,Values=running \
  --query "Reservations[].Instances[]|[?Tags[?Value=='cfn-gpu-rig-cli-autoscale-grp']].InstanceId" \
  --profile "$AWS_PROFILE" --region "$AWS_REGION")
echo "Gaming Server EC2 Instance ID .................: $INSTANCE_PUB_ID"
#.............................


#-----------------------------
# Grab the DNS of the ec2 instances for further processing
INSTANCE_PUB_DNS=$(aws ec2 describe-instances --instance-ids "$INSTANCE_PUB_ID" \
    --query 'Reservations[].Instances[].PublicDnsName' --output text            \
    --profile  "$AWS_PROFILE" --region "$AWS_REGION")
echo "Gaming Server EC2 Instance DNS ................: $INSTANCE_PUB_DNS"
#.............................




#-----------------------------
# Calculate Script Total Execution Time
TIME_END_PT=$(date +%s)
TIME_DIFF_PT=$((TIME_END_PT - TIME_START_PROJ))
echo "Total Finished Execution Time .................: \
$(( TIME_DIFF_PT / 3600 ))h $(( (TIME_DIFF_PT / 60) % 60 ))m $(( TIME_DIFF_PT % 60 ))s"
#.............................
