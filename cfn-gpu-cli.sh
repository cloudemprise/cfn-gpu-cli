#!/bin/bash -e
# debug options include -v -x
# cfn-gpu-cli.sh 
# A hardened, hightly available, Windows cloud gaming server cloudformation template composition.

# Debug pause
#read -p "Press enter to continue"


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


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# START   USER INPUT 
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

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
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
  if aws ec2 describe-regions --profile "$AWS_PROFILE" --query 'Regions[].RegionName' \
    --output text 2>/dev/null | grep -qw -- "$USER_INPUT"
  then
    echo "Project AWS CLI Region is valid ...............: $USER_INPUT"
    AWS_REGION=$USER_INPUT
    break
  else
    echo "Error! Project AWS CLI Region is invalid ......: $USER_INPUT"
  fi
done
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#-----------------------------
# Request Project Name
PROJECT_NAME="cfn-gpu-cli"
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
    PROJECT_BUCKET="proj-${PROJECT_NAME}-${AWS_REGION}"
    break
  else
    echo "Error! Project Name must be S3 Compatible .....: $USER_INPUT"
  fi
done
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Request KMS Customer managed keys
KMS_CMK_ALIAS="alias/ce/kms/$AWS_REGION"
while true
do
  # -e : stdin from terminal
  # -r : backslash not an escape character
  # -p : prompt on stderr
  # -i : use default buffer val
  read -er -i "$KMS_CMK_ALIAS" -p "Enter KMS CMK Alias ...........................: " USER_INPUT
  if aws kms list-aliases --query 'Aliases[].AliasName' --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" --output text 2>/dev/null | grep -qw -- "$USER_INPUT"
  then
    KMS_CMK_ID=$(aws kms list-aliases --profile "$AWS_PROFILE" --region "$AWS_REGION" \
      --query "Aliases[?AliasName == '$USER_INPUT'].TargetKeyId" --output text)
    echo "KMS CMK Alias verified with Key ID ............: $KMS_CMK_ID"
    KMS_CMK_ALIAS=$USER_INPUT
    break
  else
    echo "Error! Invalid KMS CMK Alias, try again .......: $USER_INPUT"
  fi
done
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#-----------------------------
# Request Domain Name
AWS_DOMAIN_NAME="cloudemprise.com"
while true
do
  # -e : stdin from terminal
  # -r : backslash not an escape character
  # -p : prompt on stderr
  # -i : use default buffer val
  read -er -i "$AWS_DOMAIN_NAME" -p "Enter Project Domain Name .....................: " USER_INPUT
  if [[ "${USER_INPUT:=$AWS_DOMAIN_NAME}" =~ (^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}$) ]]
  then
    echo "Project Domain Name is valid ..................: $USER_INPUT"
    AWS_DOMAIN_NAME=$USER_INPUT
    break
  else
    echo "Error! Domain Name must be S3 Compatible ......: $USER_INPUT"
  fi
done
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Windows Admin Password Encrypted within SSM Parameter Store 
# Gaming Server User Admin Password : Exists? : Modify or Retain ?
ADMIN_AUTH_PASS_EXISTS=$(aws ssm describe-parameters --query 'Parameters' --output text \
  --parameter-filters "Key=Name,Values=/${PROJECT_NAME}/user-admin-auth" \
  --profile "$AWS_PROFILE" --region "$AWS_REGION")
# Parameter Store Password doesn't exist
if [[ -z "$ADMIN_AUTH_PASS_EXISTS" ]]; then
  # Ask user for Windows Admin Password
  USER_INPUT1="false"
  USER_INPUT2="true"
  # Validate! While user input is different or empty...
  while [[ "$USER_INPUT1" != "$USER_INPUT2" ]] || [[ "$USER_INPUT1" == '' ]] 
  do
    # -s : silent mode
    # -r : backslash not an escape character
    # -e : stdin from terminal
    # -p : prompt on stderr
    read -srep "Enter Games Server Administrator Password .....: " USER_INPUT1
    if [[ -z "$USER_INPUT1" ]]; then
      printf '\n%s\n' "Error. No Input Entered !"
      continue
    else
      read -srep $'\nRepeat Games Server Administrator Password ....: ' USER_INPUT2
      if [[ "$USER_INPUT1" != "$USER_INPUT2" ]]; then
        printf '\n%s\n' "Error. Password Mismatch. Try Again ...........: "
      else
        printf '\n%s\n' "Password Match ........ Continue ..............:"
        ADMIN_AUTH_PASS="$USER_INPUT2"
      fi
    fi
  done
  # ___
  # Store Passphrase in SSM Parameter Store
  ADMIN_AUTH_PASS_NAME="/$PROJECT_NAME/user-admin-auth"
  echo "Adding Password to AWS Parameter Store ........: $ADMIN_AUTH_PASS_NAME"
  aws ssm put-parameter --name "$ADMIN_AUTH_PASS_NAME" --value "$ADMIN_AUTH_PASS" --overwrite \
    --type SecureString --key-id "$KMS_CMK_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --description "Windows Gaming Server Administrator Password." > /dev/null
  # ^^^
else 
  # Parameter Store exists but does user want to change it?
  while true
  do
    # Ask user if a Password Change is required
    read -re -i "n" -p "Modify existing Project Password ? (y/n) ......: " CHANGE_PASSWD
    # Modify the existing password
    if [[ "${CHANGE_PASSWD^}" == "Y" ]]; then
      # ___
      # Ask user for Windows Admin Password
      USER_INPUT1="false"
      USER_INPUT2="true"
      # Validate! While user input is different or empty...
      while [[ "$USER_INPUT1" != "$USER_INPUT2" ]] || [[ "$USER_INPUT1" == '' ]] 
      do
        # -s : silent mode
        # -r : backslash not an escape character
        # -e : stdin from terminal
        # -p : prompt on stderr
        read -srep "Enter Games Server Administrator Password .....: " USER_INPUT1
        if [[ -z "$USER_INPUT1" ]]; then
          printf '\n%s\n' "Error. No Input Entered !"
          continue
        else
          read -srep $'\nRepeat Games Server Administrator Password ....: ' USER_INPUT2
          if [[ "$USER_INPUT1" != "$USER_INPUT2" ]]; then
            printf '\n%s\n' "Error. Password Mismatch. Try Again ...........: "
          else
            printf '\n%s\n' "Password Match ........ Continue ..............:"
            ADMIN_AUTH_PASS="$USER_INPUT2"
          fi
        fi
      done
      # ___
      # Store Passphrase in SSM Parameter Store
      ADMIN_AUTH_PASS_NAME="/$PROJECT_NAME/user-admin-auth"
      echo "Adding Password to AWS Parameter Store ........: $ADMIN_AUTH_PASS_NAME"
      aws ssm put-parameter --name "$ADMIN_AUTH_PASS_NAME" --value "$ADMIN_AUTH_PASS" --overwrite \
        --type SecureString --key-id "$KMS_CMK_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
        --description "Windows Gaming Server Administrator Password." > /dev/null
      break
      # ^^^
    elif [[ "${CHANGE_PASSWD^}" == "N" ]]; then
      # Keeping password unchanged but make a local copy for later use
      ADMIN_AUTH_PASS=$(aws ssm get-parameter --profile "$AWS_PROFILE" --region "$AWS_REGION" \
        --name "/${PROJECT_NAME}/user-admin-auth" --query 'Parameter.Value' \
        --with-decryption --output text)
      #echo "SSM Parameter Store Current Saved Password ....: $ADMIN_AUTH_PASS"
      break
    else
      # Input [y/n]
      echo "Error! Invalid Input please try again .........: $CHANGE_PASSWD"
    fi
  done
fi
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#-----------------------------
# Get Route 53 Domain hosted zone ID
HOSTED_ZONE_ID=$(aws route53 list-hosted-zones-by-name --dns-name "$AWS_DOMAIN_NAME" \
  --profile "$AWS_PROFILE" --region "$AWS_REGION" --query 'HostedZones[].Id' --output text \
  | awk -F "/" '{print $3}')
[[ -z "$HOSTED_ZONE_ID" ]] \
    && { echo "Invalid Hosted Zone!"; exit 1; } \
    || { echo "Route53 Hosted Zone ID ........................: $HOSTED_ZONE_ID"; }
#.............................
# Stipulate fully qualified domain name for DCV protocol
echo "FQDN Gaming Server ............................: \
${PROJECT_NAME}-${AWS_REGION}.${AWS_DOMAIN_NAME}:8443"
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#-----------------------------
# Variable Creation
#-----------------------------
# Name given to Cloudformation Stack
STACK_NAME="$PROJECT_NAME-stack"
echo "The Stack Name ................................: $STACK_NAME"
# Get Account(ROOT) ID
AWS_ACC_ID=$(aws sts get-caller-identity --query 'Account' --output text --profile "$AWS_PROFILE" \
  --region "$AWS_REGION")
echo "The Root Account ID ...........................: $AWS_ACC_ID"
# Console Admin profile userid
AWS_USER_ADMIN="usr.console.admin"
AWS_USERID_ADMIN=$(aws iam get-user --user-name "$AWS_USER_ADMIN" --query 'User.UserId' \
  --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
echo "The Console Admin userid ......................: $AWS_USERID_ADMIN"
# CLI profile userid
AWS_USERID_CLI=$(aws sts get-caller-identity --query 'UserId' --output text \
  --profile "$AWS_PROFILE" --region "$AWS_REGION")
echo "The Script Caller userid ......................: $AWS_USERID_CLI"
#-----------------------------
# Script caller IP CIDR for SSH Bastion Host (if needed)
SSH_ACCESS_CIDR="$(curl -s https://checkip.amazonaws.com/)/32"
echo "The Script Caller IP CIDR  ....................: $SSH_ACCESS_CIDR"
# Grab the latest AMI
AMI_NAME="/aws/service/ami-windows-latest/Windows_Server-2019-English-Full-Base"
AMI_LATEST=$(aws ssm get-parameters --output text --names "$AMI_NAME" --profile "$AWS_PROFILE" \
  --query 'Parameters[0].[Value]' --region "$AWS_REGION")
echo "The lastest AMI ...............................: $AMI_LATEST"
#-----------------------------
SPOT_DURATION="60"
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# END   USER INPUT
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# START   Artifact Creation
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#----------------------------------------------
# Create S3 Project Bucket Policy from local template exclude scratch folder
find -L ./policies/s3/template* -type f ! -path "*/scratch/*" -print0 |
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
      sed -i "s/Region/$AWS_REGION/" "$_"
      sed -i "s/ProjectBucket/$PROJECT_BUCKET/" "$_"
      sed -i "s/RootAccount/$AWS_ACC_ID/" "$_"
      sed -i "s/ConsoleAdmin/$AWS_USERID_ADMIN/" "$_"
      sed -i "s/ScriptCallerUserId/$AWS_USERID_CLI/" "$_"
      echo "Creating S3 Bucket Policy .....................: $_"
    fi
  done
#.............................

#----------------------------------------------
# Create Cloudformation Stack Policies from local templates exclude scratch folder
find -L ./policies/cfn/template* -type f ! -path "*/scratch/*" -print0 |
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
# Create IAM inline Resource Policies from local templates exclude scratch folder
find -L ./policies/ec2/template* -type f ! -path "*/scratch/*" -print0 |
# -L : Follow symbolic links
  while IFS= read -r -d '' TEMPLATE
  do
    if [[ ! -s "$TEMPLATE" ]]; then
      echo "Invalid Template Inline Policy ................: $TEMPLATE"
      exit 1
    else
      # Copy/Rename template via parameter expansion
      cp "$TEMPLATE" "${TEMPLATE//template/$PROJECT_NAME}"
      # Replace appropriate variables
      sed -i "s/ProjectName/$PROJECT_NAME/" "$_"
      sed -i "s/Region/$AWS_REGION/" "$_"
      sed -i "s/ProjectBucket/$PROJECT_BUCKET/" "$_"
      sed -i "s/RootAccount/$AWS_ACC_ID/" "$_"
      echo "Creating EC2 Inline Custom Policy .............: $_"
    fi
  done
#.............................

#----------------------------------------------
# Create SSM inline PassRole Policy from local template exclude scratch folder
find -L ./policies/ssm/template* -type f ! -path "*/scratch/*" -print0 |
# -L : Follow symbolic links
  while IFS= read -r -d '' TEMPLATE
  do
    if [[ ! -s "$TEMPLATE" ]]; then
      echo "Invalid Template SSM PassRole Policy ..........: $TEMPLATE"
      exit 1
    else
      # Copy/Rename template via parameter expansion
      cp "$TEMPLATE" "${TEMPLATE//template/$PROJECT_NAME}"
      # Replace appropriate variables
      sed -i "s/ProjectName/$PROJECT_NAME/" "$_"
      sed -i "s/RootAccount/$AWS_ACC_ID/" "$_"
      echo "Creating SSM Inline Custom Policy .............: $_"
    fi
  done
#.............................

#----------------------------------------------
# Create the json objects requred for the CMK Key Policy from local template 
# exclude scratch folder
#   1. EC2 Autoscaling/SpotPrice Service Linked Roles
#   2. SSM Parameter Store
#   3. SNS Topic 
#   4. S3 Project Bucket
find -L ./policies/kms/template* -type f ! -path "*/scratch/*" -print0 |
# -L : Follow symbolic links
  while IFS= read -r -d '' TEMPLATE
  do
    if [[ ! -s "$TEMPLATE" ]]; then
      echo "Invalid Template KMS CMK json Policy Objects ..: $TEMPLATE"
      exit 1
    else
      # Copy/Rename template via parameter expansion
      cp "$TEMPLATE" "${TEMPLATE//template/$PROJECT_NAME}"
      # Replace appropriate variables
      sed -i "s/ProjectName/$PROJECT_NAME/" "$_"
      sed -i "s/RootAccount/$AWS_ACC_ID/" "$_"
      echo "Creating KMS CMK json Policy Objects ..........: $_"
    fi
  done
#.............................

#-----------------------------
# Create CloudWatch Agent config from template exclude scratch folder
find -L ./logs/template*.json -type f ! -path "*/scratch/*" -print0 |
# -L : Follow symbolic links
  while IFS= read -r -d '' TEMPLATE
  do
    # Copy/Rename template via parameter expansion
    cp "$TEMPLATE" "${TEMPLATE//template/$PROJECT_NAME}"
    # Update FQDN of gaming record set
    sed -i "s/ProjectName/$PROJECT_NAME/g" "$_"
    # Create archive of client configs (special) no containing directory
    tar -rf "$(dirname "$_")/${PROJECT_NAME}-amzn-cw-agent.json.tar" \
      --remove-files -C "$(dirname "$_")" "$(basename "$_")"
    echo "Creating CloudWatch Agent Configuration .......: $_"
  done
#.............................

#----------------------------------------------
# Create SSM Automation Powershell script from local template exclude scratch folder
find -L ./ssm/template* -type f ! -path "*/scratch/*" -print0 |
# -L : Follow symbolic links
  while IFS= read -r -d '' TEMPLATE
  do
    if [[ ! -s "$TEMPLATE" ]]; then
      echo "Invalid Template SSM Automation Script ........: $TEMPLATE"
      exit 1
    else
      # Copy/Rename template via parameter expansion
      cp "$TEMPLATE" "${TEMPLATE//template/$PROJECT_NAME}"
      # Replace appropriate variables
      sed -i "s/ProjectName/$PROJECT_NAME/" "$_"
      sed -i "s/ProjectBucket/$PROJECT_BUCKET/" "$_"
      echo "Creating SSM Run/Automation Artifact ..........: $_"
    fi
  done
#.............................

#----------------------------------------------
# Create Firefox Harden Profile Powershell script from local template exclude scratch folder
find -L ./firefox/template* -type f ! -path "*/scratch/*" -print0 |
# -L : Follow symbolic links
  while IFS= read -r -d '' TEMPLATE
  do
    if [[ ! -s "$TEMPLATE" ]]; then
      echo "Invalid Template Firefox Profile Artifact .....: $TEMPLATE"
      exit 1
    else
      # Copy/Rename template via parameter expansion
      cp "$TEMPLATE" "${TEMPLATE//template/$PROJECT_NAME}"
      # Replace appropriate variables
      sed -i "s/ProjectName/$PROJECT_NAME/" "$_"
      sed -i "s/ProjectBucket/$PROJECT_BUCKET/" "$_"
      echo "Creating Firefox Profile Artifact .............: $_"
    fi
  done
#.............................

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# END   Artifact Creation
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# START   SSM SERVICE ROLE CREATION 
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# ___
# Stringify Inline Policies
SSM_TRUST_POLICY=$(tr -d " \t\n\r" < ./policies/ssm/${PROJECT_NAME}-policy-ssm-assume-role.json)
SSM_PASSROLE_POLICY=$(tr -d " \t\n\r" < ./policies/ssm/${PROJECT_NAME}-policy-ssm-pass-role.json)
# ___
# --- Create SSM Automation Service Role
SSM_API_ROLE_NAME="$PROJECT_NAME-ssm-automation-$AWS_REGION"
echo "Creating SSM Automation Service Role ..........: $SSM_API_ROLE_NAME"
SSM_API_ROLE_ID="$(aws iam create-role --role-name "$SSM_API_ROLE_NAME" --output text   \
  --query 'Role.RoleId' --path "/ce/" --assume-role-policy-document "$SSM_TRUST_POLICY" \
  --profile "$AWS_PROFILE" --region "$AWS_REGION")"
echo "SSM Automation Service Role userid ............: $SSM_API_ROLE_ID"
# ___
# Add new JSON element to S3 Project Bucket Policy for EC2 RoleId
POLICY_DOC=$(find ./policies/s3/${PROJECT_NAME}-policy-s3-bucket.json -type f)
jq --arg var_role_id "$SSM_API_ROLE_ID:*" \
'.Statement[].Condition.StringNotLike[] += [ $var_role_id ]' < "${POLICY_DOC}" > "${POLICY_DOC}".tmp 
mv "${POLICY_DOC}".tmp "$POLICY_DOC"
# ___
# Affix SSM Passrole Policy
SSM_ROLE_POLICY_NAME="$PROJECT_NAME-ssm-automation-iam-passrole"
aws iam put-role-policy --role-name "$SSM_API_ROLE_NAME" --policy-name "$SSM_ROLE_POLICY_NAME" \
  --policy-document "$SSM_PASSROLE_POLICY" --profile "$AWS_PROFILE" --region "$AWS_REGION"
echo "SSM Automation Role affixed Passrole Policy ...: $SSM_ROLE_POLICY_NAME"
# ___
# Affix Managed Policy SSMAutomation Service Role
SSM_ROLE_MANAGED_ARN="arn:aws:iam::aws:policy/service-role/AmazonSSMAutomationRole"
aws iam attach-role-policy --role-name "$SSM_API_ROLE_NAME" --policy-arn "$SSM_ROLE_MANAGED_ARN" \
  --profile "$AWS_PROFILE" --region "$AWS_REGION"
echo "SSM Automation Role affixed Managed Policy ....: $SSM_ROLE_MANAGED_ARN"
#.............................

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# END   SSM SERVICE ROLE CREATION
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# START   EC2 INSTANCE ROLES CREATION 
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# ___
# Stringify Inline Policies
EC2_TRUST_POLICY=$(tr -d " \t\n\r" < ./policies/ec2/${PROJECT_NAME}-policy-ec2-assume-role.json)
EC2_S3_LT_POLICY=$(tr -d " \t\n\r" < ./policies/ec2/${PROJECT_NAME}-policy-ec2-s3-access-lt.json)
EC2_S3_PUB_POLICY=$(tr -d " \t\n\r" < ./policies/ec2/${PROJECT_NAME}-policy-ec2-s3-access-pub.json)
EC2_S3_SSM_POLICY=$(tr -d " \t\n\r" < ./policies/ec2/${PROJECT_NAME}-policy-ec2-s3-access-ssm.json)
EC2_S3_DCV_POLICY=$(tr -d " \t\n\r" < ./policies/ec2/${PROJECT_NAME}-policy-ec2-s3-access-dcv.json)
EC2_SSM_SSM_POLICY=$(tr -d " \t\n\r" < ./policies/ec2/${PROJECT_NAME}-policy-ec2-ssm-access-ssm.json)
# similar method using jq (preservers whitespace)
# jq '.' policy.json | jq -sR '.'

#-----------------------------
# Create EC2 Instance Profiles & IAM Role Polices for SSM Update AMI, Golden Image Build & 
# Autoscaling Launch Template Instances.
#-----------------------------
for PREFIX in SSM PUB LT; do
  # ___
  # --- Create (variable) IAM Role Name = Instance Profile Name
  declare "$PREFIX"_EC2_IAM_NAME="${PROJECT_NAME}"-ec2-"${PREFIX,,}"-"${AWS_REGION}"
  VAR_NAME="$PREFIX"_EC2_IAM_NAME
  echo "Creating EC2 IAM Instance Profile .............: ${!VAR_NAME}"
  # ___
  #--- Create EC2 Instance Profile
  declare "$PREFIX"_EC2_PROFILE_ID="$(aws iam create-instance-profile --output text \
      --instance-profile-name "${!VAR_NAME}"                                        \
      --query 'InstanceProfile.InstanceProfileId' --profile "$AWS_PROFILE" --region "$AWS_REGION")"
  VAR_PROFILE_ID="$PREFIX"_EC2_PROFILE_ID
  echo "The EC2 Instance Profile userid ...............: ${!VAR_PROFILE_ID}"
  # ___
  # --- Create IAM Role with EC2 Assume Policy
  echo "Creating Complementary EC2 IAM Role ...........: ${!VAR_NAME}"
  declare "$PREFIX"_EC2_ROLE_ID="$(aws iam create-role --role-name "${!VAR_NAME}" \
      --assume-role-policy-document "$EC2_TRUST_POLICY" --path "/ce/" \
      --output text --query 'Role.RoleId' --profile "$AWS_PROFILE" --region "$AWS_REGION")"
  VAR_ROLE_ID="$PREFIX"_EC2_ROLE_ID
  echo "The IAM Role userid ...........................: ${!VAR_ROLE_ID}"
  # ___
  # --- Attaching IAM Role to Instance Profile
  aws iam add-role-to-instance-profile --instance-profile-name "${!VAR_NAME}" \
      --role-name "${!VAR_NAME}" --profile "$AWS_PROFILE" --region "$AWS_REGION"
  echo "Attaching IAM Role to Instance Profile ........: ${!VAR_NAME}"
  # ___
  # Add new JSON element to S3 Project Bucket Policy for EC2 RoleId
  POLICY_DOC=$(find ./policies/s3/${PROJECT_NAME}-policy-s3-bucket.json -type f)
  jq --arg var_role_id "${!VAR_ROLE_ID}:*" \
  '.Statement[].Condition.StringNotLike[] += [ $var_role_id ]' < "${POLICY_DOC}" > "${POLICY_DOC}".tmp 
  mv "${POLICY_DOC}".tmp "$POLICY_DOC"
  # ___
  # Create sensible Names for Inline Policy Docs that go in IAM roles
  EC2_ROLE_SSM_NAME="${PROJECT_NAME}"-ssm-"${PREFIX,,}"-"${AWS_REGION}"
  EC2_ROLE_S3_PROJ="${PROJECT_NAME}"-s3-proj-"${PREFIX,,}"-"${AWS_REGION}"
  EC2_ROLE_S3_DCV="${PROJECT_NAME}"-s3-dcv-"${PREFIX,,}"-"${AWS_REGION}"
  # ...
  # Attach Polcies to Roles for each Build Stage, i.e. SSM, PUB, LT
  if [[ $PREFIX == "SSM" ]]; then
      # Add access to project bucket
      aws iam put-role-policy --role-name "${!VAR_NAME}"  \
          --policy-name "$EC2_ROLE_S3_PROJ"               \
          --policy-document "$EC2_S3_SSM_POLICY" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with S3 Access Policy .: ${EC2_ROLE_S3_PROJ}"
      # ___
      # Add access to SSM Parameter Store user-admin-auth
      aws iam put-role-policy --role-name "${!VAR_NAME}"  \
          --policy-name "$EC2_ROLE_SSM_NAME"               \
          --policy-document "$EC2_SSM_SSM_POLICY" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with S3 Access Policy .: ${EC2_ROLE_SSM_NAME}"
      # ___
      # Add access to dcv-license bucket
      aws iam put-role-policy --role-name "${!VAR_NAME}"  \
          --policy-name "$EC2_ROLE_S3_DCV"               \
          --policy-document "$EC2_S3_DCV_POLICY" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with S3 Access Policy .: ${EC2_ROLE_S3_DCV}"
      # ___
      # Managed Policy CloudWatch Agent
      EC2_ROLE_MANAGED_ARN="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
      aws iam attach-role-policy --role-name "${!VAR_NAME}" \
        --policy-arn "$EC2_ROLE_MANAGED_ARN" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with Managed Policy ...: ${EC2_ROLE_MANAGED_ARN}"
      # ___
      # Managed Policy SSM Automation
      EC2_ROLE_MANAGED_ARN="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      aws iam attach-role-policy --role-name "${!VAR_NAME}" \
        --policy-arn "$EC2_ROLE_MANAGED_ARN" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with Managed Policy ...: ${EC2_ROLE_MANAGED_ARN}"
      # ___
      # Managed Policy Power User !!! TEMPORARY NEED TO REFINE AFTER DEBUG
      EC2_ROLE_MANAGED_ARN="arn:aws:iam::aws:policy/PowerUserAccess"
      aws iam attach-role-policy --role-name "${!VAR_NAME}" \
        --policy-arn "$EC2_ROLE_MANAGED_ARN" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with Managed Policy ...: ${EC2_ROLE_MANAGED_ARN}"
      # ...
  # Polcies for Golden Image AMI Build Phase
  elif [[ $PREFIX == "PUB" ]]; then
      # Add access to project bucket
      aws iam put-role-policy --role-name "${!VAR_NAME}"  \
          --policy-name "$EC2_ROLE_S3_PROJ"               \
          --policy-document "$EC2_S3_PUB_POLICY" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with S3 Access Policy .: ${EC2_ROLE_S3_PROJ}"
      # ___
      # Add access to dcv-license bucket
      aws iam put-role-policy --role-name "${!VAR_NAME}"  \
          --policy-name "$EC2_ROLE_S3_DCV"               \
          --policy-document "$EC2_S3_DCV_POLICY" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with S3 Access Policy .: ${EC2_ROLE_S3_DCV}"
      # ___
      # Managed Policy CloudWatch Agent
      EC2_ROLE_MANAGED_ARN="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
      aws iam attach-role-policy --role-name "${!VAR_NAME}" \
        --policy-arn "$EC2_ROLE_MANAGED_ARN" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with Managed Policy ...: ${EC2_ROLE_MANAGED_ARN}"
      # ___
      # Managed Policy SSM Automation
      # Include this policy if you need to Run SSM Documents on the Build Stage Instance
      EC2_ROLE_MANAGED_ARN="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      aws iam attach-role-policy --role-name "${!VAR_NAME}" \
        --policy-arn "$EC2_ROLE_MANAGED_ARN" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with Managed Policy ...: ${EC2_ROLE_MANAGED_ARN}"
      # ___
      # Managed Policy Power User !!! TEMPORARY NEED TO REFINE AFTER DEBUG
      EC2_ROLE_MANAGED_ARN="arn:aws:iam::aws:policy/PowerUserAccess"
      aws iam attach-role-policy --role-name "${!VAR_NAME}" \
        --policy-arn "$EC2_ROLE_MANAGED_ARN" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with Managed Policy ...: ${EC2_ROLE_MANAGED_ARN}"
      # ...
  # Policies for Autoscaling Launch Template Instances
  else 
      # Add access to project bucket
      aws iam put-role-policy --role-name "${!VAR_NAME}"  \
          --policy-name "$EC2_ROLE_S3_PROJ"               \
          --policy-document "$EC2_S3_LT_POLICY" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with S3 Access Policy .: ${EC2_ROLE_S3_PROJ}"
      # ___
      # Add access to dcv-license bucket
      aws iam put-role-policy --role-name "${!VAR_NAME}"  \
          --policy-name "$EC2_ROLE_S3_DCV"               \
          --policy-document "$EC2_S3_DCV_POLICY" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with S3 Access Policy .: ${EC2_ROLE_S3_DCV}"
      # ___
      # Managed Policy CloudWatch Agent
      EC2_ROLE_MANAGED_ARN="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
      aws iam attach-role-policy --role-name "${!VAR_NAME}" \
        --policy-arn "$EC2_ROLE_MANAGED_ARN" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with Managed Policy ...: ${EC2_ROLE_MANAGED_ARN}"
      # ___
      # Managed Policy Power User !!! TEMPORARY NEED TO REFINE AFTER DEBUG
      EC2_ROLE_MANAGED_ARN="arn:aws:iam::aws:policy/PowerUserAccess"
      aws iam attach-role-policy --role-name "${!VAR_NAME}" \
        --policy-arn "$EC2_ROLE_MANAGED_ARN" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      echo "The IAM Role is affixed with Managed Policy ...: ${EC2_ROLE_MANAGED_ARN}"
      # ___
      # Managed Policy SSM Automation
      # Include this policy if you need to Run SSM Documents on the Autoscaled Instance
      #EC2_ROLE_MANAGED_ARN="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      #aws iam attach-role-policy --role-name "${!VAR_NAME}" \
      #  --policy-arn "$EC2_ROLE_MANAGED_ARN" --profile "$AWS_PROFILE" --region "$AWS_REGION"
      #echo "The IAM Role is affixed with Managed Policy ...: ${EC2_ROLE_MANAGED_ARN}"
      # ...
  fi
  # ___
done

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# END   EC2 INSTANCE ROLES CREATION 
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# START   UPLOAD ARTIFACTS
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#----------------------------------------------
# Create S3 Project Bucket with Encryption + Policy
if (aws s3 mb "s3://$PROJECT_BUCKET" --profile "$AWS_PROFILE" --region "$AWS_REGION" > /dev/null)
then 
  aws s3api put-bucket-encryption --bucket "$PROJECT_BUCKET"  \
      --server-side-encryption-configuration                \
      '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}' \
      --profile "$AWS_PROFILE" --region "$AWS_REGION"
      # ...
  aws s3api put-bucket-policy --bucket "$PROJECT_BUCKET"  \
      --profile "$AWS_PROFILE" --region "$AWS_REGION"   \
      --policy "file://policies/s3/${PROJECT_NAME}-policy-s3-bucket.json" \
      # ...
  echo "S3 Project Bucket Created .....................: s3://$PROJECT_BUCKET"
else
  echo "Failed to Create S3 Project Bucket !!!!!!!!!!!!: s3://$PROJECT_BUCKET"
  exit 1
fi
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Upload all created policy artifacts to S3
find ./policies -type f -name "${PROJECT_NAME}*.json" ! -path "*/scratch/*" -print0 |
  while IFS= read -r -d '' FILE
  do
    if [[ ! -s "$FILE" ]]; then
      echo "Error! Invalid Template Policy Document .......: $FILE"
      exit 1
      # ...
    elif (aws s3 mv "$FILE" "s3://$PROJECT_BUCKET${FILE#.}" --profile "$AWS_PROFILE" \
          --region "$AWS_REGION" > /dev/null)
    then
      echo "Uploading Policy Document to S3 Location ......: s3://$PROJECT_BUCKET${FILE#.}"
      # ...
    else continue
    fi
  done
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Upload Cloudformation Template artifacts to S3
find -L ./cfn-templates -type f -name "*.yaml" ! -path "*/scratch/*" -print0 |
# -L : Follow symbolic links
  while IFS= read -r -d '' FILE
  do
    if [[ ! -s "$FILE" ]]; then
      echo "Invalid Cloudformation Template Document ......: $FILE"
      exit 1
      # ...
    elif (aws s3 cp "$FILE" "s3://$PROJECT_BUCKET${FILE#.}" --profile "$AWS_PROFILE" \
          --region "$AWS_REGION" > /dev/null)
    then
      echo "Uploading Cloudformation Template to S3 .......: s3://$PROJECT_BUCKET${FILE#.}"
      # ...
    else continue
    fi
  done
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Compress & Upload CloudWatch Agent config to S3
# Remove hierarchy from archives for more flexible extraction options.
S3_LOCATION="s3://$PROJECT_BUCKET/logs"
if [[ $(gzip -c ./logs/*.tar | aws s3 cp - ${S3_LOCATION}/${PROJECT_NAME}-amzn-cw-agent.json.tar.gz \
    --profile "$AWS_PROFILE" --region "$AWS_REGION") -ne 0 ]]
then
  echo "CW Agent Config Failed to Uploaded to S3 ......: ${S3_LOCATION}"
  exit 1
  # ...
else
  echo "CW Agent Config Uploaded to S3 Location .......: ${S3_LOCATION}"
  # archive extracted & no longer needed
  rm ./logs/${PROJECT_NAME}*.tar
  # ...
fi
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Upload to S3 SSM Postupdate Powershell Script as well as EC2LaunchV2 custom yaml config
find -L ./ssm -type f \( -name "${PROJECT_NAME}*.ps1" -o -name "${PROJECT_NAME}*.yml" \) \
  ! -path "*/scratch/*" -print0 |
#----------------------------------------------
  while IFS= read -r -d '' FILE
  do
    if [[ ! -s "$FILE" ]]; then
      echo "Error! Invalid SSM Powershell Script ..........: $FILE"
      exit 1
      # ...
    elif (aws s3 mv "$FILE" "s3://$PROJECT_BUCKET${FILE#.}" --profile "$AWS_PROFILE" \
          --region "$AWS_REGION" > /dev/null)
    then
      echo "Uploading SSM Powershell Script to S3 Location : s3://$PROJECT_BUCKET${FILE#.}"
      # ...
    else continue
    fi
  done
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Upload Firefox Hardened Profile to S3
#find -L ./firefox -type f -name "firefox-profile*.zip" ! -path "*/scratch/*" -print0 |
#  while IFS= read -r -d '' FILE
#  do
#    echo "Attempting to Upload Firefox Profile Archive ..: $FILE"
#    # ...
#    if [[ ! -s "$FILE" ]]; then
#      echo "Error! Invalid Firefox Profile Archive ........: $FILE"
#      exit 1
#      # ...
#    elif (aws s3 cp "$FILE" "s3://$PROJECT_BUCKET${FILE#.}" --profile "$AWS_PROFILE" \
#          --region "$AWS_REGION" > /dev/null)
#    then
#      echo "Uploading Firefox Profile Archive to S3 .......: s3://$PROJECT_BUCKET${FILE#.}"
#      # ...
#    else continue
#    fi
#  done
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Upload Firefox Hardened Profile Aritifacts to S3
find -L ./firefox -type f -name "${PROJECT_NAME}-firefox-profile*" ! -path "*/scratch/*" -print0 |
  while IFS= read -r -d '' FILE
  do
    echo "Attempting to Upload Firefox Profile Artifact .: $FILE"
    # ...
    if [[ ! -s "$FILE" ]]; then
      echo "Error! Invalid Firefox Profile Artifact .......: $FILE"
      exit 1
      # ...
    elif (aws s3 cp "$FILE" "s3://$PROJECT_BUCKET${FILE#.}" --profile "$AWS_PROFILE" \
          --region "$AWS_REGION" > /dev/null)
    then
      echo "Uploading Firefox Profile Artifact to S3 ......: s3://$PROJECT_BUCKET${FILE#.}"
      # ...
    else continue
    fi
  done
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# END   UPLOAD ARTIFACTS 
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# START   CLOUDFORMATION STACK CREATION STAGE1
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# Create the foundational/immutable architecture for the project
BUILD_COUNTER="stage1"
# ___
TEMPLATE_URL="https://${PROJECT_BUCKET}.s3.${AWS_REGION}\
.amazonaws.com/cfn-templates/cfn-gpu-cli.yaml"
# ___
STACK_POLICY_URL="https://${PROJECT_BUCKET}.s3.${AWS_REGION}\
.amazonaws.com/policies/cfn/${PROJECT_NAME}-policy-cfn${BUILD_COUNTER}-stack.json"
# ___
echo "Cloudformation Stack Creation Initiated .......: $BUILD_COUNTER"
echo "Cloudformation Stack Template URL .............: $TEMPLATE_URL"
# ___
STACK_ID=$(aws cloudformation create-stack --stack-name "$STACK_NAME" --parameters      \
                ParameterKey=ProjectName,ParameterValue="$PROJECT_NAME"                 \
                ParameterKey=BuildStep,ParameterValue="$BUILD_COUNTER"                  \
                ParameterKey=GamingDomainName,ParameterValue="$AWS_DOMAIN_NAME"         \
                ParameterKey=GamingHostedZoneId,ParameterValue="$HOSTED_ZONE_ID"        \
                ParameterKey=SshAccessCIDR,ParameterValue="$SSH_ACCESS_CIDR"            \
                ParameterKey=CurrentAmi,ParameterValue="$AMI_LATEST"                    \
                ParameterKey=GamingEmailAddrSNS,ParameterValue="$USER_EMAIL"            \
                ParameterKey=SpotBlockDuration,ParameterValue="$SPOT_DURATION"          \
                --tags Key=Name,Value="$PROJECT_NAME"                                   \
                --stack-policy-url "$STACK_POLICY_URL" --template-url "$TEMPLATE_URL"   \
                --profile "$AWS_PROFILE" --region "$AWS_REGION"                         \
                --on-failure DO_NOTHING --capabilities CAPABILITY_NAMED_IAM --output text)
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Wait for stack creation to complete
if [[ $? -eq 0 ]]; then
  echo "Cloudformation Stack Creation In Progress .....: $STACK_ID"
  CHECK_STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" --output text \
    --query 'Stacks[0].StackStatus' --profile "$AWS_PROFILE" --region "$AWS_REGION")
  while [[ $CHECK_STATUS == "REVIEW_IN_PROGRESS" ]] || [[ $CHECK_STATUS == "CREATE_IN_PROGRESS" ]]
  do
      # Wait x seconds and then check stack status again
      sleep 5
      printf '.'
      CHECK_STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" --output text \
        --query 'Stacks[0].StackStatus' --profile "$AWS_PROFILE" --region "$AWS_REGION")
  done
  printf '\n'
fi
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Validate stack creation Success
if (aws cloudformation wait stack-create-complete --stack-name "$STACK_ID" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION")
then 
  echo "Cloudformation Stack Create Process Complete ..: $BUILD_COUNTER"
else 
  echo "Error: Stack Create Failed!"
  exit 1
fi
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Calculate Stack Creation Execution Time
TIME_END_PT=$(date +%s)
TIME_DIFF_PT=$((TIME_END_PT - TIME_START_PROJ))
echo "$BUILD_COUNTER Finished Execution Time ................: \
$(( TIME_DIFF_PT / 3600 ))h $(( (TIME_DIFF_PT / 60) % 60 ))m $(( TIME_DIFF_PT % 60 ))s"

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# END   CLOUDFORMATION STACK CREATION STAGE1
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<



#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# START   SSM AUTOMATION 
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# Check if SSM UpdateWindowsAmi Already Exists
AMI_UPDATE=$(aws ec2 describe-images --filters "Name=tag:Name,Values=$PROJECT_NAME-ssm-update" \
  --owners self --query 'Images[].ImageId' --output text --profile "$AWS_PROFILE" \
  --region "$AWS_REGION")
# ___
# Skip SSM UpdateWindowsAmi Automation if found.
if [[ ! -z "$AMI_UPDATE" ]]; then
  echo "Omitting Automation, UpdateWindowsAmi found ...: $AMI_UPDATE"
else
  # Execute SSM UpdateWindowsAmi Document
  echo "Will now perform SSM Update on the Latest AMI .: $AMI_LATEST"
  # ___
  # Execute Automation Document to Update AMI
  SSM_AUTO_DOC="AWS-UpdateWindowsAmi"
  # ___
  # Choose Instance Size : NVidia Drivers require g4 selection, else t2 dev instance cheaper.
  SSM_AUTO_EC2="t2.micro"
  #SSM_AUTO_EC2="g4dn.xlarge"
  # ___
  # Instance Profile
  SSM_EC2_PROFILE="${PROJECT_NAME}-ec2-ssm-${AWS_REGION}"
  # ___describe-images
  # Service Linked Role
  SSM_SERVICE_ROLE="arn:aws:iam::$AWS_ACC_ID:role/ce/$PROJECT_NAME-ssm-automation-$AWS_REGION"
  # ___
  # PreUpdate Powershell Command to Copy PostUpdate Script to localhost.
  SSM_PRE_UPDATE="Copy-S3Object -BucketName $PROJECT_BUCKET -KeyPrefix ssm -LocalFolder C:\\$PROJECT_BUCKET\\ssm"
  #---
  # PostUpdate Powershell Script
  SSM_POST_UPDATE="C:\\$PROJECT_BUCKET\\ssm\\$PROJECT_NAME-ssm-update-ami.ps1"
  # ___
  # Run SSM UpdateWindowsAmi Document within Secure VPC
  # Get Public Subnet ID AZ-A 
  SUBNET_PUB_ID_A=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" --output text \
    --query "Stacks[].Outputs[?OutputKey == 'PublicSubnetIdA'].OutputValue")
  # ___
  # Execute the Automation Document
  COMMAND_ID=$(aws ssm start-automation-execution --document-name="$SSM_AUTO_DOC"           \
    --query 'AutomationExecutionId' --profile "$AWS_PROFILE" --region "$AWS_REGION"         \
    --tags Key=Project,Value="${PROJECT_NAME}" --parameters "SourceAmiId=$AMI_LATEST,       \
    IamInstanceProfileName=$SSM_EC2_PROFILE,AutomationAssumeRole=$SSM_SERVICE_ROLE,         \
    TargetAmiName=${PROJECT_NAME}-ssm-update,PreUpdateScript=$SSM_PRE_UPDATE,               \
    PostUpdateScript=$SSM_POST_UPDATE,InstanceType=$SSM_AUTO_EC2,SubnetId=$SUBNET_PUB_ID_A" \
    --output text)
  # ___
  # Execute the Automation Document
  #COMMAND_ID=$(aws ssm start-automation-execution --document-name="$SSM_AUTO_DOC"     \
  #  --query 'AutomationExecutionId' --profile "$AWS_PROFILE" --region "$AWS_REGION"   \
  #  --tags Key=Project,Value="${PROJECT_NAME}" --parameters "SourceAmiId=$AMI_LATEST, \
  #  IamInstanceProfileName=$SSM_EC2_PROFILE,InstanceType=$SSM_AUTO_EC2,               \
  #  AutomationAssumeRole=$SSM_SERVICE_ROLE,SubnetId=$SUBNET_PUB_ID_A,                 \
  #  TargetAmiName=${PROJECT_NAME}-ssm-update" --output text)
  # ___
  # Provide Feedback on Automation Status
  if [[ $? -eq 0 ]]; then
    echo "SSM Automation Execution Command ID ...........: $COMMAND_ID"
    CHECK_STATUS=$(aws ssm describe-automation-executions --profile "$AWS_PROFILE"  \
      --region "$AWS_REGION" --filter "Key=ExecutionId,Values=$COMMAND_ID"          \
      --output text --query 'AutomationExecutionMetadataList[].AutomationExecutionStatus')
    echo "SSM Automation Execution Status ...............: $CHECK_STATUS"
    while [[ $CHECK_STATUS == "InProgress" ]]; do
      printf '.'
      sleep 10
      CHECK_STATUS=$(aws ssm describe-automation-executions --profile "$AWS_PROFILE"  \
        --region "$AWS_REGION" --filter "Key=ExecutionId,Values=$COMMAND_ID"          \
        --output text --query 'AutomationExecutionMetadataList[].AutomationExecutionStatus')
    done
    printf '\n'
    [[ $CHECK_STATUS == "Failed" ]] && \
    { echo "SSM Failed to Execute Auto Update AMI .........: $COMMAND_ID"; exit 1; } \
    || { echo "SSM Automation Execution Status ...............: $CHECK_STATUS"; }
  fi
  # ___
  # Automation Success ??? then Process SSM UpdateWindowsAmi AMI ID
  if [[ $CHECK_STATUS == "Success" ]]; then
    AMI_UPDATE=$(aws ssm describe-automation-executions --output text --profile "$AWS_PROFILE" \
      --filter "Key=ExecutionId,Values=$COMMAND_ID"  --region "$AWS_REGION" \
      --query 'AutomationExecutionMetadataList[].Outputs.["CreateImage.ImageId"]')
    echo "SSM Automation Updated AMI ....................: $AMI_UPDATE"
    # ___
    # Give AMI a Name Tag
    aws ec2 create-tags --resources "$AMI_UPDATE" --profile "$AWS_PROFILE" \
      --region "$AWS_REGION" --tags Key=Name,Value="${PROJECT_NAME}-ssm-update"
    # ___
  else 
    echo "SSM Automation UpdateWindowsAmi Failed! .......: $CHECK_STATUS"
    exit 1
  fi
  # ___
fi

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# END   SSM AUTOMATION
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# START   GOLDEN AMI CREATION
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#----------------------------------------------
# Check if Golden Image AMI Already Exists
AMI_BUILD=$(aws ec2 describe-images --filters "Name=tag:Name,Values=${PROJECT_NAME}-pub-build" \
  --owners self --query 'Images[].ImageId' --output text --profile "$AWS_PROFILE" \
  --region "$AWS_REGION")
# ___
# Perform Golden Image Creation if not found.
if [[ ! -z "$AMI_BUILD" ]]; then
  echo "Omit Golden Image creation, Build AMI found ...: $AMI_BUILD"
else
  # Execute Golden Image Creation routine
  echo "Will now build Golden Image AMI on Update AMI .: $AMI_UPDATE"
  # ___
  BUILD_COUNTER="stage2"
  # ___
  echo "Cloudformation Stack Update Initiated .........: $BUILD_COUNTER"
  # ___
  aws cloudformation update-stack --stack-name "$STACK_ID" --parameters \
        ParameterKey=BuildStep,ParameterValue="$BUILD_COUNTER"          \
        ParameterKey=CurrentAmi,ParameterValue="$AMI_UPDATE"            \
        ParameterKey=ProjectName,UsePreviousValue=true                  \
        ParameterKey=GamingDomainName,UsePreviousValue=true             \
        ParameterKey=GamingHostedZoneId,UsePreviousValue=true           \
        ParameterKey=SshAccessCIDR,UsePreviousValue=true                \
        ParameterKey=GamingEmailAddrSNS,UsePreviousValue=true           \
        --stack-policy-url "$STACK_POLICY_URL" --use-previous-template  \
        --profile "$AWS_PROFILE" --region "$AWS_REGION"                 \
        --tags Key=Name,Value="$PROJECT_NAME" > /dev/null    
  #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  # ____________________________
  if [[ $? -eq 0 ]]; then
    # Wait for stack creation to complete
    echo "Cloudformation Stack Update In Progress .......: $STACK_ID"
    CHECK_STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" \
      --query 'Stacks[0].StackStatus' --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
    while [[ $CHECK_STATUS == "UPDATE_IN_PROGRESS" ]] || [[ $CHECK_STATUS == "CREATE_IN_PROGRESS" ]]
    do
        # Wait x seconds and then check stack status again
        sleep 5
        printf '.'
        CHECK_STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" --output text \
          --query 'Stacks[0].StackStatus' --profile "$AWS_PROFILE" --region "$AWS_REGION")
    done
    printf '\n'
  fi
  #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  # ____________________________
  # Validate stack creation has not failed
  if (aws cloudformation wait stack-update-complete --stack-name "$STACK_ID" \
      --region "$AWS_REGION" --profile "$AWS_PROFILE")
  then 
    echo "Cloudformation Stack Update Process Complete ..: $BUILD_COUNTER"
  else 
    echo "Error: Stack Update Failed!"
    exit 1
  fi
  #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  # ____________________________
  # Get EC2 Instance ID
  INSTANCE_PUB_ID=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" --output text \
    --query "Stacks[].Outputs[?OutputKey == 'InstanceIdPublicBuild'].OutputValue"             \
    --profile "$AWS_PROFILE" --region "$AWS_REGION")
  echo "Golden AMI Build Stage EC2 Instance ID ........: $INSTANCE_PUB_ID"
  #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  # ____________________________
  # Wait for instance status stopped before moving on.
  # Userdata Script stops instance when script is complete.
  echo "Waiting on Instance Status Stopped ............: "
  CHECK_INSTANCE_STATUS=$(aws ec2 describe-instances --instance-ids "$INSTANCE_PUB_ID"   \
    --query 'Reservations[].Instances[].State.Name' --output text --profile "$AWS_PROFILE" \
    --region "$AWS_REGION")
  while [[ $CHECK_INSTANCE_STATUS != "stopped" ]]
  do
      # Wait 3 seconds and then check stack status again
      sleep 3
      printf '.'
      CHECK_INSTANCE_STATUS=$(aws ec2 describe-instances --instance-ids "$INSTANCE_PUB_ID"   \
        --query 'Reservations[].Instances[].State.Name' --output text --profile "$AWS_PROFILE" \
        --region "$AWS_REGION")
  done
  printf '\n'
  echo "Golden AMI Build Stage EC2 Instance State .....: $CHECK_INSTANCE_STATUS"
  #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  # ____________________________
  # Create Golden AMI
  echo "Start Process of Golden Image Creation ........: "
  AMI_BUILD=$(aws ec2 create-image --instance-id "$INSTANCE_PUB_ID" --profile "$AWS_PROFILE" \
    --name "${PROJECT_NAME}-pub-build" --description "${PROJECT_NAME}-pub-build-ami" \
    --output text  --region "$AWS_REGION")
  #.............................
  if [[ $? -eq 0 ]]; then
    # Wait for detection to complete
    echo "Waiting for AMI Creation to complete ..........: $AMI_BUILD"
    CHECK_AMI_STATUS=$(aws ec2 describe-images --image-ids "$AMI_BUILD" --output text \
      --query 'Images[].State' --profile "$AWS_PROFILE" --region "$AWS_REGION")
    while [[ $CHECK_AMI_STATUS != "available" ]]
    do
        # Wait 3 seconds and then check stack status again
        sleep 3
        printf '.'
        CHECK_AMI_STATUS=$(aws ec2 describe-images --image-ids "$AMI_BUILD" --output text \
          --query 'Images[].State' --profile "$AWS_PROFILE" --region "$AWS_REGION")
    done
    printf '\n'
    echo "Build Stage Golden Image Status ...............: $CHECK_AMI_STATUS "
  else
    echo "Error! Creation of Golden Image failed ........: $INSTANCE_PUB_ID"
    exit 1
  fi
  #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  # ____________________________
  # Give AMI a Name Tag
  aws ec2 create-tags --resources "$AMI_BUILD" --profile "$AWS_PROFILE" \
    --tags Key=Name,Value="${PROJECT_NAME}-pub-build" --region "$AWS_REGION"
  #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  # ____________________________
  # Terminate the instances - no longer needed.
  aws ec2 terminate-instances --instance-ids "$INSTANCE_PUB_ID" --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" > /dev/null
  #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  # If you need to delete SSM Update AMI do it here
  # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

  # ____________________________
  # Calculate AMI Creation Execution Time
  TIME_END_PT=$(date +%s)
  TIME_DIFF_PT=$((TIME_END_PT - TIME_START_PROJ))
  echo "Golden Image Build Complete, AMI Available ....: \
  $(( TIME_DIFF_PT / 3600 ))h $(( (TIME_DIFF_PT / 60) % 60 ))m $(( TIME_DIFF_PT % 60 ))s"
  #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  # ___
fi

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# END   GOLDEN AMI CREATION
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<



#!! COMMENT Construct Begins Here:
: <<'END'
#!! COMMENT BEGIN





#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# START   CLOUDFORMATION STACK CREATION STAGE4
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# Actualize all the "Bells and Whistles" of the architecture here.
# eg. Autoscaling/Loadbalancer/Telemetry
BUILD_COUNTER="stage4"
# ___
echo "Cloudformation Stack Update Initiated .........: $BUILD_COUNTER"
# ___
aws cloudformation update-stack --stack-name "$STACK_ID" --parameters \
      ParameterKey=BuildStep,ParameterValue="$BUILD_COUNTER"          \
      ParameterKey=CurrentAmi,ParameterValue="$AMI_BUILD"             \
      ParameterKey=ProjectName,UsePreviousValue=true                  \
      ParameterKey=GamingDomainName,UsePreviousValue=true             \
      ParameterKey=GamingHostedZoneId,UsePreviousValue=true           \
      ParameterKey=SshAccessCIDR,UsePreviousValue=true                \
      ParameterKey=GamingEmailAddrSNS,UsePreviousValue=true           \
      --stack-policy-url "$STACK_POLICY_URL" --use-previous-template  \
      --profile "$AWS_PROFILE" --region "$AWS_REGION"                 \
      --tags Key=Name,Value="$PROJECT_NAME" > /dev/null    
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
if [[ $? -eq 0 ]]; then
  # Wait for stack creation to complete
  echo "Cloudformation Stack Update In Progress .......: $STACK_ID"
  CHECK_STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" \
    --query 'Stacks[0].StackStatus' --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
  while [[ $CHECK_STATUS == "UPDATE_IN_PROGRESS" ]] || [[ $CHECK_STATUS == "CREATE_IN_PROGRESS" ]]
  do
      # Wait x seconds and then check stack status again
      sleep 5
      printf '.'
      CHECK_STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK_ID" --output text \
        --query 'Stacks[0].StackStatus' --profile "$AWS_PROFILE" --region "$AWS_REGION")
  done
  printf '\n'
fi
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Validate stack creation has not failed
if (aws cloudformation wait stack-update-complete --stack-name "$STACK_ID" --profile "$AWS_PROFILE" \
    --region "$AWS_REGION")
then 
  echo "Cloudformation Stack Update Process Complete ..: $BUILD_COUNTER"
  #printf 'Stack ID: \n%s\n' "$STACK_ID"
else 
  echo "Error: Stack Update Failed!"
  #printf 'Stack ID: \n%s\n' "$STACK_ID"
  exit 1
fi
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Calculate Stack Creation Execution Time
TIME_END_PT=$(date +%s)
TIME_DIFF_PT=$((TIME_END_PT - TIME_START_PROJ))
echo "$BUILD_COUNTER Finished Execution Time ................: \
$(( TIME_DIFF_PT / 3600 ))h $(( (TIME_DIFF_PT / 60) % 60 ))m $(( TIME_DIFF_PT % 60 ))s"

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# END   CLOUDFORMATION STACK CREATION STAGE4
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<





#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# START   MISCELLANEOUS 
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#----------------------------------------------
# Get EC2 Instance ID
FILTER1="Name=tag:Name,Values=${PROJECT_NAME}-ec2-gamer"
FILTER2="Name=instance-state-name,Values=running"
INSTANCE_LT_ID=$(aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' \
  --filters "$FILTER1" "$FILTER2" --output text --profile "$AWS_PROFILE" --region "$AWS_REGION")
echo "Gaming Server EC2 Instance ID .................: $INSTANCE_LT_ID"
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Get EC2 Instance DNS
INSTANCE_LT_DNS=$(aws ec2 describe-instances --instance-ids "$INSTANCE_LT_ID" \
    --query 'Reservations[].Instances[].PublicDnsName' --output text            \
    --profile  "$AWS_PROFILE" --region "$AWS_REGION")
echo "Gaming Server EC2 Instance DNS ................: $INSTANCE_LT_DNS"
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Validity Check. Wait for instance status ok before moving on.
echo "Waiting on Instance Status ok .................: $INSTANCE_LT_ID"
CHECK_INSTANCE_STATUS=$(aws ec2 describe-instance-status --instance-ids "$INSTANCE_LT_ID"   \
  --query 'InstanceStatuses[0].InstanceStatus.Status' --output text --profile "$AWS_PROFILE" \
  --region "$AWS_REGION")
while [[ $CHECK_INSTANCE_STATUS != "ok" ]]
do
    # Wait x seconds and then check stack status again
    sleep 5
    printf '.'
    CHECK_INSTANCE_STATUS=$(aws ec2 describe-instance-status --instance-ids "$INSTANCE_LT_ID"   \
      --query 'InstanceStatuses[0].InstanceStatus.Status' --output text --profile "$AWS_PROFILE" \
      --region "$AWS_REGION")
done
printf '\n'
echo "Spot Block Launch Template Instance State .....: OK"
#-----------------------------


#----------------------------------------------
# Create DCV Network Loadbalancer client configuration
CONFIG_DCV_R53="${PROJECT_NAME}-${AWS_REGION}.${AWS_DOMAIN_NAME}.dcv"
FQDN_DCV_R53="${PROJECT_NAME}-${AWS_REGION}.${AWS_DOMAIN_NAME}"

printf '[version]\n' > ./rdp/$CONFIG_DCV_R53
printf 'format=1.0\n\n' >> ./rdp/$CONFIG_DCV_R53
printf '[connect]\n' >> ./rdp/$CONFIG_DCV_R53
printf 'host=%s\n' $FQDN_DCV_R53 >> ./rdp/$CONFIG_DCV_R53
printf 'port=8443\n' >> ./rdp/$CONFIG_DCV_R53
printf 'user=Administrator\n' >> ./rdp/$CONFIG_DCV_R53
printf 'password=%s\n' $ADMIN_AUTH_PASS >> ./rdp/$CONFIG_DCV_R53
chmod 600 "./rdp/$CONFIG_DCV_R53"
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#----------------------------------------------
# Create DCV EC2 Elastic Network Interface client configuration
CONFIG_DCV_EC2="${PROJECT_NAME}-${AWS_REGION}.compute.amazonaws.com.dcv"
FQDN_DCV_EC2="$INSTANCE_LT_DNS"

printf '[version]\n' > ./rdp/$CONFIG_DCV_EC2
printf 'format=1.0\n\n' >> ./rdp/$CONFIG_DCV_EC2
printf '[connect]\n' >> ./rdp/$CONFIG_DCV_EC2
printf 'host=%s\n' $FQDN_DCV_EC2 >> ./rdp/$CONFIG_DCV_EC2
printf 'port=8443\n' >> ./rdp/$CONFIG_DCV_EC2
printf 'user=Administrator\n' >> ./rdp/$CONFIG_DCV_EC2
printf 'password=%s\n' $ADMIN_AUTH_PASS >> ./rdp/$CONFIG_DCV_EC2
chmod 600 "./rdp/$CONFIG_DCV_EC2"
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


#----------------------------------------------
# Create RDP R53 Elastic Network Interface client configuration
CONFIG_RDP_R53="${PROJECT_NAME}-${AWS_REGION}.${AWS_DOMAIN_NAME}.rdp"
FQDN_RDP_R53="${PROJECT_NAME}-${AWS_REGION}.${AWS_DOMAIN_NAME}"

printf 'auto connect:i:1\n' > ./rdp/$CONFIG_RDP_R53
printf 'full address:s:%s\n' "$FQDN_RDP_R53" >> ./rdp/$CONFIG_RDP_R53
printf 'username:s:Administrator\n' >> ./rdp/$CONFIG_RDP_R53
printf 'password:s:%s\n' $ADMIN_AUTH_PASS >> ./rdp/$CONFIG_RDP_R53
chmod 600 "./rdp/$CONFIG_RDP_R53"
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


#----------------------------------------------
# Create RDP EC2 Elastic Network Interface client configuration
CONFIG_RDP_EC2="${PROJECT_NAME}-${AWS_REGION}.compute.amazonaws.com.rdp"
FQDN_RDP_EC2="$INSTANCE_LT_DNS"

printf 'auto connect:i:1\n' > ./rdp/$CONFIG_RDP_EC2
printf 'full address:s:%s\n' "$FQDN_RDP_EC2" >> ./rdp/$CONFIG_RDP_EC2
printf 'username:s:Administrator\n' >> ./rdp/$CONFIG_RDP_EC2
printf 'password:s:%s\n' $ADMIN_AUTH_PASS >> ./rdp/$CONFIG_RDP_EC2
chmod 600 "./rdp/$CONFIG_RDP_EC2"
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# END   MISCELLANEOUS
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<



#!! COMMENT END
END
#!! COMMENT Construct Ends Here:



#-----------------------------
# Calculate Script Total Execution Time
TIME_END_PT=$(date +%s)
TIME_DIFF_PT=$((TIME_END_PT - TIME_START_PROJ))
echo "Total Finished Execution Time .................: \
$(( TIME_DIFF_PT / 3600 ))h $(( (TIME_DIFF_PT / 60) % 60 ))m $(( TIME_DIFF_PT % 60 ))s"
#.............................

