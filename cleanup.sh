#!/bin/bash
# debug options include -v -x
# cfn-gpu-cli.sh 
# A hardened, hightly available, cloud gaming Windows
# server cloudformation template composition.


#!! COMMENT Construct Begins Here:
: <<'END'
#!! COMMENT BEGIN

#!! COMMENT END
END
#!! COMMENT Construct Ends Here:


#----------------------------------------------
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

#----------------------------------------------
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
#.............................

#----------------------------------------------
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
#.............................

#---

#----------------------------------------------
# Routine to Delete Instance Profiles & Roles
# Roles must have the specified path prefix:
# --path /ce/
#-----------------------------
#-o-o-o-o-o-o-o-o-o-o-o-o-o-o-o
# Detach Roles & Delete Instance Profiles
aws iam list-instance-profiles --query 'InstanceProfiles[].InstanceProfileName' \
  --profile "$AWS_PROFILE" --region "$AWS_REGION" --output json \
  | jq -r .[] | grep "^$PROJECT_NAME" | grep "$AWS_REGION$" | while read -r INST_PROFILE
do
  # ___
  aws iam remove-role-from-instance-profile --instance-profile-name "$INST_PROFILE" \
    --role-name "$INST_PROFILE" --profile "$AWS_PROFILE" --region "$AWS_REGION"
  echo "Role Removed from Instance Profile ............: $INST_PROFILE"
  # ___
  aws iam delete-instance-profile --instance-profile-name "$INST_PROFILE" --profile "$AWS_PROFILE" \
    --region "$AWS_REGION"
  echo "Deleting Instance Profile .....................: $INST_PROFILE"
done
#-----------------------------
# Delete Roles 
aws iam list-roles --path "/ce/" --query 'Roles[].RoleName' --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" --output json \
  | jq -r .[] | grep "^$PROJECT_NAME" | grep "$AWS_REGION$" | while read -r ROLES
do
  echo "Removing Policies from Role ...................: $ROLES"
  # ___
  aws iam list-role-policies --role-name $ROLES --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" --output json --query 'PolicyNames' \
    | jq -r .[] | while read -r INLINE_POLICY
  do
    aws iam delete-role-policy --role-name "$ROLES" --policy-name "$INLINE_POLICY" \
      --profile "$AWS_PROFILE" --region "$AWS_REGION"
    echo "Inline Policy Deleted from Role ...............: $INLINE_POLICY"
  done
  # ___
  aws iam list-attached-role-policies --role-name $ROLES --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" --output json --query 'AttachedPolicies[].PolicyArn' \
    | jq -r .[] | while read -r MANAGED_POLICY
  do
  # ___
    aws iam detach-role-policy --role-name "$ROLES" --policy-arn "$MANAGED_POLICY" \
      --profile "$AWS_PROFILE" --region "$AWS_REGION"
    echo "Removed Managed Policy from Role ..............: $MANAGED_POLICY"
  done
  # ___
  aws iam delete-role --role-name "$ROLES" --profile "$AWS_PROFILE" --region "$AWS_REGION"
  echo "Role Deleted ..................................: $ROLES"
done
#-----------------------------
#-o-o-o-o-o-o-o-o-o-o-o-o-o-o-o

#--- 

#----------------------------------------------
# Delete Project Bucket 
#PROJECT_BUCKET="s3://proj-cfn-gpu-cli"
if (aws s3 ls "s3://$PROJECT_BUCKET" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    > /dev/null 2>&1)
then
  # Delete Project Bucket
  echo "Project Bucket Deletion in Progress ...........: $PROJECT_BUCKET"
  aws s3 rb --force "s3://$PROJECT_BUCKET" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    > /dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    echo "Project Bucket Deletion Success ...............: $PROJECT_BUCKET"
  else
    echo "Project Bucket Deletion Failed ................: $PROJECT_BUCKET"
    #exit 1
  fi
else
  echo "Failed to find Project Bucket .................: $PROJECT_BUCKET"
  #exit 1
fi
#.............................

#--- 

#----------------------------------------------
# Delete Project Cloudformation Stack 
STACK_NAME="$PROJECT_NAME-stack"
if (aws cloudformation describe-stacks --stack-name "$STACK_NAME" --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" > /dev/null 2>&1)
then
  # ___
  aws cloudformation delete-stack --stack-name "$STACK_NAME" --profile "$AWS_PROFILE" \
    --region "$AWS_REGION"
  echo "Project Stack Deleted .........................: $STACK_NAME"
else
  echo "Failed to find Project Stack ..................: $STACK_NAME"
  #exit 1
fi
#.............................

#---

#---

#----------------------------------------------
# Delete Project AMI  
AMI_NAME="$PROJECT_NAME-pub-build"
AMI_ID=$(aws ec2 describe-images --filters Name=name,Values=${AMI_NAME} --owners self --output text \
  --query 'Images[].ImageId' --profile "$AWS_PROFILE" --region "$AWS_REGION" 2> /dev/null)
if [[ "$AMI_ID" != "" ]]
then
  echo "AMI Found .....................................: $AMI_ID"
  # Get Snapshot ID
  SNAPSHOT_ID=$(aws ec2 describe-images --filters Name=name,Values=${AMI_NAME} \
                --output text --query 'Images[].BlockDeviceMappings[].Ebs.SnapshotId' \
                --profile "$AWS_PROFILE" --region "$AWS_REGION")
  echo "Snapshot Found ................................: $SNAPSHOT_ID"
  # Deregister AMI
  aws ec2 deregister-image --image-id "$AMI_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION"
  echo "AMI Deregistred ...............................: OK"
  # Snapshot Deleted
  aws ec2 delete-snapshot --snapshot-id "$SNAPSHOT_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION"

  echo "Snapshot Deleted ..............................: OK"
else
  echo "Failed to find Project AMI ....................: $AMI_NAME"
  #exit 1
fi
#.............................


#!! COMMENT Construct Begins Here:
: <<'END'
#!! COMMENT BEGIN




#----------------------------------------------
# Delete SSM Update AMI  
AMI_NAME="cfn-gpu-cli-ssm-update"
AMI_ID=$(aws ec2 describe-images --filters Name=name,Values=${AMI_NAME} --owners self --output text \
  --query 'Images[].ImageId' --profile "$AWS_PROFILE" --region "$AWS_REGION" 2> /dev/null)
if [[ "$AMI_ID" != "" ]]
then
  echo "AMI Found .....................................: $AMI_ID"
  # Get Snapshot ID
  SNAPSHOT_ID=$(aws ec2 describe-images --filters Name=name,Values=${AMI_NAME} \
                --output text --query 'Images[].BlockDeviceMappings[].Ebs.SnapshotId' \
                --profile "$AWS_PROFILE" --region "$AWS_REGION")
  echo "Snapshot Found ................................: $SNAPSHOT_ID"
  # Deregister AMI
  aws ec2 deregister-image --image-id "$AMI_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION"
  echo "AMI Deregistred ...............................: OK"
  # Snapshot Deleted
  aws ec2 delete-snapshot --snapshot-id "$SNAPSHOT_ID" --profile "$AWS_PROFILE" --region "$AWS_REGION"

  echo "Snapshot Deleted ..............................: OK"
else
  echo "Failed to find SSM update AMI .................: $AMI_NAME"
  #exit 1
fi
#.............................


#!! COMMENT END
END
#!! COMMENT Construct Ends Here:



#!! COMMENT Construct Begins Here:
: <<'END'
#!! COMMENT BEGIN

#!! COMMENT END
END
#!! COMMENT Construct Ends Here: