#!/bin/bash
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

#---

#-----------------------------
# Delete Instance Profile
ROLE_NAME="cfn-gpu-rig-cli-lt-iam-ec2-eu-central-1"
if (aws iam get-instance-profile --instance-profile-name "$ROLE_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION" > /dev/null 2>&1)
then
  # Detach/Delete Role Policies from Role
  aws iam detach-role-policy --role-name "$ROLE_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy
  aws iam delete-role-policy --role-name "$ROLE_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --policy-name cfn-gpu-rig-cli-lt-ec2-s3-eu-central-1
  echo "Role Polices Removed ..........................: OK"
  #...
  # Remove Role from Instance Profile
  aws iam remove-role-from-instance-profile --instance-profile-name "$ROLE_NAME" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" --role-name "$ROLE_NAME"
  echo "Roles Removed from Instance Profile ...........: $ROLE_NAME"
  #...
  # Delete Role
  aws iam delete-role --role-name "$ROLE_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION"
  echo "Role Deleted ..................................: $ROLE_NAME"
  #...
  # Delete Instance Profile
  aws iam delete-instance-profile --instance-profile-name "$ROLE_NAME"
  echo "Instance Profle Deleted .......................: $ROLE_NAME"
else
  echo "Failed to find Instance Profile ...............: $ROLE_NAME"
  #exit 1
fi
#.............................

#-----------------------------
# Delete Instance Profile
ROLE_NAME="cfn-gpu-rig-cli-priv-iam-ec2-eu-central-1"
if (aws iam get-instance-profile --instance-profile-name "$ROLE_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION" > /dev/null 2>&1)
then
  # Detach/Delete Role Policies from Role
  aws iam delete-role-policy --role-name "$ROLE_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --policy-name cfn-gpu-rig-cli-priv-ec2-s3-eu-central-1
  aws iam delete-role-policy --role-name "$ROLE_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --policy-name cfn-gpu-rig-cli-priv-ec2-ssm-eu-central-1
  echo "Role Polices Removed ..........................: OK"
  #...
  # Remove Role from Instance Profile
  aws iam remove-role-from-instance-profile --instance-profile-name "$ROLE_NAME" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" --role-name "$ROLE_NAME"
  echo "Roles Removed from Instance Profile ...........: $ROLE_NAME"
  #...
  # Delete Role
  aws iam delete-role --role-name "$ROLE_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION"
  echo "Role Deleted ..................................: $ROLE_NAME"
  #...
  # Delete Instance Profile
  aws iam delete-instance-profile --instance-profile-name "$ROLE_NAME"
  echo "Instance Profle Deleted .......................: $ROLE_NAME"
else
  echo "Failed to find Instance Profile ...............: $ROLE_NAME"
  #exit 1
fi
#.............................

#-----------------------------
# Delete Instance Profile
ROLE_NAME="cfn-gpu-rig-cli-pub-iam-ec2-eu-central-1"
if (aws iam get-instance-profile --instance-profile-name "$ROLE_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION" > /dev/null 2>&1)
then
  # Detach/Delete Role Policies from Role
  aws iam delete-role-policy --role-name "$ROLE_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --policy-name cfn-gpu-rig-cli-pub-ec2-s3-eu-central-1 
  echo "Role Polices Removed ..........................: OK"
  #...
  # Remove Role from Instance Profile
  aws iam remove-role-from-instance-profile --instance-profile-name "$ROLE_NAME" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" --role-name "$ROLE_NAME"
  echo "Roles Removed from Instance Profile ...........: $ROLE_NAME"
  #...
  # Delete Role
  aws iam delete-role --role-name "$ROLE_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION"
  echo "Role Deleted ..................................: $ROLE_NAME"
  #...
  # Delete Instance Profile
  aws iam delete-instance-profile --instance-profile-name "$ROLE_NAME"
  echo "Instance Profle Deleted .......................: $ROLE_NAME"
else
  echo "Failed to find Instance Profile ...............: $ROLE_NAME"
  #exit 1
fi
#.............................

#--- 

#-----------------------------
# Delete Project Bucket 
BUCKET_NAME="s3://proj-cfn-gpu-rig-cli"
if (aws s3 ls "$BUCKET_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION" > /dev/null 2>&1)
then
  # Delete Project Bucket
  echo "Project Bucket Deletion in Progress ...........: $BUCKET_NAME"
  aws s3 rb --force "$BUCKET_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION" > /dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    echo "Project Bucket Deletion Success ...............: $BUCKET_NAME"
  else
    echo "Project Bucket Deletion Failed ................: $BUCKET_NAME"
    #exit 1
  fi
else
  echo "Failed to find Project Bucket .................: $BUCKET_NAME"
  #exit 1
fi
#.............................

#---

#-----------------------------
# Delete Project AMI  
AMI_NAME="cfn-gpu-rig-cli-gpu-build"
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

#--- 

#-----------------------------
# Delete Project Bucket 
STACK_NAME="cfn-gpu-rig-cli-stack"
if (aws cloudformation describe-stacks --stack-name "$STACK_NAME" --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" > /dev/null 2>&1)
then
  # Detach/Delete Role Policies from Role
  aws cloudformation delete-stack --stack-name "$STACK_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION"
  echo "Project Stack Deleted .........................: $STACK_NAME"
else
  echo "Failed to find Project Stack ..................: $STACK_NAME"
  #exit 1
fi
#.............................

#---
