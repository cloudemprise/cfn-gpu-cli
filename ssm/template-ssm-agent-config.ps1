$BucketLocalPath = "C:\ProjectBucket"
$PrefixEC2Launch = "ssm\ProjectName-ec2launch-agent-config.yml"
$SourceFilePath = Join-Path $BucketLocalPath $PrefixEC2Launch
$DestinFileDir = "C:\ProgramData\Amazon\EC2Launch\config"
#New-Item $DestinFileDir -ItemType "directory" -Force
$DestinFilePath = Join-Path $DestinFileDir "agent-config.yml"
Copy-Item $SourceFilePath -Destination $DestinFilePath