<#
   This script accomplishes the following:
    1. Migrate EC2Launch to Version 2
    2. Cofigure EC2Launch with custom settings
    2. Installs AWSCLI_v2
    3. Installs firefox-esr
    4. Removes any unwanted system addons from firefox
    5. ((Downloads and installs a preconfigured hardened firefox user profile))
    6. Installs Nvidia gpu drivers and configures license
    7. Installs Nice Desktop Cloud Visualization drivers for high performance RDP
    8. ((Enables the NICE DCV QUIC UDP transport protocol))
#>

# ___________________________
# PROJECT VARIABLES
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^
#$NameOfProject = "cfn-gpu-cli"
$NameOfProject = "ProjectName"
$NameOfProjBucket = "ProjectBucket"
#$NameOfProjBucket = "proj-cfn-gpu-cli-eu-central-1"
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^

# ___________________________
# Migrate to EC2LaunchV2
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^
# create sub directory 
$EC2LaunchFilePath = "C:\$NameOfProjBucket\ec2launch"
New-Item $EC2LaunchFilePath -ItemType "directory" -Force
# download zip file
$Url = 'https://s3.amazonaws.com/amazon-ec2launch-v2-utils/MigrationTool/windows/amd64/latest/EC2LaunchMigrationTool.zip'
$ZipFileNameFull = Join-Path $EC2LaunchFilePath $(Split-Path -Path $Url -Leaf)
Invoke-WebRequest -Uri $Url -OutFile $ZipFileNameFull
# capture zip base filename
$ZipFileNameBase = (Get-Item $ZipFileNameFull).Basename
# change to archive location & extract archive
Set-Location $EC2LaunchFilePath
Expand-Archive -Path $ZipFileNameFull
# change to extracted location
$UnzipFileLocation = Join-Path $EC2LaunchFilePath "$ZipFileNameBase"
Set-Location -Path "$UnzipFileLocation"
# filter for specific driver
$ScriptFileName = Get-ChildItem -Path $UnzipFileLocation -Name -Include "*.ps1"
# execute script
powershell .\$ScriptFileName
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^


# ___________________________
# Set custom EC2Launch agent-config
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^
$BucketLocalPath = "C:\$NameOfProjBucket"
$PrefixEC2Launch = "ssm\$NameOfProject-ec2launch-agent-config.yml"
$SourceFilePath = Join-Path $BucketLocalPath $PrefixEC2Launch
$DestinFileDir = "C:\ProgramData\Amazon\EC2Launch\config"
#New-Item $DestinFileDir -ItemType "directory" -Force
$DestinFilePath = Join-Path $DestinFileDir "agent-config.yml"
Copy-Item $SourceFilePath -Destination $DestinFilePath
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^

# ___________________________
# EC2Launch agent-config password configuration
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^
#Set-Location -Path "C:\$NameOfProjBucket\ssm"
#powershell ".\$NameOfProject-ssm-agent-config.ps1"
$SsmStorePassword=Get-SSMParameter -Name "/$NameOfProject/user-admin-auth" -WithDecryption 1 -Select Parameter.Value
$env:Path += ";C:\Program Files\Amazon\EC2Launch"
$agentConfig = ec2launch get-agent-config --format json | ConvertFrom-Json
$adminPassword =@"
{
    "task": "setAdminAccount",
    "frequency": "once",
    "inputs": {
        "name": "Administrator",
        "password": {
            "type": "static",
            "data": "$SsmStorePassword"
        }
    }
}
"@
$agentConfig.config | %{if($_.stage -eq 'preReady'){$_.tasks += (ConvertFrom-Json -InputObject $adminPassword)}}
$agentConfig | ConvertTo-Json -Depth 6 | Out-File -encoding UTF8 $env:ProgramData/Amazon/EC2Launch/config/agent-config.yml
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^

# ___________________________
# awscli_v2
Start-Process msiexec.exe -Wait -ArgumentList '/i "https://awscli.amazonaws.com/AWSCLIV2.msi" /passive'
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^

# ___________________________
# firefox-esr
Start-Process msiexec.exe -Wait -ArgumentList '/i "https://download-installer.cdn.mozilla.net/pub/firefox/releases/78.14.0esr/win64/en-GB/Firefox Setup 78.14.0esr.msi" /passive'
# Removed unwanted system addons
Remove-Item -Path "C:\Program Files\Mozilla Firefox\browser\features\*.xpi" -Force
# ___________________________
# DOWNLOAD S3 OBJECTS: FIREFOX HARDENED PROFILE
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^
$FirefoxLocalPath = "C:\$NameOfProjBucket"
$PrefixFirefox = "firefox"
$ObjectsFirefox = Get-S3Object -BucketName $NameOfProjBucket -KeyPrefix $PrefixFirefox
# ...........................
foreach ($Object in $ObjectsFirefox) {
    $LocalFileName = $Object.Key
    if ($LocalFileName -ne '' -and $Object.Size -ne 0) {
        $LocalFilePath = Join-Path $FirefoxLocalPath $LocalFileName
        Copy-S3Object -BucketName $NameOfProjBucket -Key $Object.Key -LocalFile $LocalFilePath
    }
}
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^

# ___________________________
# DOWNLOAD S3 OBJECTS: NVIDIA DRIVER
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^
$NvidiaBucket = "nvidia-gaming"
$NvidiaLocalPath = "C:\$NameOfProjBucket\nvidia"
$PrefixNvidia = "windows/latest"
$ObjectsNvidia = Get-S3Object -BucketName $NvidiaBucket -KeyPrefix $PrefixNvidia
# ...........................
foreach ($Object in $ObjectsNvidia) {
    $LocalFileName = $Object.Key
    if ($LocalFileName -ne '' -and $Object.Size -ne 0) {
        $LocalFilePath = Join-Path $NvidiaLocalPath $LocalFileName
        Copy-S3Object -BucketName $NvidiaBucket -Key $Object.Key -LocalFile $LocalFilePath
    }
}
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^

# install nvidia driver
# location where zip file is located
$ZipFileLocation = Join-Path $NvidiaLocalPath $PrefixNvidia
# zip filename, including extention
$ZipFileName = Get-ChildItem -Path $ZipFileLocation -Name -Include "*.zip"
# zip file name full
$ZipFileNameFull = Join-Path $ZipFileLocation $ZipFileName
# zip file name base
$ZipFileNameBase = (Get-Item $ZipFileNameFull).Basename
# change to zip file location
Set-Location $ZipFileLocation
# extract zip file
Expand-Archive -Path $ZipFileNameFull
# change to executable file location
$UnzipFileLocation = Join-Path $ZipFileLocation "$ZipFileNameBase\Windows"
Set-Location -Path "$UnzipFileLocation"
# filter for specific driver
$ExeFileName = Get-ChildItem -Path $UnzipFileLocation -Name -Include "*server2019*.exe"
# execute driver file in silent mode
$ExeFileNameFull = Join-Path $UnzipFileLocation $ExeFileName
Start-Process -NoNewWindow -Wait -FilePath $ExeFileNameFull -ArgumentList '/s'
# ...........................

# NVIDIA Gaming license
New-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global" -Name "vGamingMarketplace" -PropertyType "DWord" -Value "2"
#reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global" /v vGamingMarketplace /t REG_DWORD /d 2
Invoke-WebRequest -Uri "https://nvidia-gaming.s3.amazonaws.com/GridSwCert-Archive/GridSwCertWindows_2021_10_2.cert" -OutFile "$Env:PUBLIC\Documents\GridSwCert.txt"
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^


# ___________________________
# Install nice-dcv driver
New-Item -ItemType "directory" -Path "C:\$NameOfProjBucket\dcv"
Set-Location -Path "C:\$NameOfProjBucket\dcv"
Start-Process msiexec.exe -Wait -ArgumentList '/i "https://d1uj6qtbmh3dt5.cloudfront.net/2021.2/Servers/nice-dcv-server-x64-Release-2021.2-11135.msi" AUTOMATIC_SESSION_OWNER=Administrator ADDLOCAL=ALL /passive /l*v dcv_install_msi.log'
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^
