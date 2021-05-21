<#
   This script accomplishes the following:
    1. Installs AWSCLI_v2
    2. Installs firefox-esr
    3. Removes any unwanted system addons from firefox
    4. Downloads and installs a preconfigured hardened firefox user profile
    5. Installs Nvidia gpu drivers and configures license
    6. Installs Nice Desktop Cloud Visualization drivers for high performance RDP
    7. Enables the NICE DCV QUIC UDP transport protocol
#>

# ___________________________
# PROJECT VARIABLES
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^
$NameOfProject = "ProjectName"
$NameOfProjBucket = "ProjectBucket"

# ___________________________
# BASIC INSTALLATIONS
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^
# awscli_v2
Start-Process msiexec.exe -Wait -ArgumentList '/i "https://awscli.amazonaws.com/AWSCLIV2.msi" /passive'
# firefox-esr
Start-Process msiexec.exe -Wait -ArgumentList '/i "https://download-installer.cdn.mozilla.net/pub/firefox/releases/78.9.0esr/win64/en-GB/Firefox Setup 78.9.0esr.msi" /passive'
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

# Install nice-dcv driver
New-Item -ItemType "directory" -Path "C:\$NameOfProjBucket\dcv"
Set-Location -Path "C:\$NameOfProjBucket\dcv"
Start-Process msiexec.exe -Wait -ArgumentList '/i "https://d1uj6qtbmh3dt5.cloudfront.net/2021.0/Servers/nice-dcv-server-x64-Release-2021.0-10242.msi" AUTOMATIC_SESSION_OWNER=Administrator ADDLOCAL=ALL /passive /l*v dcv_install_msi.log'
# Enable QUIC UDP transport protocol
#New-ItemProperty -Path "Registry::HKEY_USERS\S-1-5-18\Software\GSettings\com\nicesoftware\dcv\connectivity" -Name "enable-quic-frontend" -PropertyType "DWord" -Value "1"
