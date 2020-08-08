cls
[string]$sharingUrl = Read-Host 'Please Enter the Onedrive-Link'
[string]$Base64Value = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($sharingUrl))
[string]$encodedUrl = "u!" + $base64Value.TrimEnd('=').Replace('/','_').Replace('+','-')

$LINK = -join('https://api.onedrive.com/v1.0/shares/', $encodedUrl, '/root/content')
Write-Host $LINK -ForegroundColor Yellow
Read-Host