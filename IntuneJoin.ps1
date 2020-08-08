$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$Host.UI.RawUI.BackgroundColor = ($bckgrnd = 'Black')
[console]::BufferWidth = [console]::WindowWidth
$host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(8192,50)
$maxWS = $host.UI.RawUI.Get_MaxWindowSize()
$ws = $host.ui.RawUI.WindowSize
IF($maxws.width -ge 100)
{ $ws.width = 100 }
ELSE { $ws.width = $maxws.width }
IF($maxws.height -ge 20)
{ $ws.height = 20 }
ELSE { $ws.height = $maxws.height }
$host.ui.RawUI.Set_WindowSize($ws)
$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
$testadmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if ($testadmin -eq $false) {
  Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
  exit $LASTEXITCODE
}
#>-----------------------------------------------------------------------------
function New_Entry ([int]$xposi,[int]$yposi,[string]$Text,[System.ConsoleColor]$Color) 
{
    $position=$Host.ui.RawUI.CursorPosition
    $position.x = $xposi
    $position.y = $yposi
    $Host.ui.RawUI.CursorPosition=$position
    Write-Host $Text -ForegroundColor $Color
}
#>-----------------------------------------------------------------------------

function fu-WindowsAutoPilotInfo()
{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)][alias("DNSHostName","ComputerName","Computer")] [String[]] $Name = @("localhost"),
    [Parameter(Mandatory=$False)] [String] $OutputFile = "", 
    [Parameter(Mandatory=$False)] [String] $GroupTag = "",
    [Parameter(Mandatory=$False)] [Switch] $Append = $false,
    [Parameter(Mandatory=$False)] [System.Management.Automation.PSCredential] $Credential = $null,
    [Parameter(Mandatory=$False)] [Switch] $Partner = $false,
    [Parameter(Mandatory=$False)] [Switch] $Force = $false,
    [Parameter(Mandatory=$False)] [Switch] $Online = $false,
    [Parameter(Mandatory=$False)] [String] $AddToGroup = "",
    [Parameter(Mandatory=$False)] [Switch] $Assign = $false
  )

  Begin
  {
    # Initialize empty list
    $computers = @()

    # If online, make sure we are able to authenticate
    if ($Online) {

      # Get WindowsAutopilotIntune module (and dependencies)
      $module = Import-Module WindowsAutopilotIntune -PassThru -ErrorAction Ignore
      if (-not $module) {
        Write-Host "Installing module WindowsAutopilotIntune"
        Install-Module WindowsAutopilotIntune -Force
      }
      Import-Module WindowsAutopilotIntune -Scope Global

      # Get Azure AD if needed
      if ($AddToGroup)
      {
        $module = Import-Module AzureAD -PassThru -ErrorAction Ignore
        if (-not $module)
        {
          Write-Host "Installing module WindowsAutopilotIntune"
          Install-Module WindowsAutopilotIntune -Force
        }
      }

      # Connect
      $graph = Connect-MSGraph
      Write-Host "Connected to Intune tenant $($graph.TenantId)"
      if ($AddToGroup)
      {
        $aadId = Connect-AzureAD -AccountId $graph.UPN
        Write-Host "Connected to Azure AD tenant $($aadId.TenantId)"
      }

      # Force the output to a file
      if ($OutputFile -eq "")
      {
        $OutputFile = "$($env:TEMP)\autopilot.csv"
      } 
    }
  }

  Process
  {
    foreach ($comp in $Name)
    {
      $bad = $false

      # Get a CIM session
      if ($comp -eq "localhost") {
        $session = New-CimSession
      }
      else
      {
        $session = New-CimSession -ComputerName $comp -Credential $Credential
      }

      # Get the common properties.
      Write-Verbose "Checking $comp"
      $serial = (Get-CimInstance -CimSession $session -Class Win32_BIOS).SerialNumber

      # Get the hash (if available)
      $devDetail = (Get-CimInstance -CimSession $session -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'")
      if ($devDetail -and (-not $Force))
      {
        $hash = $devDetail.DeviceHardwareData
      }
      else
      {
        $bad = $true
        $hash = ""
      }

      # If the hash isn't available, get the make and model
      if ($bad -or $Force)
      {
        $cs = Get-CimInstance -CimSession $session -Class Win32_ComputerSystem
        $make = $cs.Manufacturer.Trim()
        $model = $cs.Model.Trim()
        if ($Partner)
        {
          $bad = $false
        }
      }
      else
      {
        $make = ""
        $model = ""
      }

      # Getting the PKID is generally problematic for anyone other than OEMs, so let's skip it here
      $product = ""

      # Depending on the format requested, create the necessary object
      if ($Partner)
      {
        # Create a pipeline object
        $c = New-Object psobject -Property @{
          "Device Serial Number" = $serial
          "Windows Product ID" = $product
          "Hardware Hash" = $hash
          "Manufacturer name" = $make
          "Device model" = $model
        }
        # From spec:
        #	"Manufacturer Name" = $make
        #	"Device Name" = $model

      }
      elseif ($GroupTag -ne "")
      {
        # Create a pipeline object
        $c = New-Object psobject -Property @{
          "Device Serial Number" = $serial
          "Windows Product ID" = $product
          "Hardware Hash" = $hash
          "Group Tag" = $GroupTag
        }
      }
      else
      {
        # Create a pipeline object
        $c = New-Object psobject -Property @{
          "Device Serial Number" = $serial
          "Windows Product ID" = $product
          "Hardware Hash" = $hash
        }
      }

      # Write the object to the pipeline or array
      if ($bad)
      {
        # Report an error when the hash isn't available
        Write-Error -Message "Unable to retrieve device hardware data (hash) from computer $comp" -Category DeviceError
      }
      elseif ($OutputFile -eq "")
      {
        $c
      }
      else
      {
        $computers += $c
      }

      Remove-CimSession $session
    }
  }

  End
  {
    if ($OutputFile -ne "")
    {
      if ($Append)
      {
        if (Test-Path $OutputFile)
        {
          $computers += Import-CSV -Path $OutputFile
        }
      }
      if ($Partner)
      {
        $computers | Select "Device Serial Number", "Windows Product ID", "Hardware Hash", "Manufacturer name", "Device model" | ConvertTo-CSV -NoTypeInformation | % {$_ -replace '"',''} | Out-File $OutputFile
      }
      elseif ($GroupTag -ne "")
      {
        $computers | Select "Device Serial Number", "Windows Product ID", "Hardware Hash", "Group Tag" | ConvertTo-CSV -NoTypeInformation | % {$_ -replace '"',''} | Out-File $OutputFile
      }
      else
      {
        $computers | Select "Device Serial Number", "Windows Product ID", "Hardware Hash" | ConvertTo-CSV -NoTypeInformation | % {$_ -replace '"',''} | Out-File $OutputFile
      }
    }
    if ($Online)
    {
      # Add the devices
      $importStart = Get-Date
      $imported = @()
      $computers | % {
        $imported += Add-AutopilotImportedDevice -serialNumber $_.'Device Serial Number' -hardwareIdentifier $_.'Hardware Hash' -groupTag $_.'Group Tag'
      }

      # Wait until the devices have been imported
      $processingCount = 1
        while ($processingCount -gt 0)
        {
        $current = @()
        $processingCount = 0
        $imported | % {
          $device = Get-AutopilotImportedDevice -id $_.id
                if ($device.state.deviceImportStatus -eq "unknown") {
                    $processingCount = $processingCount + 1
          }
          $current += $device
        }
            $deviceCount = $imported.Length
            Write-Host "Waiting for $processingCount of $deviceCount to be imported"
            if ($processingCount -gt 0){
                Start-Sleep 30
            }
      }
      $importDuration = (Get-Date) - $importStart
      $importSeconds = [Math]::Ceiling($importDuration.TotalSeconds)
      Write-Host "All devices imported.  Elapsed time to complete import: $importSeconds seconds"
		
      # Wait until the devices can be found in Intune (should sync automatically)
      $syncStart = Get-Date
      $processingCount = 1
        while ($processingCount -gt 0)
        {
        $autopilotDevices = @()
        $processingCount = 0
        $current | % {
          $device = Get-AutopilotDevice -id $_.state.deviceRegistrationId
                if (-not $device) {
                    $processingCount = $processingCount + 1
          }
          $autopilotDevices += $device					
        }
            $deviceCount = $autopilotDevices.Length
            Write-Host "Waiting for $processingCount of $deviceCount to be synced"
            if ($processingCount -gt 0){
                Start-Sleep 30
            }
      }
      $syncDuration = (Get-Date) - $syncStart
      $syncSeconds = [Math]::Ceiling($syncDuration.TotalSeconds)
      Write-Host "All devices synced.  Elapsed time to complete sync: $syncSeconds seconds"

      # Add the device to the specified AAD group
      if ($AddToGroup)
      {
        $aadGroup = Get-AzureADGroup -Filter "DisplayName eq '$AddToGroup'"
        $autopilotDevices | % {
          $aadDevice = Get-AzureADDevice -ObjectId "deviceid_$($_.azureActiveDirectoryDeviceId)"
          Add-AzureADGroupMember -ObjectId $aadGroup.ObjectId -RefObjectId $aadDevice.ObjectId
        }
        Write-Host "Added devices to group '$AddToGroup' ($($aadGroup.ObjectId))"
      }

      # Wait for assignment (if specified)
      if ($Assign)
      {
        $assignStart = Get-Date
        $processingCount = 1
        while ($processingCount -gt 0)
        {
          $processingCount = 0
          $autopilotDevices | % {
            $device = Get-AutopilotDevice -id $_.id -Expand
            if (-not ($device.deploymentProfileAssignmentStatus.StartsWith("assigned"))) {
              $processingCount = $processingCount + 1
            }
          }
          $deviceCount = $autopilotDevices.Length
          Write-Host "Waiting for $processingCount of $deviceCount to be assigned"
          if ($processingCount -gt 0){
            Start-Sleep 30
          }	
        }
        $assignDuration = (Get-Date) - $assignStart
        $assignSeconds = [Math]::Ceiling($assignDuration.TotalSeconds)
        Write-Host "Profiles assigned to all devices.  Elapsed time to complete assignment: $assignSeconds seconds"	
      }
    }
  }

}
#>--------------------------------------------------------------------------------------------------------
$CSVTool = Split-Path $script:MyInvocation.MyCommand.Path
$Path_Tools = -join($CSVTool, "\CSV\")
$path = -join("$Path_Tools", "$env:COMPUTERNAME.csv")
If (!(Test-Path -Path $Path_Tools)) {New-Item -ItemType Directory -Path $Path_Tools | Out-Null} 

cls
Write-Host "CSV-Creator"
Write-Host "------------------------"
Write-Host ""
Write-Host "________________________"
Write-Host "Creation 4kHashfile   = "
Write-Host "Destination Path      = "
Write-Host "Intune AutoJoin       = "

New_Entry 24 4 "<-" Yellow
fu-WindowsAutoPilotInfo -OutputFile $path
New_Entry 24 4 "finished" Green
New_Entry 24 5 $path Green

New_Entry 24 6 "<-" Yellow
fu-WindowsAutoPilotInfo -Online
New_Entry 24 6 "finished" Green
New_Entry 24 7 "" White
