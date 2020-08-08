  Do {
  $ErrorActionPreference = 'SilentlyContinue'
  $Host.UI.RawUI.BackgroundColor = ($bckgrnd = 'Black')
  
  $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  $testadmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
  if ($testadmin -eq $false) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    exit $LASTEXITCODE
  }

  [string]$Global:Sequ1 = ""
  [string]$Global:Sequ2 = ""
  [string]$Global:Sequ3 = ""
  [string]$Global:Sequ4 = ""

  #### - CONVERTER - ##################################################################################################################################
  filter ConvertTo-MaskLength {
    [CmdletBinding()]
    [OutputType([Int32])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Alias("Mask")]
        [IPAddress]$SubnetMask
    )
    
    $binaryOctets = $SubnetMask.GetAddressBytes() | ForEach-Object { 
        [Convert]::ToString($_, 2)
    }
    ($binaryOctets -join '').Trim('0').Length
  }

  ######################################################################################################################################################
  function Conv ([int]$Sque_Nr) {
    [string]$Sequence = ""
    Do {
        If (!($Global:Suffix -eq 0))
        {
        $Global:Suffix = $Global:Suffix - 1
        $Sequence = $Sequence + "1"
        }
        else{$Sequence = $Sequence + "0"}
    
    }While (!($Sequence -match ".{8}"))

    if ($Sque_Nr -eq 1)     {$Global:Sequ1 = [convert]::ToInt32($Sequence,2)}
    elseif ($Sque_Nr -eq 2) {$Global:Sequ2 = [convert]::ToInt32($Sequence,2)}
    elseif ($Sque_Nr -eq 3) {$Global:Sequ3 = [convert]::ToInt32($Sequence,2)}
    elseif ($Sque_Nr -eq 4) {$Global:Sequ4 = [convert]::ToInt32($Sequence,2)}
  }
  function Config ()
  {
    $UAdapter = Get-NetAdapter -InterfaceAlias $UString.InterfaceAlias | Select-Object -ExpandProperty InterfaceDescription
    $UIP4vA = Get-NetIPAddress -InterfaceAlias $UString.InterfaceAlias | Select-Object -ExpandProperty IPv4Address
    [string]$DHCP_check = Get-NetIPAddress -InterfaceAlias $UString.InterfaceAlias | Select-Object -ExpandProperty "PrefixOrigin"
    [string]$DHCP_active = $DHCP_check.ToString().ToUpper()
    $UIPdnsA = Get-DnsClientServerAddress -InterfaceAlias $UString.InterfaceAlias | Select-Object -ExpandProperty ServerAddresses
    [int]$Global:Suffix = Get-NetIPAddress -InterfaceAlias $UString.InterfaceAlias | Select-Object -ExpandProperty "PrefixLength"

    Conv 1
    Conv 2
    Conv 3
    Conv 4

    $SUBMASK = -join($Global:Sequ1, ".", $Global:Sequ2, ".", $Global:Sequ3, ".", $Global:Sequ4)
    ###########################################################################
    cls
    Write-Host ""
    Write-Host "IP-Address changer"
    Write-Host "--------------------"
    Write-Host ""
    Write-Host ""
    Write-Host $UAdapter -ForegroundColor yellow
    Write-Host "_______________________________________________________________________________"
    Write-Host ""
    Write-Host "Current configuration:"
    Write-Host "IP-Address:" `t -NoNewline
    Write-Host $UIP4vA  -ForegroundColor Yellow -NoNewline
    Write-Host " (" -NoNewline
    Write-Host $DHCP_active -ForegroundColor Green -NoNewline
    Write-Host ")"
    Write-Host "Subnetmask:" `t -NoNewline
    Write-Host $SUBMASK  -ForegroundColor Yellow
    Write-Host "DNS-Address:" `t -NoNewline
    Write-Host $UIPdnsA  -ForegroundColor Yellow
    Write-Host "_______________________________________________________________________________"

    Read-Host
  }
  #########################################################################################################################################################
  #########################################################################################################################################################
  #########################################################################################################################################################
  
  Do {
  $UString = Get-NetIPInterface | Select-Object InterfaceAlias, AddressFamily, ConnectionState
  $maxLines = $UString | measure
    cls
    Write-Host ""
    Write-Host "IP-Address changer"
    Write-Host "--------------------"
    Write-Host ""
    Write-Host ""
    Write-Host 'Please select affected Network-Adapter'
    Write-Host ""
    Write-Host ""
    Write-Host "  Nr.           Adapter (Connection Status)"
    Write-Host "__________________________________________________________________________"
    [int]$Numb = 1
    foreach ($UString in $UString)
    {
      If ($UString.InterfaceAlias -notmatch "Loopback" -and $UString.AddressFamily -eq "IPv4")
      {$UAdapter = Get-NetAdapter $UString.InterfaceAlias | Select-Object -ExpandProperty InterfaceDescription}
      else {$UAdapter = ""}

      If (!($UAdapter -le ".{1}"))
      {
        Write-Host '[ ' -NoNewline
        Write-Host $Numb -NoNewline -ForegroundColor Yellow
        Write-Host ' ]>------- ' -NoNewline
        Write-Host `t -NoNewline
        Write-Host $UAdapter  -NoNewline
        If ($UString.ConnectionState -eq "Connected")
        {
          Write-Host " (Connected)" -ForegroundColor Green
        }
        else
        {
          Write-Host " (Disconnected)" -ForegroundColor Red
        }

        $Numb =  $Numb + 1
    }}
    $maxLines = $UString | measure
    Write-Host "__________________________________________________________________________"
    [int]$Nr = Read-Host 'Select Nr'
  } While($Nr -lt 1 -or $Nr -gt $maxLines)

  ###########################################################################

  Clear-Host
  $NrSWList = '[ '+ $Nr + ' ]'
  $UString = Get-NetIPInterface | Select-Object InterfaceAlias, AddressFamily, ConnectionState
  [int]$Numb =  1

  $loopbreaker = "false"
  ###########################################################################
  foreach ($UString in $UString) 
  {
    If ($UString.InterfaceAlias -notmatch "Loopback" -and $UString.AddressFamily -eq "IPv4")
    {$UAdapter = Get-NetAdapter $UString.InterfaceAlias | Select-Object -ExpandProperty InterfaceDescription}
    else {$UAdapter = ""}

    If (!($UAdapter -le ".{2}"))
    {
      $checkSW = '[ '+ $Numb +' ]'

      If ($NrSWList -eq $checkSW -and $loopbreaker -eq "false")
      {
        $UAdapter = Get-NetAdapter -InterfaceAlias $UString.InterfaceAlias | Select-Object -ExpandProperty InterfaceDescription
        $UIP4vA = Get-NetIPAddress -InterfaceAlias $UString.InterfaceAlias -AddressFamily "IPv4" | Select-Object -ExpandProperty IPv4Address
    
        [string]$DHCP_check = Get-NetIPAddress -InterfaceAlias $UString.InterfaceAlias -AddressFamily "IPv4" | Select-Object -ExpandProperty "PrefixOrigin"
        [string]$DHCP_active = $DHCP_check.ToString().ToUpper()

        $UIPdnsA = Get-DnsClientServerAddress -InterfaceAlias $UString.InterfaceAlias -AddressFamily "IPv4" | Select-Object -ExpandProperty ServerAddresses
        [int]$Global:Suffix = Get-NetIPAddress -InterfaceAlias $UString.InterfaceAlias -AddressFamily "IPv4" | Select-Object -ExpandProperty "PrefixLength"

        Conv 1
        Conv 2
        Conv 3
        Conv 4

        $SUBMASK = -join($Global:Sequ1, ".", $Global:Sequ2, ".", $Global:Sequ3, ".", $Global:Sequ4) 
        cls
        Write-Host ""
        Write-Host "IP-Address changer"
        Write-Host "--------------------"
        Write-Host ""
        Write-Host ""
        Write-Host "Please select follow Mode for Adapter " -NoNewline
        Write-Host "" -NoNewline
        Write-Host $UAdapter -ForegroundColor yellow
        Write-Host "_______________________________________________________________________________"
        Write-Host ""
        Write-Host "Current configuration:"
        Write-Host "IP-Address:" `t -NoNewline
        Write-Host $UIP4vA  -ForegroundColor Yellow -NoNewline
        Write-Host " (" -NoNewline
        Write-Host $DHCP_active -ForegroundColor Green -NoNewline
        Write-Host ")"
        Write-Host "Subnetmask:" `t -NoNewline
        Write-Host $SUBMASK  -ForegroundColor Yellow
        Write-Host "DNS-Address:" `t -NoNewline
        Write-Host $UIPdnsA  -ForegroundColor Yellow
        Write-Host "_______________________________________________________________________________"
        Do {
          $mode = Read-Host "Select (D)HCP, (S)tatic IP: "
        } While (!($mode -eq "d" -or $mode -eq "s"))
        
        #####################################################################################################################################
        If ($mode -eq "d")
        {     
          $interface = Get-NetIPInterface -InterfaceAlias $UString.InterfaceAlias
          $interface | Remove-NetRoute -AddressFamily IPv4 -Confirm:$false
          $interface | Set-NetIPInterface -Dhcp Enabled
          $interface | Set-DnsClientServerAddress -ResetServerAddresses
          
          $ethernet = Get-WmiObject -Class Win32_NetworkAdapterConfiguration
          foreach ($lan in $ethernet)
          { 
          sleep 2
          $lan.ReleaseDHCPLease() | out-Null
          $lan.RenewDHCPLease() | out-Null 
          }
                    
          config
        }
        #####################################################################################################################################
        elseif ($mode -eq "s")
        {
          Do {$Nipv4 = Read-Host "Enter new IPv4-Address: "} While (($Nipv4 -le ".{6}"))
          Do {$NSNM = Read-Host "Enter new Subnetmask: "} While (($NSNM -le ".{6}"))
          Do {$NSGW = Read-Host "Enter new Standardgateway: "} While (($NSGW -le ".{6}"))
          $NDNS1 = Read-Host "Enter new Primary DNS-Address: "
          $NDNS2 = Read-Host "Enter new Secundary DNS-Address: "

          $NSNM = ConvertTo-MaskLength $NSNM

          Set-NetIPInterface -InterfaceAlias $UString.InterfaceAlias -Dhcp Disabled
          New-NetIPAddress -InterfaceAlias $UString.InterfaceAlias -IPAddress $Nipv4 -PrefixLength $NSNM -DefaultGateway $NSGW
          Set-DnsClientServerAddress -InterfaceAlias $UString.InterfaceAlias -ServerAddresses $NDNS1, $NDNS2

          config
        }

        $loopbreaker = "true"
      }
      $Numb =  $Numb + 1
  }}
} While ($true)