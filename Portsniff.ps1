[int]$ScanPort = 1
[int]$MaxPort = 1024
#>-------------------------------------------------------
$ErrorActionPreference = 'SilentlyContinue'
#>-------------------------------------------------------
function Clean_Status ()
{
  $position=$Host.ui.RawUI.CursorPosition
  $position.x = 28
  $position.y = 6
  $Host.ui.RawUI.CursorPosition=$position
  Write-Host "   " -NoNewline
  $position=$Host.ui.RawUI.CursorPosition
  $position.x = 28
  $position.y = 7
  $Host.ui.RawUI.CursorPosition=$position
  Write-Host "   " -NoNewline
  $position=$Host.ui.RawUI.CursorPosition
  $position.x = 28
  $position.y = 8
  $Host.ui.RawUI.CursorPosition=$position
  Write-Host "   " -NoNewline
  $position=$Host.ui.RawUI.CursorPosition
  $position.x = 28
  $position.y = 9
  $Host.ui.RawUI.CursorPosition=$position
  Write-Host "   " -NoNewline
  $position=$Host.ui.RawUI.CursorPosition
  $position.x = 28
  $position.y = 10
  $Host.ui.RawUI.CursorPosition=$position
  Write-Host "   " -NoNewline
  $position=$Host.ui.RawUI.CursorPosition
  $position.x = 28
  $position.y = 11
  $Host.ui.RawUI.CursorPosition=$position
  Write-Host "   " -NoNewline
  $position=$Host.ui.RawUI.CursorPosition
  $position.x = 28
  $position.y = 12
  $Host.ui.RawUI.CursorPosition=$position
  Write-Host "   " -NoNewline
  $position=$Host.ui.RawUI.CursorPosition
  $position.x = 0
  $position.y = 15
  $Host.ui.RawUI.CursorPosition=$position
}

Function Portping { Param($address, $port, $timeout=50)
  $socket=New-Object System.Net.Sockets.TcpClient
  try {
    $result=$socket.BeginConnect($address, $port, $NULL, $NULL)
    if (!$result.AsyncWaitHandle.WaitOne($timeout, $False)) {
      throw [System.Exception]::new('Connection Timeout')
    }
    $socket.EndConnect($result)
    $socket.Connected
    case
    $socket = $false
  }
  finally
  {

    $socket.Close()
  }
}

function Fix_Ping ([int]$xposi,[int]$yposi,[string]$address,[int]$Port)
{
  Clean_Status
  $position=$Host.ui.RawUI.CursorPosition
  $position.x = 0
  $position.y = $yposi
  $Host.ui.RawUI.CursorPosition=$position
  Write-Host "->" -ForegroundColor Yellow

  $Test = [bool](Portping -address $address -port $Port)

  $position=$Host.ui.RawUI.CursorPosition
  $position.x = 0
  $position.y = $yposi
  $Host.ui.RawUI.CursorPosition=$position
  If ($Test -eq $true) {Write-Host "open" -ForegroundColor Green}
  else {Write-Host "close" -ForegroundColor Red}
}
function Flex_Ping ([int]$xposi, [int]$yposi,[string]$address,[int]$Port)
{
  $position1=$Host.ui.RawUI.CursorPosition
  $position1.x = 0
  $position1.y = 14
  $Host.ui.RawUI.CursorPosition=$position1

  Write-Host "Deepscan: Port $Port     "
  $Test = [bool](Portping -address $address -port $Port)

  If ($Test -eq $true)
  {
    $val = $val + 1
    $position2=$Host.ui.RawUI.CursorPosition
    $position2.x = $xposi
    $position2.y = $yposi + $val
    $Host.ui.RawUI.CursorPosition=$position2
    Write-Host $val
    #Write-Host "open" -NoNewline -ForegroundColor Green
    #Write-Host "     = PORT $Port"
  }
}

Clear-Host
write-Host "Probe - Portcheck Scanner" -ForegroundColor Blue
Write-Host "-------------------------" -ForegroundColor Blue
Write-Host
Write-Host "Please enter Destination-Adresse.."
Write-Host "IP: " -NoNewline
$IP = Read-Host
Clear-Host
Write-Host ""
Write-Host "Probe for " -NoNewline
Write-Host $IP -ForegroundColor Yellow
Write-Host "--------------------------------"
Write-Host
Write-Host "Firewall           Port"
Write-Host "_______________________"
Write-Host "      = HTTP-PORT(80)"
Write-Host "      = HTTPS-PORT(443)"
Write-Host "      = FTP-PORT(20)"
Write-Host "      = FTP-PORT(21)"
Write-Host "      = SSH-PORT(22)"
Write-Host "      = TELNET(23)"
Write-Host "      = SMTP-PORT(25)"
Write-Host "________________________"
Write-Host "Deepscan: "
Write-Host "Firewall           Port"
Write-Host "________________________"
Write-Host ""
Fix_Ping 0 6 $IP 80
Fix_Ping 0 7 $IP 443
Fix_Ping 0 8 $IP 20
Fix_Ping 0 9 $IP 21
Fix_Ping 0 10 $IP 22
Fix_Ping 0 11 $IP 23
Fix_Ping 0 12 $IP 25
    
Write-Host ""
Clean_Status

While (!($ScanPort -eq $MaxPort))
{
    $position1=$Host.ui.RawUI.CursorPosition
    $position1.x = 0
    $position1.y = 14
    $Host.ui.RawUI.CursorPosition=$position1

    Write-Host "Deepscan: Port $ScanPort     "
    $Test = [bool](Portping -address $IP -port $ScanPort)

    If ($Test -eq $true)
    {
      [int]$val += 1
      $position2=$Host.ui.RawUI.CursorPosition
      $position2.x = 0
      $position2.y = 16 + $val
      $Host.ui.RawUI.CursorPosition=$position2
      Write-Host "open" -NoNewline -ForegroundColor Green
      Write-Host "     = PORT $ScanPort"
    }
  $ScanPort += 1

}
Read-Host