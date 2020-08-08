$ErrorActionPreference = "SilentlyContinue"
$Host.UI.RawUI.BackgroundColor = ($bckgrnd = 'Black')
$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
$testadmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if ($testadmin -eq $false) {
Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
exit $LASTEXITCODE
}

function New_Entry ([int]$xposi,[int]$yposi,[string]$Text,[System.ConsoleColor]$Color) 
{
    $position=$Host.ui.RawUI.CursorPosition
    $position.x = $xposi
    $position.y = $yposi
    $Host.ui.RawUI.CursorPosition=$position
    Write-Host $Text -ForegroundColor $Color
}

function Step1() #Backup Static Network Adapter
{
Foreach($NIC in Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Manual)
{
If (!(Test-Path -Path "C:\tmp\NICs")){New-Item -ItemType Directory -Path "C:\tmp\NICs"}

#InterfaceAlias
$NICAlias = $NIC.InterfaceAlias

#IPv4 Address
$NICIPAddress = Get-NetIPAddress -InterfaceAlias Ethernet0 | Select-Object -ExpandProperty IPAddress
$NICIPAddressConv = -join("IPv4Address : ", $NICIPAddress)
$NICIPAddressConv | Out-File "C:\tmp\NICS\$NICAlias.txt"

#Subnetmask
$PrefixLength = Get-NetIPAddress -InterfaceAlias $NICAlias | Select-Object -ExpandProperty PrefixLength
$PrefixLengtConv = -join("PrefixLength : ",$PrefixLength)
$PrefixLengtConv | Out-File "C:\tmp\NICS\$NICAlias.txt" -Append

#Gateway
$NICGateway = Get-NetIPConfiguration -InterfaceAlias $NICAlias | Select-Object -ExpandProperty IPv4DefaultGateway | Select-Object -ExpandProperty NextHop
$NICGatewayConv = -join("Gateway : " , $NICGateway)
$NICGatewayConv | Out-File "C:\tmp\NICS\$NICAlias.txt" -Append

#DNS
$DNSfound = Get-DnsClientServerAddress -InterfaceAlias $NICAlias -AddressFamily IPv4 | Select-Object ServerAddresses
$DNSAdress1 = $DNSfound.ServerAddresses.Item(0)
$DNSAdress1Conv = -join("PrimaryDNS : ",$DNSAdress1)
$DNSAdress1Conv | Out-File "C:\tmp\NICS\$NICAlias.txt" -Append
$DNSAdress2 = $DNSfound.ServerAddresses.Item(1)
$DNSAdress2Conv = -join("AlternateDNS : ",$DNSAdress2)
$DNSAdress2Conv | Out-File "C:\tmp\NICS\$NICAlias.txt" -Append
}
}

function Step2() #WINSOCK Reset Skript
{
ipconfig /flushdns | Out-Null
netsh int ip reset | Out-Null
netsh winsock reset | Out-Null
netsh interface ip delete arpcache | Out-Null
}

function Step3() #Delete Registry-Keys from Device
{
$Devs = Get-PnpDevice -class Net | Where-Object {$_ -like "*Intel*" -or $_ -like "*Realtek*" -or $_ -like "*vmxnet3*"} | Select FriendlyName,InstanceId 

ForEach ($Dev in $Devs) {
    $RemoveKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($Dev.InstanceId)"
    Get-Item $RemoveKey | Select-Object -ExpandProperty Property | %{ Remove-ItemProperty -Path $RemoveKey -Name $_ } 
}
}

function Step4() #Delete all Unknown Devices from Device-Manager
{
$NarrowByClass = "Net"
$Force = $True

Param(
  [array]$NarrowByClass,
  [switch]$Force
)

$removeDevices = $true

function Filter-Device {
    Param (
        [System.Object]$dev
    )
    $Class = $dev.Class
    $FriendlyName = $dev.FriendlyName
    $matchFilter = $false


    if (($matchFilter -eq $false) -and ($NarrowByClass -ne $null)) {
        $shouldInclude = $false
        foreach ($ClassFilter in $NarrowByClass) {
            if ($ClassFilter -eq $Class) {
                $shouldInclude = $true
                break
            }
        }
        $matchFilter = !$shouldInclude
    }

    return $matchFilter
}

function Filter-Devices {
    Param (
        [array]$devices
    )
    $filteredDevices = @()
    foreach ($dev in $devices) {
        $matchFilter = Filter-Device -Dev $dev
        if ($matchFilter -eq $false) {
            $filteredDevices += @($dev)
        }
    }
    return $filteredDevices
}

$setupapi = @"
using System;
using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;
namespace Win32
{
    public static class SetupApi
    {
         // 1st form using a ClassGUID only, with Enumerator = IntPtr.Zero
        [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SetupDiGetClassDevs(
           ref Guid ClassGuid,
           IntPtr Enumerator,
           IntPtr hwndParent,
           int Flags
        );
    
        // 2nd form uses an Enumerator only, with ClassGUID = IntPtr.Zero
        [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SetupDiGetClassDevs(
           IntPtr ClassGuid,
           string Enumerator,
           IntPtr hwndParent,
           int Flags
        );
        
        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetupDiEnumDeviceInfo(
            IntPtr DeviceInfoSet,
            uint MemberIndex,
            ref SP_DEVINFO_DATA DeviceInfoData
        );
    
        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiDestroyDeviceInfoList(
            IntPtr DeviceInfoSet
        );
        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetupDiGetDeviceRegistryProperty(
            IntPtr deviceInfoSet,
            ref SP_DEVINFO_DATA deviceInfoData,
            uint property,
            out UInt32 propertyRegDataType,
            byte[] propertyBuffer,
            uint propertyBufferSize,
            out UInt32 requiredSize
        );
        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool SetupDiGetDeviceInstanceId(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            StringBuilder DeviceInstanceId,
            int DeviceInstanceIdSize,
            out int RequiredSize
        );

    
        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetupDiRemoveDevice(IntPtr DeviceInfoSet,ref SP_DEVINFO_DATA DeviceInfoData);
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA
    {
       public uint cbSize;
       public Guid classGuid;
       public uint devInst;
       public IntPtr reserved;
    }
    [Flags]
    public enum DiGetClassFlags : uint
    {
        DIGCF_DEFAULT       = 0x00000001,  // only valid with DIGCF_DEVICEINTERFACE
        DIGCF_PRESENT       = 0x00000002,
        DIGCF_ALLCLASSES    = 0x00000004,
        DIGCF_PROFILE       = 0x00000008,
        DIGCF_DEVICEINTERFACE   = 0x00000010,
    }
    public enum SetupDiGetDeviceRegistryPropertyEnum : uint
    {
         SPDRP_DEVICEDESC          = 0x00000000, // DeviceDesc (R/W)
         SPDRP_HARDWAREID          = 0x00000001, // HardwareID (R/W)
         SPDRP_COMPATIBLEIDS           = 0x00000002, // CompatibleIDs (R/W)
         SPDRP_UNUSED0             = 0x00000003, // unused
         SPDRP_SERVICE             = 0x00000004, // Service (R/W)
         SPDRP_UNUSED1             = 0x00000005, // unused
         SPDRP_UNUSED2             = 0x00000006, // unused
         SPDRP_CLASS               = 0x00000007, // Class (R--tied to ClassGUID)
         SPDRP_CLASSGUID           = 0x00000008, // ClassGUID (R/W)
         SPDRP_DRIVER              = 0x00000009, // Driver (R/W)
         SPDRP_CONFIGFLAGS         = 0x0000000A, // ConfigFlags (R/W)
         SPDRP_MFG             = 0x0000000B, // Mfg (R/W)
         SPDRP_FRIENDLYNAME        = 0x0000000C, // FriendlyName (R/W)
         SPDRP_LOCATION_INFORMATION    = 0x0000000D, // LocationInformation (R/W)
         SPDRP_PHYSICAL_DEVICE_OBJECT_NAME = 0x0000000E, // PhysicalDeviceObjectName (R)
         SPDRP_CAPABILITIES        = 0x0000000F, // Capabilities (R)
         SPDRP_UI_NUMBER           = 0x00000010, // UiNumber (R)
         SPDRP_UPPERFILTERS        = 0x00000011, // UpperFilters (R/W)
         SPDRP_LOWERFILTERS        = 0x00000012, // LowerFilters (R/W)
         SPDRP_BUSTYPEGUID         = 0x00000013, // BusTypeGUID (R)
         SPDRP_LEGACYBUSTYPE           = 0x00000014, // LegacyBusType (R)
         SPDRP_BUSNUMBER           = 0x00000015, // BusNumber (R)
         SPDRP_ENUMERATOR_NAME         = 0x00000016, // Enumerator Name (R)
         SPDRP_SECURITY            = 0x00000017, // Security (R/W, binary form)
         SPDRP_SECURITY_SDS        = 0x00000018, // Security (W, SDS form)
         SPDRP_DEVTYPE             = 0x00000019, // Device Type (R/W)
         SPDRP_EXCLUSIVE           = 0x0000001A, // Device is exclusive-access (R/W)
         SPDRP_CHARACTERISTICS         = 0x0000001B, // Device Characteristics (R/W)
         SPDRP_ADDRESS             = 0x0000001C, // Device Address (R)
         SPDRP_UI_NUMBER_DESC_FORMAT       = 0X0000001D, // UiNumberDescFormat (R/W)
         SPDRP_DEVICE_POWER_DATA       = 0x0000001E, // Device Power Data (R)
         SPDRP_REMOVAL_POLICY          = 0x0000001F, // Removal Policy (R)
         SPDRP_REMOVAL_POLICY_HW_DEFAULT   = 0x00000020, // Hardware Removal Policy (R)
         SPDRP_REMOVAL_POLICY_OVERRIDE     = 0x00000021, // Removal Policy Override (RW)
         SPDRP_INSTALL_STATE           = 0x00000022, // Device Install State (R)
         SPDRP_LOCATION_PATHS          = 0x00000023, // Device Location Paths (R)
         SPDRP_BASE_CONTAINERID        = 0x00000024  // Base ContainerID (R)
    }
}
"@

Add-Type -TypeDefinition $setupapi

    #Array for all removed devices report
    $removeArray = @()
    #Array for all devices report
    $array = @()

    $setupClass = [Guid]::Empty
    #Get all devices
    $devs = [Win32.SetupApi]::SetupDiGetClassDevs([ref]$setupClass, [IntPtr]::Zero, [IntPtr]::Zero, [Win32.DiGetClassFlags]::DIGCF_ALLCLASSES)

    #Initialise Struct to hold device info Data
    $devInfo = new-object Win32.SP_DEVINFO_DATA
    $devInfo.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($devInfo)

    #Device Counter
    $devCount = 0
    #Enumerate Devices
    while([Win32.SetupApi]::SetupDiEnumDeviceInfo($devs, $devCount, [ref]$devInfo)) {

        #Will contain an enum depending on the type of the registry Property, not used but required for call
        $propType = 0
        #Buffer is initially null and buffer size 0 so that we can get the required Buffer size first
        [byte[]]$propBuffer = $null
        $propBufferSize = 0
        #Get Buffer size
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_FRIENDLYNAME, [ref]$propType, $propBuffer, 0, [ref]$propBufferSize) | Out-null
        #Initialize Buffer with right size
        [byte[]]$propBuffer = New-Object byte[] $propBufferSize

        #Get HardwareID
        $propTypeHWID = 0
        [byte[]]$propBufferHWID = $null
        $propBufferSizeHWID = 0
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_HARDWAREID, [ref]$propTypeHWID, $propBufferHWID, 0, [ref]$propBufferSizeHWID) | Out-null
        [byte[]]$propBufferHWID = New-Object byte[] $propBufferSizeHWID

        #Get DeviceDesc (this name will be used if no friendly name is found)
        $propTypeDD = 0
        [byte[]]$propBufferDD = $null
        $propBufferSizeDD = 0
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_DEVICEDESC, [ref]$propTypeDD, $propBufferDD, 0, [ref]$propBufferSizeDD) | Out-null
        [byte[]]$propBufferDD = New-Object byte[] $propBufferSizeDD

        #Get Install State
        $propTypeIS = 0
        [byte[]]$propBufferIS = $null
        $propBufferSizeIS = 0
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_INSTALL_STATE, [ref]$propTypeIS, $propBufferIS, 0, [ref]$propBufferSizeIS) | Out-null
        [byte[]]$propBufferIS = New-Object byte[] $propBufferSizeIS

        #Get Class
        $propTypeCLSS = 0
        [byte[]]$propBufferCLSS = $null
        $propBufferSizeCLSS = 0
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_CLASS, [ref]$propTypeCLSS, $propBufferCLSS, 0, [ref]$propBufferSizeCLSS) | Out-null
        [byte[]]$propBufferCLSS = New-Object byte[] $propBufferSizeCLSS
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_CLASS, [ref]$propTypeCLSS, $propBufferCLSS, $propBufferSizeCLSS, [ref]$propBufferSizeCLSS)  | out-null
        $Class = [System.Text.Encoding]::Unicode.GetString($propBufferCLSS)

        #Read FriendlyName property into Buffer
        if(![Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_FRIENDLYNAME, [ref]$propType, $propBuffer, $propBufferSize, [ref]$propBufferSize)){
            [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_DEVICEDESC, [ref]$propTypeDD, $propBufferDD, $propBufferSizeDD, [ref]$propBufferSizeDD)  | out-null
            $FriendlyName = [System.Text.Encoding]::Unicode.GetString($propBufferDD)
            #The friendly Name ends with a weird character
            if ($FriendlyName.Length -ge 1) {
                $FriendlyName = $FriendlyName.Substring(0,$FriendlyName.Length-1)
            }
        } else {
            #Get Unicode String from Buffer
            $FriendlyName = [System.Text.Encoding]::Unicode.GetString($propBuffer)
            #The friendly Name ends with a weird character
            if ($FriendlyName.Length -ge 1) {
                $FriendlyName = $FriendlyName.Substring(0,$FriendlyName.Length-1)
            }
        }

        #InstallState returns true or false as an output, not text
        $InstallState = [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_INSTALL_STATE, [ref]$propTypeIS, $propBufferIS, $propBufferSizeIS, [ref]$propBufferSizeIS)

        # Read HWID property into Buffer
        if(![Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_HARDWAREID, [ref]$propTypeHWID, $propBufferHWID, $propBufferSizeHWID, [ref]$propBufferSizeHWID)){
            #Ignore if Error
            $HWID = ""
        } else {
            #Get Unicode String from Buffer
            $HWID = [System.Text.Encoding]::Unicode.GetString($propBufferHWID)
            #trim out excess names and take first object
            $HWID = $HWID.split([char]0x0000)[0].ToUpper()
        }

        #all detected devices list
        $device = New-Object System.Object
        $device | Add-Member -type NoteProperty -name FriendlyName -value $FriendlyName
        $device | Add-Member -type NoteProperty -name HWID -value $HWID
        $device | Add-Member -type NoteProperty -name InstallState -value $InstallState
        $device | Add-Member -type NoteProperty -name Class -value $Class
        if ($array.count -le 0) {
            sleep 1
        }
        $array += @($device)

        if ($removeDevices -eq $true) {
            #we want to remove devices so let's check the filters...
            $matchFilter = Filter-Device -Dev $device

            if ($InstallState -eq $False) {
                if ($matchFilter -eq $false) {
                    $message  = "Attempting to remove device $FriendlyName"
                    $confirmed = $false
                    if (!$Force -eq $true) {
                        $question = 'Are you sure you want to proceed?'
                        $choices  = '&Yes', '&No'
                        $decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
                        if ($decision -eq 0) {
                            $confirmed = $true
                        }
                    } else {
                        $confirmed = $true
                    }
                    if ($confirmed -eq $true) {
                                             $removeObj = New-Object System.Object
                        $removeObj | Add-Member -type NoteProperty -name FriendlyName -value $FriendlyName
                        $removeObj | Add-Member -type NoteProperty -name HWID -value $HWID
                        $removeObj | Add-Member -type NoteProperty -name InstallState -value $InstallState
                        $removeObj | Add-Member -type NoteProperty -name Class -value $Class
                        $removeArray += @($removeObj)
                        if([Win32.SetupApi]::SetupDiRemoveDevice($devs, [ref]$devInfo)){
              
                        } else {
               
                        }
                    } else {
               
                    }
                } else {
          
                }
            }
        }
        $devcount++
    }
}

function Step5() #Search of lost Devices
{
 
    [string]$SourceCode =  @"
 
    using System.Runtime.InteropServices;
 
    using System;
 
   
 
    namespace check.devices
 
    {
 
        // These are the native win32 methods that we require
 
        internal static class NativeMethods
 
        {
 
            [DllImport("cfgmgr32.dll", SetLastError = true, EntryPoint = "CM_Locate_DevNode_Ex", CharSet = CharSet.Auto)]
 
            public static extern UInt32 CM_Locate_DevNode_Ex(ref UInt32 DevInst, IntPtr DeviceID, UInt64 Flags, IntPtr Machine);
 
 
 
            [DllImport("cfgmgr32.dll", SetLastError = true, EntryPoint = "CM_Reenumerate_DevNode_Ex", CharSet = CharSet.Auto)]
 
            public static extern UInt32 CM_Reenumerate_DevNode_Ex(UInt32 DevInst, UInt64 Flags, IntPtr Machine);
 
 
 
            [DllImport("cfgmgr32.dll", SetLastError = true, EntryPoint = "CMP_WaitNoPendingInstallEvents", CharSet = CharSet.Auto)]
 
            public static extern UInt32 CMP_WaitNoPendingInstallEvents(UInt32 TimeOut);
 
        }
 
       
 
        // This class houses the public methods that we'll use from powershell
 
        public static class StaticMethods
 
        {
 
       
 
            public const UInt32 CR_SUCCESS = 0;
 
            public const UInt64 CM_REENUMERATE_SYNCHRONOUS = 1;
 
            public const UInt64 CM_LOCATE_DEVNODE_NORMAL = 0;
 
           
 
            public static UInt32 RescanAllDevices()
 
            {
 
                //only connect to local device nodes
 
                UInt32 ResultCode = 0;
 
                IntPtr LocalMachineInstance = IntPtr.Zero;
 
                UInt32 DeviceInstance = 0;
 
                UInt32 PendingTime = 30000;
 
 
 
                ResultCode = NativeMethods.CM_Locate_DevNode_Ex(ref DeviceInstance, IntPtr.Zero, CM_LOCATE_DEVNODE_NORMAL, LocalMachineInstance);
 
                if (CR_SUCCESS == ResultCode)
 
                {
 
                    ResultCode = NativeMethods.CM_Reenumerate_DevNode_Ex(DeviceInstance, CM_REENUMERATE_SYNCHRONOUS, LocalMachineInstance);
 
                    ResultCode = NativeMethods.CMP_WaitNoPendingInstallEvents(PendingTime);
 
                }
 
                return ResultCode;
 
            }
 
        }
 
    }
 
"@

    add-type -TypeDefinition $SourceCode

[check.devices.staticmethods]::RescanAllDevices() | Out-Null
[check.devices.staticmethods]::RescanAllDevices() | Out-Null
}

function Step6() #Restore Static Network Adapter
{
ForEach ($File in Get-ChildItem -Path "C:\tmp\NICs")
{
ForEach ($Entry in Get-Content -Path "C:\tmp\NICs\$File")
{
$NICAlias = $Entry.PSChildName.Replace(".txt", "")

If ($Entry -match "IPv4Address"){$NICIPAddress = $Entry.Replace("IPv4Address : ","")}
elseIf ($Entry -match "PrefixLength"){$NICSubNet = $Entry.Replace("PrefixLength : ","")}
elseIf ($Entry -match "Gateway"){$NICIPGateway = $Entry.Replace("Gateway : ","")}
elseIf ($Entry -match "PrimaryDNS"){$NICDNS1 = $Entry.Replace("PrimaryDNS : ","")}
elseIf ($Entry -match "AlternateDNS"){$NICDNS2 = $Entry.Replace("AlternateDNS : ","")}
}}
Set-NetIPInterface -InterfaceAlias $NICAlias -Dhcp Disabled | Out-Null
New-NetIPAddress -InterfaceAlias $NICAlias -IPAddress $NICIPAddress -PrefixLength $NICSubNet -DefaultGateway $NICIPGateway | Out-Null
$NICDNS = -join($NICDNS1, ",", $NICDNS2)
Set-DnsClientServerAddress -InterfaceAlias $NICAlias -ServerAddresses $NICDNS | Out-Null
}

#########################################################################################################################
# - Menu - ##############################################################################################################
cls
Write-Host "Vergil - Fix Network Winsock Issue"
Write-Host "----------------------------------"
Write-Host ""
Write-Host "Please close all applications!   " -ForegroundColor Yellow
Write-Host "Your network cards will be completely reset." -ForegroundColor Yellow
Write-Host "_________________________________"
Write-Host ""
Write-Host "Press enter, to start this fix..."
Read-Host
cls
Write-Host "Vergil - Fix Network Winsock Issue"
Write-Host "----------------------------------"
Write-Host
Write-Host "Please wait, processing..." -ForegroundColor Red
Write-Host ""
Write-Host "_________________________________"
Write-Host "Backup Static Network Adapter  = "
Write-Host "Reset Winsock Configuration    = "
Write-Host "Clear Registry Entry           = "
Write-Host "Remove all Network Adapter     = "
Write-Host "Reinitialize Network Adapter   = "
Write-Host "Restore Static Network Adapter = "
Write-Host "_________________________________"
Write-Host
#########################################################################################################################
$Job = Start-Job -Name "work" -ScriptBlock ${Function:Step1}
 Do {
      New_Entry 33 6 "<-" Yellow 
      Start-Sleep -Milliseconds 500
      New_Entry 33 6 "  " Yellow
      Start-Sleep -Milliseconds 500                
    } While ($Job.State -eq 'Running')
     Remove-Job * -Force
New_Entry 33 6 "ok" green 
#########################################################################################################################
$Job = Start-Job -Name "work" -ScriptBlock ${Function:Step2}
 Do {
      New_Entry 33 7 "<-" Yellow 
      Start-Sleep -Milliseconds 500
      New_Entry 33 7 "  " Yellow
      Start-Sleep -Milliseconds 500                
    } While ($Job.State -eq 'Running')
     Remove-Job * -Force
New_Entry 33 7 "ok" green 
#########################################################################################################################
$Job = Start-Job -Name "work" -ScriptBlock ${Function:Step3}
 Do {
      New_Entry 33 8 "<-" Yellow 
      Start-Sleep -Milliseconds 500
      New_Entry 33 8 "  " Yellow
      Start-Sleep -Milliseconds 500                
    } While ($Job.State -eq 'Running')
     Remove-Job * -Force
New_Entry 33 8 "ok" green 
#########################################################################################################################
$Job = Start-Job -Name "work" -ScriptBlock ${Function:Step4}
 Do {
      New_Entry 33 9 "<-" Yellow 
      Start-Sleep -Milliseconds 500
      New_Entry 33 9 "  " Yellow
      Start-Sleep -Milliseconds 500                
    } While ($Job.State -eq 'Running')
     Remove-Job * -Force
New_Entry 33 9 "ok" green 
#########################################################################################################################
$Job = Start-Job -Name "work" -ScriptBlock ${Function:Step5}
 Do {
      New_Entry 33 10 "<-" Yellow 
      Start-Sleep -Milliseconds 500
      New_Entry 33 10 "  " Yellow
      Start-Sleep -Milliseconds 500                
    } While ($Job.State -eq 'Running')
     Remove-Job * -Force

New_Entry 33 10 "ok" green 
#########################################################################################################################
$Job = Start-Job -Name "work" -ScriptBlock ${Function:Step6}
 Do {
      New_Entry 33 11 "<-" Yellow 
      Start-Sleep -Milliseconds 500
      New_Entry 33 11 "  " Yellow
      Start-Sleep -Milliseconds 500                
    } While ($Job.State -eq 'Running')
Remove-Job * -Force
New_Entry 33 11 "ok" green 
#########################################################################################################################
New_Entry 0 3 "Please restart now this Client!" green
New_Entry 0 12 "" White

$HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
$HOST.UI.RawUI.Flushinputbuffer()