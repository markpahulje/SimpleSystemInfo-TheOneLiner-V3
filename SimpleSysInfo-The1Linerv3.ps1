#============================================================================================================================================================
# AUTHOR:         metadataconsult@gmail.com
# WEBSITE:        http://metadataconsulting.blogspot.com
#
# SCRIPT NAME:    SimpleSysInfo-The1Linerv2.ps1  
# DATE:           11/02/2018 
# VERSION:        1.1.2.18275
#
# SYNPOSIS:       The 1 liner for essential PC/Sys info, using non-identifying specs for a post, quote or tweet 
# COMMENT:        No more cobling this together, universal standard. Detects SSD vs HD with rotary speed
#
# V2 IMPROVEMENTS:Gets hard drive rotations speed (RPMs) from kernel32.dll P/Invoke method, and better error transparency.
#                 Add GPUs, report max GPU RAM size and description found for brevity
#                 
# EXECUTE:        .\SimpleSysInfo-The1Linerv2.ps1 (WITH ADMINISTRATOR PRIVLEDGES)
#
# RUN AS ADMIN :  Start-Process powershell -Verb runAs
#
# OUTPUT:         Microsoft Windows 10 Pro 1803 (10.0.17134.81), Intel Core i7-2760QM CPU @ 2.40GHz * 4, 32GB RAM, 1TB HD @ 7,200 RPM
# OR              THINKPADW530 [42763JZ], Microsoft Windows 10 Pro 1803 (10.0.17134.81), Intel Core i7-2760QM CPU @ 2.40GHz * 4, 32GB RAM, 1TB HD @ 7,200 RPM
# SSD SAMPLE:     Microsoft Windows 10 Pro 1803 (10.0.17134.191), Intel Core i7-4600U CPU @ 2.10GHz * 2, 8GB RAM, 128GB SSD
#
# LICENSE SUMMARY In a nutshell, you are not allowed to copyright, or take a patent on this code, or profit from it, those are or will be under perview of author. Otherwise, you are free to distribute and use.
# LICENSE URL:    http://metadataconsulting.blogspot.com/p/non-profit-open-software-license-3.html
#============================================================================================================================================================

#Requires -Version 3.0
$versionMinimum = [Version]'3.0'
if ($versionMinimum -gt $PSVersionTable.PSVersion)
{ 
    Write-Host "Requires PowerShell version 3.0"
    Write-Host "Running PowerShell $($PSVersionTable.PSVersion)"
    Break 
}


# The problem with forcing a double into an integer in modulo operations is that Powershell uses banker's rounding algorithm. Hence make our own fn
function Get-FriendlyByteSize {
    param($Bytes)
    $sizes='Bytes,KB,MB,GB,TB,PB,EB,ZB' -split ','
    for($i=0; ($Bytes -ge 1kb) -and 
        ($i -lt $sizes.Count); $i++) {$Bytes/=1kb}
    $N=2; if($i -eq 0) {$N=0}
    "{0:N$($N)} {1}" -f $Bytes, $sizes[$i]
}

function Get-FriendlyRAMSize {
    param($Bytes)
    $sizes='Bytes,KB,MB,GB,TB,PB,EB,ZB' -split ','
    for($i=0; ($Bytes -ge 1kb) -and 
        ($i -lt $sizes.Count); $i++) {$Bytes/=1kb}
    $N=0; if($i -eq 0) {$N=0}
    "{0:N$($N)}{1}" -f $Bytes, $sizes[$i]
}

function Get-FriendlySize {
    param($Number)
    $sizes='Bytes,KB,MB,GB,TB,PB,EB,ZB' -split ','
    for($i=0; ($Number -ge 1000) -and ($i -lt $sizes.Count); $i++)
    {$Number/=1000}
    $N=0; if($i -eq 0) {$N=0}
    "{0:N$($N)}{1}" -f $Number, $sizes[$i]
}

<#
.SYNOPSIS
   Detects if the passed drive letter is a Solid State Disk (SSD) or a
   spindle disk. Returns integer for RPM speed or 1 for SSD.

.DESCRIPTION
   
   The methods used for detecting are by reading the Nominal Media Rotation
   Rate. These values are measured through method calls
   into the Kernel32.dll. If either of the Win32 DLL calls return true then
   the script will return false. If an exception occurs in either of the
   Win32 DLL calls, the return value will be dependant on the remaining call.

.PARAMETER BootDiskLetter
#>

function GetHDRPMSSD {
[CmdletBinding(SupportsShouldProcess=$true,
               ConfirmImpact="Low")]
[OutputType([UInt32])]
Param
(
    [Parameter(Mandatory=$true,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=0)]
    [String]
    $BootDriveLetterwithcolon
)

Begin {
    $code = @"
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Text;
 
namespace Util
{
    public class GetHDRPMSSD
    {
        // For CreateFile to get handle to drive
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
 
        // CreateFile to get handle to drive
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);
 
        // For control codes
        private const uint FILE_DEVICE_MASS_STORAGE = 0x0000002d;
        private const uint IOCTL_STORAGE_BASE = FILE_DEVICE_MASS_STORAGE;
        private const uint FILE_DEVICE_CONTROLLER = 0x00000004;
        private const uint IOCTL_SCSI_BASE = FILE_DEVICE_CONTROLLER;
        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_ANY_ACCESS = 0;
        private const uint FILE_READ_ACCESS = 0x00000001;
        private const uint FILE_WRITE_ACCESS = 0x00000002;
 
        private static uint CTL_CODE(uint DeviceType, uint Function,
                                     uint Method, uint Access)
        {
            return ((DeviceType << 16) | (Access << 14) |
                    (Function << 2) | Method);
        }
 
        // For DeviceIoControl to check no seek penalty
        private const uint StorageDeviceSeekPenaltyProperty = 7;
        private const uint PropertyStandardQuery = 0;
 
        [StructLayout(LayoutKind.Sequential)]
        private struct STORAGE_PROPERTY_QUERY
        {
            public uint PropertyId;
            public uint QueryType;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public byte[] AdditionalParameters;
        }
 
        [StructLayout(LayoutKind.Sequential)]
        private struct DEVICE_SEEK_PENALTY_DESCRIPTOR
        {
            public uint Version;
            public uint Size;
            [MarshalAs(UnmanagedType.U1)]
            public bool IncursSeekPenalty;
        }
 
        // DeviceIoControl to check no seek penalty
        [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl",
                   SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            ref STORAGE_PROPERTY_QUERY lpInBuffer,
            uint nInBufferSize,
            ref DEVICE_SEEK_PENALTY_DESCRIPTOR lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);
 
        // For DeviceIoControl to check nominal media rotation rate
        private const uint ATA_FLAGS_DATA_IN = 0x02;
 
        [StructLayout(LayoutKind.Sequential)]
        private struct ATA_PASS_THROUGH_EX
        {
            public ushort Length;
            public ushort AtaFlags;
            public byte PathId;
            public byte TargetId;
            public byte Lun;
            public byte ReservedAsUchar;
            public uint DataTransferLength;
            public uint TimeOutValue;
            public uint ReservedAsUlong;
            public IntPtr DataBufferOffset;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] PreviousTaskFile;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] CurrentTaskFile;
        }
 
        [StructLayout(LayoutKind.Sequential)]
        private struct ATAIdentifyDeviceQuery
        {
            public ATA_PASS_THROUGH_EX header;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public ushort[] data;
        }
 
        // DeviceIoControl to check nominal media rotation rate
        [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl",
                   SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            ref ATAIdentifyDeviceQuery lpInBuffer,
            uint nInBufferSize,
            ref ATAIdentifyDeviceQuery lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);
 
        // For error message
        private const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
 
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint FormatMessage(
            uint dwFlags,
            IntPtr lpSource,
            uint dwMessageId,
            uint dwLanguageId,
            StringBuilder lpBuffer,
            uint nSize,
            IntPtr Arguments);
 

        // Method for no seek penalty, alternate to determine if this spindle disk aka hard drive
        // Method for no seek penalty
        public static bool HasSeekPenalty(string sDrive)
        {
            SafeFileHandle hDrive = CreateFileW(
                sDrive,
                0, // No access to drive
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);

            if (hDrive == null || hDrive.IsInvalid)
            {
                string message = GetErrorMessage(Marshal.GetLastWin32Error());
                throw new System.Exception(message);
            }

            uint IOCTL_STORAGE_QUERY_PROPERTY = CTL_CODE(
                IOCTL_STORAGE_BASE, 0x500,
                METHOD_BUFFERED, FILE_ANY_ACCESS); // From winioctl.h
 
            STORAGE_PROPERTY_QUERY query_seek_penalty =
                new STORAGE_PROPERTY_QUERY();
            query_seek_penalty.PropertyId = StorageDeviceSeekPenaltyProperty;
            query_seek_penalty.QueryType = PropertyStandardQuery;
 
            DEVICE_SEEK_PENALTY_DESCRIPTOR query_seek_penalty_desc =
                new DEVICE_SEEK_PENALTY_DESCRIPTOR();
 
            uint returned_query_seek_penalty_size;
 
            bool query_seek_penalty_result = DeviceIoControl(
                hDrive,
                IOCTL_STORAGE_QUERY_PROPERTY,
                ref query_seek_penalty,
                (uint)Marshal.SizeOf(query_seek_penalty),
                ref query_seek_penalty_desc,
                (uint)Marshal.SizeOf(query_seek_penalty_desc),
                out returned_query_seek_penalty_size,
                IntPtr.Zero);
 
            hDrive.Close();
 
            if (query_seek_penalty_result == false)
            {
                string message = GetErrorMessage(Marshal.GetLastWin32Error());
                throw new System.Exception(message);
            }
            else
            {
                return query_seek_penalty_desc.IncursSeekPenalty;
            }
        }

        // Method for nominal media rotation rate
        // (Administrative privilege is required)
        public static UInt32 HasNominalMediaRotationRate(string sDrive)
        {
            SafeFileHandle hDrive = CreateFileW(
                sDrive,
                GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);
 
            if (hDrive == null || hDrive.IsInvalid)
            {
                string message = GetErrorMessage(Marshal.GetLastWin32Error());
                throw new System.Exception(message); //embedded in powershell this does nothing
            }
 
            uint IOCTL_ATA_PASS_THROUGH = CTL_CODE(
                IOCTL_SCSI_BASE, 0x040b, METHOD_BUFFERED,
                FILE_READ_ACCESS | FILE_WRITE_ACCESS); // From ntddscsi.h
 
            ATAIdentifyDeviceQuery id_query = new ATAIdentifyDeviceQuery();
            id_query.data = new ushort[256];
 
            id_query.header.Length = (ushort)Marshal.SizeOf(id_query.header);
            id_query.header.AtaFlags = (ushort)ATA_FLAGS_DATA_IN;
            id_query.header.DataTransferLength =
                (uint)(id_query.data.Length * 2); // Size of "data" in bytes
            id_query.header.TimeOutValue = 3; // Sec
            id_query.header.DataBufferOffset = (IntPtr)Marshal.OffsetOf(
                typeof(ATAIdentifyDeviceQuery), "data");
            id_query.header.PreviousTaskFile = new byte[8];
            id_query.header.CurrentTaskFile = new byte[8];
            id_query.header.CurrentTaskFile[6] = 0xec; // ATA IDENTIFY DEVICE
 
            uint retval_size;
 
            bool result = DeviceIoControl(
                hDrive,
                IOCTL_ATA_PASS_THROUGH,
                ref id_query,
                (uint)Marshal.SizeOf(id_query),
                ref id_query,
                (uint)Marshal.SizeOf(id_query),
                out retval_size,
                IntPtr.Zero);
 
            hDrive.Close();
 
            if (result == false)
            {
                string message = GetErrorMessage(Marshal.GetLastWin32Error());
                throw new System.Exception(message);
            }
            else
            {
                // Word index of nominal media rotation rate
                const int kNominalMediaRotRateWordIndex = 217;
 
                //Tue 02-Oct-18 2:33pm v2 - updated 
                //Index of nominal media rotation rate
                //SOURCE: http://www.t13.org/documents/UploadedDocuments/docs2009/d2015r1a-ATAATAPI_Command_Set_-_2_ACS-2.pdf
                //          7.18.7.81 Word 217
                //QUOTE: Word 217 indicates the nominal media rotation rate of the device and is defined in table:
                //          Value           Description
                //          --------------------------------
                //          0000h           Rate not reported
                //          0001h           Non-rotating media (e.g., solid state device)
                //          0002h-0400h     Reserved
                //          0401h-FFFEh     Nominal media rotation rate in rotations per minute (rpm)
                //                          (e.g., 7200 rpm = 1C20h)
                //          FFFFh           Reserved
                
                //http://qaru.site/questions/493997/detecting-ssd-in-windows
                //#define kNominalMediaRotRateWordIndex 217
                //_tprintf(L"%d", (UINT)id_query.data[kNominalMediaRotRateWordIndex]);

                return id_query.data[kNominalMediaRotRateWordIndex];//no hex translation needed

            }
        }
 
        // Method for error message
        private static string GetErrorMessage(int code)
        {
            StringBuilder message = new StringBuilder(255);
 
            FormatMessage(
              FORMAT_MESSAGE_FROM_SYSTEM,
              IntPtr.Zero,
              (uint)code,
              0,
              message,
              (uint)message.Capacity,
              IntPtr.Zero);
 
            return message.ToString();
        }
    }
}
"@
    Add-Type -TypeDefinition $code -PassThru | Out-Null

    $hasRotationRate = 0
    $hasSeekPenalty = $false
}

Process {
    
    [UInt32]$hasRotationRate = 0
    
    #v2 https://msdn.microsoft.com/en-us/1d35c087-6672-4fc6-baa1-a886dd9d3878?f=255&MSPPError=-2147217396
    $driveString = "\\.\"+$BootDriveLetterwithcolon; 
    
    #v1 $driveString = "\\.\PhysicalDrive" + $PhysicalDiskId  #Wed 03-Oct-18 9:03am MDC, alternate but too complicated
    #v1 Write-Verbose -Message "Current disk item id is: $PhysicalDiskId"
 
    Write-Verbose -Message "Current disk string is: $driveString"
    Write-Verbose -Message "Calling Win32 DLL Method 'DeviceIoControl' in 'HasNominalMediaRotationRate'."
    if ($PSCmdlet.ShouldProcess("Physical Disk $PhysicalDiskId","Read Nominal Media Rotation Rate Property")) {
        try {
            $hasRotationRate = [Util.GetHDRPMSSD]::HasNominalMediaRotationRate([string]$driveString)
        } catch {
            
            Write-Verbose -Message "HasNominalMediaRotationRate detection failed with the following error;"
            Write-Verbose -Message $Error[0].Exception.Message
            
            if ($Error[0].Exception.Message -match 'Access is denied') 
            {
                $hasRotationRate = 007 #throw our own error spy message, meaning this is not being run in elevated Admin privledges
            }
            elseif ($Error[0].Exception.Message -match 'The system cannot find the file specified') 
            {
                $hasRotationRate = 11 #Wrong drive letter 
            }           
            else { 
                $hasRotationRate = 3 #Unknown error
                Write-Warning "HasNominalMediaRotationRate detection failed with the following error;"
                Write-Warning $Error[0].Exception.Message
            }
        }
    }
   
    Write-Verbose -Message "Calling Win32 DLL Method 'DeviceIoControl' in 'HasSeekPenalty'."
    if ($PSCmdlet.ShouldProcess("Physical Disk $PhysicalDiskId","Read Seek Penalty Property")) {
        try {
            $hasSeekPenalty = [Util.DetectSSD]::HasSeekPenalty([string]$driveString)
        } catch {
            Write-Verbose -Message "HasSeekPenalty detection failed with the following error;"
            Write-Verbose -Message $Error[0].Exception.Message
            $hasSeekPenalty = $false
        }
    }

    if ($hasRotationRate -eq 3 -and $hasSeekPenalty -eq $true) {
        $hasRotationRate = 2; # It's a hard drive
    }
    
    Write-Output -InputObject ($hasRotationRate)
    
}

End {
}
}

 

function Get-SimpleSysInfo {
Param ([string]$list)

    #Build array collectn
    $infoCollection = @() 
       
    Foreach ($l in $list)
    {
	    $BootInfo = Get-WmiObject Win32_BootConfiguration -ComputerName $l #Get Boot Information
        $CPUInfo = Get-WmiObject Win32_Processor -ComputerName $l #Get CPU Information
	    $OSInfo = Get-WmiObject Win32_OperatingSystem -ComputerName $l #Get OS Information
        $PCInfo = Get-WmiObject Win32_ComputerSystem -ComputerName $l #Get PC Information
        $GPUInfo = Get-WmiObject Win32_VideoController -ComputerName $l #Get GPU
    
        $BootDriveLetter =  $BootInfo.BootDirectory[0..1] -join ''
        $BootDiskNumber = $BootInfo.Caption.Split('\\')[2]
        $BootDiskNumber = $BootDiskNumber[($BootDiskNumber.Length-1)..$BootDiskNumber.Length] -join ''
        $BootPartitionNumber = $BootInfo.Caption.Split('\\')[3]
        $BootPartitionNumber = $BootPartitionNumber[($BootPartitionNumber.Length-1)..$BootPartitionNumber.Length] -join ''
   
        # Alternatives
        #        Get-WmiObject Win32_DiskDrive | sort Index | ft Index,DeviceID,@{l='Signature';e={"{0:X}" -f $_.Signature}},Model -a
        #
        #        $Disk = Get-WmiObject -Class Win32_logicaldisk | Where {$_.DeviceID -Match $BootDriveLetter}
        #        $DiskPartition = $Disk.GetRelated('Win32_DiskPartition')
        #        $DeviceID = $DiskPartition | Select-Object -Property DeviceID
        #        $Devicepart1 = ($DeviceID -split "Disk #")[1]; 
        #        $BootDiskNumber = ($Devicepart1 -split ",")[0]; 

        $OSServicePack = $OSInfo.ServicePackMajorVersion
        [version]$OSVersionType = $OSInfo | Select-Object -ExpandProperty Version
        
        #for Window 10+ release number, otherwise SP number [implicit computername scope, NO where clause]
        try
        {
            $OSVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ReleaseID -ErrorAction Stop).ReleaseID
        }
        catch
        {
            $OSVersion = $OSInfo.Version
        }
        #implicit computername scope, NO where clause       
        try
        {
            [string]$UpdateBuildRevision = $(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction Stop).UBR
            $UpdateBuildRevision = "." + $UpdateBuildRevision 
        }
        catch
        {
            $UpdateBuildRevision = ""
        }
        $CurrentBuild = $OSInfo.Version + $UpdateBuildRevision 

        #CPU info
        $CPUManufacturer = $CPUInfo | Select-Object -ExpandProperty Name
        #Manufacturer retail name contains dup spaces, save space for 1 liner
        $CPUManufacturer = $CPUManufacturer -replace '\s+', ' '
        $CPUManufacturer =$CPUManufacturer -replace '\(R\)', '' 
        $CPUManufacturer =$CPUManufacturer -replace '\(TM\)', '' 
        
        $CPUNumberOfCores = $CPUInfo | Select-Object -ExpandProperty NumberOfCores
        $CPUBits = $CPUInfo | Select-Object -ExpandProperty AddressWidth

	    #Get Memory Information. The data will be shown in a table as MB, rounded to the nearest second decimal.
	    #$OSTotalVirtualMemory = [math]::round($OSInfo.TotalVirtualMemorySize / 1MB, 2)
	    #$OSTotalVisibleMemory = [math]::round(($OSInfo.TotalVisibleMemorySize / 1MB), 2)
	    #$IPAddress = Get-WmiObject win32_Networkadapterconfiguration -ComputerName $l | Where-Object {$_.ipaddress -notlike $null}

        $PhysicalMemoryPrint = Get-WmiObject CIM_PhysicalMemory -ComputerName $l | Measure-Object -Property capacity -Sum | % {Get-FriendlyRAMSize -Bytes $_.sum}
        
       
                  
        if( $ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage"){ #powershell 3.0 or others 
          Write-Warning "Cannot add type/function embedded C# script which graps Drive Type and RPMs because your language mode is $($ExecutionContext.SessionState.LanguageMode)"  
          $RPMs = 4
        }
        else{
            [UInt32]$RPMs = GetHDRPMSSD $BootDriveLetter 
        }
        
        #Tue 02-Oct-18 3:50pm v2
        #SOURCE: http://www.t13.org/documents/UploadedDocuments/docs2009/d2015r1a-ATAATAPI_Command_Set_-_2_ACS-2.pdf
        #SECTION 7.18.7.81 
        #        Word 217: Nominal media rotation rate 
        #        Word 217 indicates the nominal media rotation rate of the device and is defined in table:
        #          Value           Description
        #          --------------------------------
        #          0000h           Rate not reported
        #          0001h           Non-rotating media (e.g., solid state device)
        #          0002h-0400h     Reserved
        #          0401h-FFFEh     Nominal media rotation rate in rotations per minute (rpm)
        #                          (e.g., 7 200 rpm = 1C20h)
        #          FFFFh           Reserved
                
        if ($RPMs -eq 0) {
           $HDTypeSpeedPrint = "HD" # the manufacturer has not encoded Rotation Rate/Spindle Speed - Check using https://gsmartcontrol.sourceforge.io
           Write-Warning "The disk drive manufacturer has not encoded Rotation Rate/Spindle Speed, therefore RPMs is not available."
        }
        elseif ($RPMs -eq 1) {
            $HDTypeSpeedPrint = "SSD"
        }
        elseif ($RPMs -eq 2) {
            $HDTypeSpeedPrint = "HD"
        }
        elseif ($RPMs -eq 3) {
            $HDTypeSpeedPrint = ""; 
            Write-Warning "Unknown error. Soln: Start-Process powershell -Verb runAs"
        }
        elseif ($RPMs -eq 4) {
            $HDTypeSpeedPrint = ""; 
            Write-Warning "Soln: Run in Powershell_ISE.exe as Admin"
        }
        elseif ($RPMs -eq 7) {
            $HDTypeSpeedPrint = ""; 
            Write-Warning "Embedded C# Script does not have elevated Admin privledges to grab Drive Type and RPM speed info. Soln: Start-Process powershell -Verb runAs"
        }
        elseif ($RPMs -eq 11) {
            $HDTypeSpeedPrint = ""; 
            Write-Warning "System cannot find that drive. $BootDriveLetter" 
        }
        elseif ($RPMs -gt 1024 -and $RPMs -lt 65535) {
            $HDTypeSpeedPrint = "HD @ " + "{0} RPM" -f {Get-FriendlySize -Number $RPMs}
        } else {
            $HDTypeSpeedPrint = "HD"
        }

        $PhysicalDrive = "\\.\PHYSICALDRIVE"+$BootDiskNumber     

        $HDSizeOnDiskPrint = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $l | Where-Object {$_.DriveType -ne 5 -and $_.Name -eq $BootDriveLetter} | Measure-Object -Property Size -Sum  | % {Get-FriendlyByteSize -Bytes $_.Sum}
        
        $HDSizeActualPrint = Get-WmiObject -Class Win32_DiskDrive -ComputerName $l | Where-Object {$_.DeviceID -eq $PhysicalDrive} | Measure-Object -Property Size -Sum  | % {Get-FriendlySize -Number $_.sum}
        
        #$HDSizeOnDisk = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -ne 5 -and $_.Name -EQ $BootDriveLetter} | Measure-Object -Property Size -Sum  | % {"{0:N1}" -f ($_.sum/1GB) -as [float]}
        #$HDSizeActual = Get-WmiObject -Class Win32_DiskDrive | Where-Object {$_.DeviceID -eq $PhysicalDrive} | Measure-Object -Property Size -Sum  | % {"{0:N1}" -f ($_.sum/1000000000) -as [float]}
        #$HDDiffPercentage = ($HDSizeOnDisk - $HDSizeActual)/$HDSizeOnDisk * 100 # percentage lost space to marketing misundestanding

        #Thu 04-Oct-18 1:52pm v2 - add GPU
        #$MaxGPU = New-Object -TypeName PSObject
        $GPUCnt = ($GPUInfo).count
        If ([string]::IsNullOrEmpty($GPUCnt)) { $GPUCnt=1 } else {Write-Warning "More that one GPU Card detected. Reporting max GPU RAM size and description found for brevity."}

        $MaxGPUProcName = ""
        $MaxRam = 0
       
        Foreach ($Card in $GPUInfo)
        {
            if ($MaxRam -lt $Card.AdapterRAM) 
            {
                $MaxRam = $Card.AdapterRAM
                $MaxGPUProcName = $Card.VideoProcessor
                #$MaxGPU | Add-Member NoteProperty "$($Card.DeviceID)_VideoProcessor" $Card.VideoProcessor
                #$MaxGPU | Add-Member NoteProperty "$($Card.DeviceID)_Description" $Card.Description #Probably not needed. Seems to just echo the name. Left here in case I'm wrong!
                #$MaxGPU | Add-Member NoteProperty "$($Card.DeviceID)_Vendor" $Card.AdapterCompatibility
                #$MaxGPU | Add-Member NoteProperty "$($Card.DeviceID)_PNPDeviceID" $Card.PNPDeviceID
                #$MaxGPU | Add-Member NoteProperty "$($Card.DeviceID)_DriverVersion" $Card.DriverVersion
                   
                #$MaxGPU | Add-Member NoteProperty "$($Card.DeviceID)_AdapterRam" $getRAM   #$Card.AdapterRAM
            }
        }
        $MaxRam = Get-FriendlyRAMSize $MaxRam

        #Hold output rows
		$infoObject = New-Object PSObject
		
        #Craft formatted row
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Computer Name" -value $l
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "PC Manufacturer Name" -value $PCInfo.Name
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "PC Manufacturer Model" -value $PCInfo.Model		    
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS Name" -value $OSInfo.Caption
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS Bits" -value $OSInfo.OSArchitecture
        


        If ($OSVersionType.Major -lt 10) {
            Add-Member -inputObject $infoObject -memberType NoteProperty -name "Service Pack" -value $OSServicePack
        } else {           
            Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS Version" -value $OSVersion
        }

		Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS Build" -value $CurrentBuild
	
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Server Name" -value $CPU.SystemName # alternative
        #Add-Member -inputObject $infoObject -memberType NoteProperty -name "IPv4_Address" -value $IPAddress.IPaddress[0]

        Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU Manufacturer" -value $CPUManufacturer
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU Bits" -value $CPUBits"-bit"
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Model" -value $CPU.Description
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Manufacturer" -value $CPU.Manufacturer


		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Physical Cores" -value $CPUNumberOfCores
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU L2 Cache Size" -value $CPU.L2CacheSize
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU L3 Cache Size" -value $CPU.L3CacheSize
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Sockets" -value $CPU.SocketDesignation
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Logical Cores" -value $CPU.NumberOfLogicalProcessors

        Add-Member -inputObject $infoObject -memberType NoteProperty -name "RAM" -value $PhysicalMemoryPrint 
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "RAM (GB)" -value $PhysicalMemory
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Total Virtual Memory (MB)" -value $OSTotalVirtualMemory
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Total Visable Memory (MB)" -value $OSTotalVisibleMemory
        
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "GPU Manufacturer" -value $MaxGPUProcName 
           
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "GPU RAM" -value $MaxRam
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "GPU Cores" -value $GPUCnt
        
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS Drive - Retail Size" -value $HDSizeActualPrint
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS Drive - Size On Disk" -value $HDSizeOnDiskPrint
        #Add-Member -inputObject $infoObject -memberType NoteProperty -name "Hard Drive C: Retail Size  (GB)" -value $HDSizeActual
        #Add-Member -inputObject $infoObject -memberType NoteProperty -name "Hard Drive C: Size On Disk (GB)" -value $HDSizeOnDisk
        #Add-Member -inputObject $infoObject -memberType NoteProperty -name "Hard Drive C: Marketing Loss %" -value $HDDiffPercentage

	    Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS Drive - Type" -value $HDTypeSpeedPrint
    
		$infoCollection += $infoObject	
    }
    #Output to the screen for a visual feedback or CSV
    $infoCollection 
    #| Export-Csv -path .\SimpleSysInfo_$((Get-Date).ToString('MMddyyyy_hhmmss')).csv -NoTypeInformation #Export the results in csv file.


    #the quotable one liner    
    foreach ($ic in $infoCollection) {
 
        If ($OSVersionType.Major -lt 10) {
             #$ic.'PC Manufacturer Name'+" ["+$ic.'PC Manufacturer Model' +"], "+ $ic.'OS Name' + " (" +'OS Bits' + ")," + " SP " +$ic.'Service Pack' + " (" +$ic.'OS Build' + "), " + ($ic.'CPU Manufacturer')  + " * " + $ic.'Physical Cores' + ", " + $ic.RAM + " RAM, " + $ic.'OS Drive - Retail Size' + " " + $ic.'OS Drive - Type'
              $ic.'OS Name' + "(" +$ic.'OS Bits' + ") " + "SP " +$ic.'Service Pack' + " (" +$ic.'OS Build' + "), " + ($ic.'CPU Manufacturer')  + " (" +$ic.'CPU Bits' + ")" +  " * " + $ic.'Physical Cores' + ", " + $ic.RAM + " RAM, " + $ic.'GPU Manufacturer' + " "+$ic.'GPU RAM' + " * " + $ic.'GPU Cores' + ", " + $ic.'OS Drive - Retail Size' + " " + $ic.'OS Drive - Type'
        } else {           
             #$ic.'PC Manufacturer Name'+" ["+$ic.'PC Manufacturer Model' +"], "+ $ic.'OS Name'  + " " + $ic.'OS Version' + " (" +$ic.'OS Build' + "), " + ($ic.'CPU Manufacturer') + " * " + $ic.'Physical Cores' + ", " + $ic.RAM + " RAM, " + $ic.'OS Drive - Retail Size' + " " + $ic.'OS Drive - Type'
             $ic.'OS Name'  + "(" +$ic.'OS Bits' + ") " + $ic.'OS Version' + " (" +$ic.'OS Build' + "), " + ($ic.'CPU Manufacturer') + " (" +$ic.'CPU Bits' + ")" + " * " + $ic.'Physical Cores' + ", " + $ic.RAM + " RAM, "+ ($ic.'GPU Manufacturer') + " "+$ic.'GPU RAM' + " * " + $ic.'GPU Cores' + ", " + $ic.'OS Drive - Retail Size' + " " + $ic.'OS Drive - Type'
        }

    }
 


} #End Get-SimpleSysInfo


#Get your computer name, or a list of computers (comma seperated)
$PCList = $env:computername;

Get-SimpleSysInfo -List $PCList