# Function to safely get WMI/CIM data
function Get-WmiDataSafely {
    param (
        [string]$Class,
        [string]$Namespace = "root\CIMV2",
        [scriptblock]$Filter = {$true}
    )
    try {
        # Try Get-CimInstance first (more reliable with permissions)
        try {
            $result = Get-CimInstance -ClassName $Class -Namespace $Namespace -ErrorAction Stop | 
                Where-Object $Filter
            if ($result) { return $result }
        } catch {
            Write-Verbose "CIM access failed, falling back to WMI: $($_.Exception.Message)"
        }

        # Fallback to Get-WmiObject
        try {
            $result = Get-WmiObject -Class $Class -Namespace $Namespace -ErrorAction Stop | 
                Where-Object $Filter
            if ($result) { return $result }
        } catch {
            Write-Verbose "WMI access failed: $($_.Exception.Message)"
        }

        # Last resort: try with alternative credentials if available
        try {
            $result = Get-CimInstance -ClassName $Class -Namespace $Namespace `
                -ComputerName "localhost" -ErrorAction Stop | 
                Where-Object $Filter
            if ($result) { return $result }
        } catch {
            Write-Warning "Failed to get $Class data after all attempts"
        }

        return $null
    } catch {
        Write-Warning "Failed to get $Class data: $($_.Exception.Message)"
        return $null
    }
}

# Function to safely access object properties
function Get-SafeValue {
    param (
        $Object,
        $PropertyName,
        $DefaultValue = "Unknown"
    )
    try {
        if ($null -eq $Object) { return $DefaultValue }
        $value = $Object.$PropertyName
        if ($null -eq $value) { return $DefaultValue }
        return $value
    } catch {
        return $DefaultValue
    }
}

# Get System Information with error handling
$cpu = Get-WmiDataSafely -Class Win32_Processor | Select-Object -First 1
$computerSystem = Get-WmiDataSafely -Class Win32_ComputerSystem
$ram = Get-SafeValue -Object $computerSystem -PropertyName "TotalPhysicalMemory" -DefaultValue 0
$ramGB = [math]::Round($ram/1GB, 2)

# Get GPU with fallback options
$gpu = Get-WmiDataSafely -Class Win32_VideoController
if (-not $gpu) {
    $gpu = @{
        Name = "Unknown Graphics Device"
        VideoMemoryType = "Unknown"
        AdapterRAM = 0
    }
}

# Get Disk info with validation
$disk = Get-WmiDataSafely -Class Win32_LogicalDisk -Filter { $_.DeviceID -eq 'C:' }
if (-not $disk) {
    $disk = @{
        Size = 0
        FreeSpace = 0
    }
}

# Get Network info with multiple adapter handling
$network = @(Get-WmiDataSafely -Class Win32_NetworkAdapterConfiguration -Filter { $_.IPEnabled -eq $true })
if ($network.Count -eq 0) {
    $network = @(@{
        Description = "No active network adapters"
        IPAddress = @("Not Available")
        MACAddress = "Not Available"
        DHCPEnabled = $false
        DHCPServer = "Not Available"
        DefaultIPGateway = @("Not Available")
        IPSubnet = @("Not Available")
    })
}

# Get OS Information
$os = Get-WmiDataSafely -Class Win32_OperatingSystem | 
    Select-Object Caption, Version, BuildNumber, OSArchitecture

# Add Windows version check function
function Test-Windows11 {
    param (
        [Parameter(Mandatory=$false)]
        [PSObject]$osInfo
    )
    
    try {
        # Check if running on Windows 11
        if ($osInfo.Caption -match "Windows 11") {
            return @{ IsWin11 = $true; Message = "Running Windows 11" }
        }
        
        # Check Windows 10 build number (Windows 11 is 22000 or higher)
        if ($osInfo.Caption -match "Windows 10" -and [int]$osInfo.BuildNumber -ge 22000) {
            return @{ IsWin11 = $true; Message = "Running Windows 11 (Windows 10 UI)" }
        }
        
        return @{ IsWin11 = $false; Message = "Running $($osInfo.Caption)" }
    }
    catch {
        return @{ IsWin11 = $false; Message = "Could not determine Windows version" }
    }
}

# Output Information
Write-Host "`nSystem Information Summary`n------------------------"
Write-Host "Computer Name: $(Get-SafeValue -Object $computerSystem -PropertyName 'Name')"
Write-Host "Model: $(Get-SafeValue -Object $computerSystem -PropertyName 'Manufacturer') $(Get-SafeValue -Object $computerSystem -PropertyName 'Model')"
Write-Host "CPU: $(Get-SafeValue -Object $cpu -PropertyName 'Name')"
Write-Host "CPU Cores: $(Get-SafeValue -Object $cpu -PropertyName 'NumberOfCores' -DefaultValue 0)"
Write-Host "CPU Logical Processors: $(Get-SafeValue -Object $cpu -PropertyName 'NumberOfLogicalProcessors' -DefaultValue 0)"
Write-Host "RAM: $ramGB GB"
Write-Host "GPU: $($gpu.Name)"
Write-Host "OS: $($os.Caption)"
Write-Host "OS Version: $($os.Version)"
Write-Host "OS Architecture: $($os.OSArchitecture)"
Write-Host "Disk Size: $([math]::Round($disk.Size/1GB, 2)) GB"
Write-Host "Free Space: $([math]::Round($disk.FreeSpace/1GB, 2)) GB"

Write-Host "`nNetwork Information:"
foreach ($adapter in $network) {
    Write-Host "`nAdapter: $(Get-SafeValue -Object $adapter -PropertyName 'Description')"
    $ipAddress = Get-SafeValue -Object $adapter -PropertyName 'IPAddress' -DefaultValue @("Not Available")
    Write-Host "IP Address: $($ipAddress[0])"
    Write-Host "MAC Address: $(Get-SafeValue -Object $adapter -PropertyName 'MACAddress')"
    $dhcpEnabled = Get-SafeValue -Object $adapter -PropertyName 'DHCPEnabled' -DefaultValue $false
    Write-Host "IP Assignment: $(if ($dhcpEnabled) { 'DHCP' } else { 'Static' })"
    if ($dhcpEnabled) {
        Write-Host "DHCP Server: $(Get-SafeValue -Object $adapter -PropertyName 'DHCPServer')"
    }
    $subnet = Get-SafeValue -Object $adapter -PropertyName 'IPSubnet' -DefaultValue @("Not Available")
    Write-Host "Subnet Mask: $($subnet[0])"
    $gateway = Get-SafeValue -Object $adapter -PropertyName 'DefaultIPGateway' -DefaultValue @("Not Available")
    Write-Host "Default Gateway: $($gateway[0])"
}

# Windows 11 Compatibility Checks
function Get-Windows11Compatibility {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [PSObject]$cpu,
        [Parameter(Mandatory=$false)]
        [PSObject]$ram,
        [Parameter(Mandatory=$false)]
        [PSObject]$disk,
        [Parameter(Mandatory=$false)]
        [PSObject]$gpu,
        [Parameter(Mandatory=$false)]
        [double]$ramGB = 0,
        [Parameter(Mandatory=$false)]
        [double]$diskGB = 0
    )

    # Initialize result object with detailed status tracking
    $result = [PSCustomObject]@{
        CpuCompatible = $false
        TpmCompatible = $false
        TpmEnabled = $false
        SecureBootCompatible = $false
        SecureBootState = $false
        RamCompatible = $false
        DiskCompatible = $false
        DisplayCompatible = $false
        DirectXCompatible = $false
        DxVersion = "Unknown"
        AllCompatible = $false
        Details = @{
            CPU = @{
                Status = "Unknown"
                Details = @()
                ErrorMessage = $null
            }
            TPM = @{
                Status = "Unknown"
                Details = @()
                ErrorMessage = $null
            }
            SecureBoot = @{
                Status = "Unknown"
                Details = @()
                ErrorMessage = $null
            }
            Memory = @{
                Status = "Unknown"
                Details = @()
                ErrorMessage = $null
            }
            Storage = @{
                Status = "Unknown"
                Details = @()
                ErrorMessage = $null
            }
            Display = @{
                Status = "Unknown"
                Details = @()
                ErrorMessage = $null
            }
            DirectX = @{
                Status = "Unknown"
                Details = @()
                ErrorMessage = $null
            }
        }
        Guidance = @()
    }

    # CPU Check with enhanced detection
    try {
        $cpuInfo = if ($cpu) { $cpu } else {
            Get-WmiDataSafely -Class Win32_Processor | Select-Object -First 1
        }
        
        $result.CpuCompatible = $false
        $cores = Get-SafeValue -Object $cpuInfo -PropertyName 'NumberOfCores' -DefaultValue 0
        $frequency = Get-SafeValue -Object $cpuInfo -PropertyName 'MaxClockSpeed' -DefaultValue 0
        $architecture = Get-SafeValue -Object $cpuInfo -PropertyName 'AddressWidth' -DefaultValue 32
        
        $result.Details.CPU.Details += "Cores: $cores (Required: 2+)"
        $result.Details.CPU.Details += "Frequency: $frequency MHz (Required: 1000+ MHz)"
        $result.Details.CPU.Details += "Architecture: $architecture-bit (Required: 64-bit)"
        
        $result.CpuCompatible = ($cores -ge 2) -and ($frequency -ge 1000) -and ($architecture -eq 64)
        $result.Details.CPU.Status = if ($result.CpuCompatible) { "Pass" } else { "Fail" }
    }
    catch {
        $result.Details.CPU.ErrorMessage = $_.Exception.Message
        $result.Details.CPU.Status = "Error"
        Write-Warning "CPU check failed: $($_.Exception.Message)"
    }

    # Enhanced TPM Check
    try {
        $tpmDetectionMethods = @(
            @{
                Name = "Get-Tpm"
                Script = {
                    $tpm = Get-Tpm -ErrorAction Stop
                    @{
                        Present = $tpm.TpmPresent
                        Enabled = $tpm.TpmReady
                        Version = if ($tpm.TpmPresent) { "2.0" } else { "None" }
                    }
                }
            },
            @{
                Name = "WMI TPM"
                Script = {
                    $tpmWmi = Get-WmiDataSafely -Class Win32_Tpm -Namespace "root\CIMV2\Security\MicrosoftTpm"
                    if ($null -ne $tpmWmi) {
                        @{
                            Present = $true
                            Enabled = $tpmWmi.IsEnabled_InitialValue
                            Version = "2.0"
                        }
                    }
                    else { throw "No TPM found via WMI" }
                }
            },
            @{
                Name = "Registry TPM"
                Script = {
                    $tpmRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\TPM\*"
                    if (Test-Path $tpmRegPath) {
                        @{
                            Present = $true
                            Enabled = $true
                            Version = "2.0"
                        }
                    }
                    else { throw "No TPM registry entries found" }
                }
            }
        )

        $tpmStatus = $null
        foreach ($method in $tpmDetectionMethods) {
            try {
                $tpmStatus = & $method.Script
                $result.Details.TPM.Details += "Detected via $($method.Name)"
                break
            }
            catch {
                $result.Details.TPM.Details += "Failed $($method.Name): $($_.Exception.Message)"
                continue
            }
        }

        if ($tpmStatus) {
            $result.TpmCompatible = $tpmStatus.Present
            $result.TpmEnabled = $tpmStatus.Enabled
            $result.Details.TPM.Status = if ($result.TpmEnabled) { "Pass" } else { "Warning" }
        }
    }
    catch {
        $result.Details.TPM.ErrorMessage = $_.Exception.Message
        $result.Details.TPM.Status = "Error"
        Write-Warning "TPM check failed: $($_.Exception.Message)"
    }

    # Enhanced Secure Boot Check
    try {
        $secureBootMethods = @(
            @{
                Name = "Confirm-SecureBootUEFI"
                Script = {
                    $state = Confirm-SecureBootUEFI -ErrorAction Stop
                    @{
                        Compatible = $true
                        Enabled = $state
                    }
                }
            },
            @{
                Name = "Registry"
                Script = {
                    $value = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" `
                        -Name "UEFISecureBootEnabled" -ErrorAction Stop
                    @{
                        Compatible = $true
                        Enabled = $value.UEFISecureBootEnabled -eq 1
                    }
                }
            }
        )

        $secureBootStatus = $null
        foreach ($method in $secureBootMethods) {
            try {
                $secureBootStatus = & $method.Script
                $result.Details.SecureBoot.Details += "Detected via $($method.Name)"
                break
            }
            catch {
                $result.Details.SecureBoot.Details += "Failed $($method.Name): $($_.Exception.Message)"
                continue
            }
        }

        if ($secureBootStatus) {
            $result.SecureBootCompatible = $secureBootStatus.Compatible
            $result.SecureBootState = $secureBootStatus.Enabled
            $result.Details.SecureBoot.Status = if ($result.SecureBootState) { "Pass" } else { "Warning" }
        }
    }
    catch {
        $result.Details.SecureBoot.ErrorMessage = $_.Exception.Message
        $result.Details.SecureBoot.Status = "Error"
        Write-Warning "Secure Boot check failed: $($_.Exception.Message)"
    }

    # Basic Requirements with better error handling
    try {
        $result.RamCompatible = $ramGB -ge 4
        $result.Details.Memory.Status = if ($result.RamCompatible) { "Pass" } else { "Fail" }
        $result.Details.Memory.Details += "Available: $ramGB GB (Required: 4+ GB)"
    }
    catch {
        $result.Details.Memory.ErrorMessage = $_.Exception.Message
        $result.Details.Memory.Status = "Error"
    }

    try {
        $result.DiskCompatible = $diskGB -ge 64
        $result.Details.Storage.Status = if ($result.DiskCompatible) { "Pass" } else { "Fail" }
        $result.Details.Storage.Details += "Available: $diskGB GB (Required: 64+ GB)"
    }
    catch {
        $result.Details.Storage.ErrorMessage = $_.Exception.Message
        $result.Details.Storage.Status = "Error"
    }

    # Enhanced Display Check
    try {
        $resolution = if ($gpu) {
            $gpu.CurrentHorizontalResolution * $gpu.CurrentVerticalResolution
        } else { 0 }
        
        $result.DisplayCompatible = $resolution -ge (1280 * 720)
        $result.Details.Display.Status = if ($result.DisplayCompatible) { "Pass" } else { "Fail" }
        $result.Details.Display.Details += "Resolution: $($gpu.CurrentHorizontalResolution)x$($gpu.CurrentVerticalResolution) (Required: 1280x720)"
    }
    catch {
        $result.Details.Display.ErrorMessage = $_.Exception.Message
        $result.Details.Display.Status = "Error"
    }

    # Improved DirectX Check
    try {
        $dxCheck = Get-DirectXCheck -gpu $gpu
        $result.DirectXCompatible = $dxCheck.Compatible
        $result.DxVersion = $dxCheck.Version
        $result.Details.DirectX.Status = if ($result.DirectXCompatible) { "Pass" } else { "Fail" }
        $result.Details.DirectX.Details += $dxCheck.Details
    }
    catch {
        $result.Details.DirectX.ErrorMessage = $_.Exception.Message
        $result.Details.DirectX.Status = "Error"
    }

    # Calculate overall compatibility
    $result.AllCompatible = $result.CpuCompatible -and 
                           $result.TpmCompatible -and 
                           $result.SecureBootCompatible -and 
                           $result.RamCompatible -and 
                           $result.DiskCompatible -and 
                           $result.DisplayCompatible -and 
                           $result.DirectXCompatible

    # Generate specific guidance
    if (-not $result.TpmEnabled -and $result.TpmCompatible) {
        $result.Guidance += "TPM 2.0 is available but not enabled. Check BIOS/UEFI settings."
    }
    if (-not $result.SecureBootState -and $result.SecureBootCompatible) {
        $result.Guidance += "Secure Boot is available but not enabled. Check BIOS/UEFI settings."
    }

    return $result
}

function Get-DirectXCheck {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [PSObject]$gpu
    )

    $result = @{
        Compatible = $false
        Version = "Unknown"
        Details = @()
    }

    try {
        # Known DX12 compatible GPU patterns
        $dx12Patterns = @{
            NVIDIA = @(
                'GTX [789]\d0', 'GTX 1\d{3}', 
                'RTX [234]\d{3}', 'RTX 30\d0', 'RTX 40\d0'
            )
            AMD = @(
                'RX \d{3}', 'RX \d{4}', 'Vega',
                'RDNA', 'Radeon R[79]'
            )
            Intel = @(
                'UHD Graphics [6789]\d{2}',
                'Iris Xe', 'Arc A[357]\d{2}'
            )
        }

        $gpuName = Get-SafeValue -Object $gpu -PropertyName 'Name' -DefaultValue ''
        $result.Details += "GPU Name: $gpuName"

        # Check each vendor's patterns
        foreach ($vendor in $dx12Patterns.Keys) {
            foreach ($pattern in $dx12Patterns[$vendor]) {
                if ($gpuName -match $pattern) {
                    $result.Compatible = $true
                    $result.Version = "12.0"
                    $result.Details += "Matched $vendor pattern: $pattern"
                    return $result
                }
            }
        }

        # Fallback checks
        $gpuMemoryGB = [math]::Round($(Get-SafeValue -Object $gpu -PropertyName 'AdapterRAM' -DefaultValue 0)/1GB, 2)
        $result.Details += "GPU Memory: $gpuMemoryGB GB"
        
        if ($gpuMemoryGB -ge 2) {
            $result.Compatible = $true
            $result.Version = "12.0"
            $result.Details += "Sufficient GPU memory detected"
        }
    }
    catch {
        $result.Details += "Error during DirectX check: $($_.Exception.Message)"
    }

    return $result
}

# Update the Windows 11 compatibility check section
Write-Host "`nWindows Version Check`n---------------------------"
$windowsCheck = Test-Windows11 -osInfo $os
Write-Host $windowsCheck.Message

if ($windowsCheck.IsWin11) {
    Write-Host "`nSystem is already running Windows 11"
} else {
    Write-Host "`nWindows 11 Compatibility Check`n---------------------------"
    $win11Compat = Get-Windows11Compatibility -cpu $cpu -ram $ram -disk $disk -gpu $gpu -ramGB $ramGB `
        -diskGB $([math]::Round($disk.Size/1GB, 2)) -Verbose

    # Display results with enhanced details
    foreach ($component in $win11Compat.Details.Keys) {
        Write-Host "`n$component Status: $($win11Compat.Details.$component.Status)"
        foreach ($detail in $win11Compat.Details.$component.Details) {
            Write-Host "  $detail"
        }
        if ($win11Compat.Details.$component.ErrorMessage) {
            Write-Host "  Error: $($win11Compat.Details.$component.ErrorMessage)" -ForegroundColor Red
        }
    }

    # Display guidance
    if ($win11Compat.Guidance.Count -gt 0) {
        Write-Host "`nRecommended Actions:" -ForegroundColor Yellow
        foreach ($guidance in $win11Compat.Guidance) {
            Write-Host "- $guidance" -ForegroundColor Yellow
        }
    }

    Write-Host "`nOverall Windows 11 Compatible: $($win11Compat.AllCompatible)"
}

# Create CSV export
$exportPath = ".\SystemInfo.csv"

# Create headers if file doesn't exist
if (-not (Test-Path $exportPath)) {
    # Create empty CSV with headers
    [PSCustomObject]@{
        Computer_Name = ""
        Computer_Model = ""
        Computer_Manufacturer = ""
        CPU_Name = ""
        CPU_Cores = ""
        CPU_LogicalProcessors = ""
        RAM_GB = ""
        GPU_Name = ""
        OS_Name = ""
        OS_Version = ""
        OS_Architecture = ""
        Disk_Size_GB = ""
        Disk_FreeSpace_GB = ""
        Network_Adapter = ""
        IP_Address = ""
        MAC_Address = ""
        Network_IP_Assignment = ""
        Network_DHCP_Server = ""
        Network_Subnet = ""
        Network_Gateway = ""
        Export_Date = ""
        Win11_CPU_Compatible = ""
        Win11_TPM_Capable = ""
        Win11_TPM_Enabled = ""
        Win11_SecureBoot_Capable = ""
        Win11_SecureBoot_State = ""
        Win11_RAM_Compatible = ""
        Win11_Storage_Compatible = ""
        Win11_Display_Compatible = ""
        Win11_DirectX_Compatible = ""
        Win11_Overall_Compatible = ""
    } | Export-Csv -Path $exportPath -NoTypeInformation
}

# Create custom object with system information
$systemInfo = [PSCustomObject]@{
    Computer_Name = $(Get-SafeValue -Object $computerSystem -PropertyName 'Name')
    Computer_Model = $(Get-SafeValue -Object $computerSystem -PropertyName 'Model')
    Computer_Manufacturer = $(Get-SafeValue -Object $computerSystem -PropertyName 'Manufacturer')
    CPU_Name = $(Get-SafeValue -Object $cpu -PropertyName 'Name')
    CPU_Cores = $(Get-SafeValue -Object $cpu -PropertyName 'NumberOfCores' -DefaultValue 0)
    CPU_LogicalProcessors = $(Get-SafeValue -Object $cpu -PropertyName 'NumberOfLogicalProcessors' -DefaultValue 0)
    RAM_GB = $ramGB
    GPU_Name = $gpuName
    OS_Name = $os.Caption
    OS_Version = $os.Version
    OS_Architecture = $os.OSArchitecture
    Disk_Size_GB = [math]::Round($disk.Size/1GB, 2)
    Disk_FreeSpace_GB = [math]::Round($disk.FreeSpace/1GB, 2)
    Network_Adapter = $(Get-SafeValue -Object $network[0] -PropertyName 'Description')
    IP_Address = $(Get-SafeValue -Object $network[0] -PropertyName 'IPAddress' -DefaultValue @("Not Available"))[0]
    MAC_Address = $(Get-SafeValue -Object $network[0] -PropertyName 'MACAddress')
    Network_IP_Assignment = if ($(Get-SafeValue -Object $network[0] -PropertyName 'DHCPEnabled' -DefaultValue $false)) { 'DHCP' } else { 'Static' }
    Network_DHCP_Server = $(Get-SafeValue -Object $network[0] -PropertyName 'DHCPServer')
    Network_Subnet = $(Get-SafeValue -Object $network[0] -PropertyName 'IPSubnet' -DefaultValue @("Not Available"))[0]
    Network_Gateway = $(Get-SafeValue -Object $network[0] -PropertyName 'DefaultIPGateway' -DefaultValue @("Not Available"))[0]
    Export_Date = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Win11_CPU_Compatible = $win11Compat.CpuCompatible
    Win11_TPM_Capable = $win11Compat.TpmCompatible
    Win11_TPM_Enabled = $win11Compat.TpmEnabled
    Win11_SecureBoot_Capable = $win11Compat.SecureBootCompatible
    Win11_SecureBoot_State = $win11Compat.SecureBootState
    Win11_RAM_Compatible = $win11Compat.RamCompatible
    Win11_Storage_Compatible = $win11Compat.DiskCompatible
    Win11_Display_Compatible = $win11Compat.DisplayCompatible
    Win11_DirectX_Compatible = $win11Compat.DirectXCompatible
    Win11_Overall_Compatible = $win11Compat.AllCompatible
}

# Always append the data
try {
    $systemInfo | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Add-Content -Path $exportPath
} catch {
    Write-Error "Failed to export to CSV: $($_.Exception.Message)"
}

Write-Host "`nSystem information appended to $exportPath"

# Add overall script error handling
trap {
    Write-Error "Script error: $($_.Exception.Message)"
    Write-Error "at line: $($_.InvocationInfo.ScriptLineNumber)"
    exit 1
}