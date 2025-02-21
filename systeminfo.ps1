# Function to safely get WMI data
function Get-WmiDataSafely {
    param (
        [string]$Class,
        [string]$Namespace = "root\CIMV2",
        [scriptblock]$Filter = {$true}
    )
    try {
        Get-WmiObject -Class $Class -Namespace $Namespace | Where-Object $Filter
    } catch {
        Write-Warning "Failed to get $Class data: $($_.Exception.Message)"
        $null
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
    Select-Object Caption, Version, OSArchitecture

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
Write-Host "`nWindows 11 Compatibility Check`n---------------------------"

# CPU Compatibility (reusing existing CPU info)
try {
    $cpuCompatible = ($null -ne $cpu) -and (Get-SafeValue -Object $cpu -PropertyName 'NumberOfCores' -DefaultValue 0) -ge 2
} catch {
    Write-Warning "Error during CPU compatibility check: $($_.Exception.Message)"
    $cpuCompatible = $false
}

# TPM Check
try {
    $tpmEnabled = $false
    $tpmVersion = "0.0"
    $tpmCompatible = $false

    # Method 1: Try Get-Tpm cmdlet first (most reliable on newer systems)
    try {
        $tpm = Get-Tpm
        if ($tpm) {
            $tpmEnabled = $tpm.TpmPresent -and $tpm.TpmReady
            $tpmCompatible = $tpm.TpmPresent
        }
    } catch {
        Write-Warning "Get-Tpm failed, trying alternative methods"
    }

    # Method 2: WMI TPM check if Get-Tpm failed
    if (-not $tpmCompatible) {
        $tpmWmi = Get-WmiDataSafely -Class Win32_Tpm -Namespace "root\CIMV2\Security\MicrosoftTpm"
        if ($null -ne $tpmWmi) {
            $tpmVersion = if ($tpmWmi.SpecVersion) { 
                try {
                    [System.Version]$tpmWmi.SpecVersion
                    $tpmCompatible = $true
                } catch {
                    "0.0"
                }
            } else { "0.0" }
            $tpmEnabled = $tpmWmi.IsEnabled_InitialValue -eq $true
        }
    }

    # Method 3: Registry check
    if (-not $tpmCompatible) {
        try {
            $tpmReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\TPM\*" -ErrorAction Stop
            if ($tpmReg.SpecVersion) {
                $tpmVersion = [System.Version]$tpmReg.SpecVersion
                $tpmCompatible = $true
                $tpmEnabled = $true
            }
        } catch {
            Write-Warning "Registry TPM check failed"
        }
    }

    # Method 4: Manufacturer/Model check as last resort
    if (-not $tpmCompatible) {
        $manufacturer = Get-WmiDataSafely -Class Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer
        # Most business/consumer systems made after 2016 have TPM 2.0
        if ($manufacturer -match "(Dell|HP|Lenovo|ASUS|Acer|Microsoft)" -and 
            $computerSystem.Model -match "20(1[6-9]|2[0-3])") {
            $tpmCompatible = $true
            $tpmEnabled = $false
            $tpmVersion = "2.0"
        }
    }

    # Add warning if TPM capable but disabled
    if ($tpmCompatible -and -not $tpmEnabled) {
        Write-Host "WARNING: TPM appears to be available but may not be enabled in BIOS" -ForegroundColor Yellow
        Write-Host "        Check BIOS settings to enable TPM if needed" -ForegroundColor Yellow
    }

} catch {
    Write-Warning "Error during TPM check: $($_.Exception.Message)"
    $tpmCompatible = $false
    $tpmEnabled = $false
}

# SecureBoot Check
try {
    # Check if system is UEFI using multiple methods
    $isUEFI = $false
    
    # Method 1: Check firmware type using Get-ComputerInfo
    try {
        $firmware = Get-ComputerInfo -Property BiosFirmwareType
        $isUEFI = $firmware.BiosFirmwareType -eq "Uefi"
    } catch {
        # Method 2: Check bootup state
        $firmware = Get-WmiDataSafely -Class Win32_ComputerSystem
        $isUEFI = $firmware.BootupState -match "UEFI" -or $firmware.BootupState -match "Normal"
    }
    
    # Method 3: Check if SecureBoot registry key exists (indicates UEFI capability)
    if (-not $isUEFI) {
        $isUEFI = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
    }
    
    # Check current Secure Boot state using multiple methods
    $secureBootState = $false
    
    # Method 1: Direct registry check
    try {
        $secureBootKey = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction Stop
        $secureBootState = $secureBootKey.UEFISecureBootEnabled -eq 1
    } catch {
        # Method 2: Confirm-SecureBootUEFI (might not be available on all systems)
        try {
            $secureBootState = Confirm-SecureBootUEFI -ErrorAction Stop
        } catch {
            # Method 3: Check system environment variables
            $secureBootState = [System.Environment]::GetEnvironmentVariable("FIRMWARE_TYPE") -eq "UEFI" -and
                             [System.Environment]::GetEnvironmentVariable("SECURE_BOOT") -eq "1"
        }
    }

    # Final check: look for secure boot policy settings
    if (-not $secureBootState -and $isUEFI) {
        try {
            $securePolicies = Get-WmiDataSafely -Class Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard"
            $secureBootState = $securePolicies.SecurityServicesRunning -contains 1
        } catch {
            # Ignore if this check fails
        }
    }

    # System is Secure Boot compatible if it's UEFI, regardless of current state
    $secureBootCompatible = $isUEFI
    
    # Add warning message if capable but disabled
    if ($secureBootCompatible -and -not $secureBootState) {
        Write-Host "WARNING: System is Secure Boot capable but it is currently disabled" -ForegroundColor Yellow
        Write-Host "        Enable Secure Boot in UEFI/BIOS settings to meet Windows 11 requirements" -ForegroundColor Yellow
    }

} catch {
    Write-Warning "Error during Secure Boot check: $($_.Exception.Message)"
    $secureBootCompatible = $false
    $secureBootState = $false
}

# RAM Check (reusing existing RAM info)
try {
    $ramCompatible = $ramGB -ge 4
} catch {
    Write-Warning "Error during RAM compatibility check: $($_.Exception.Message)"
    $ramCompatible = $false
}

# Storage Check (reusing existing disk info)
try {
    $diskGB = [math]::Round($disk.Size/1GB, 2)
    $diskCompatible = $diskGB -ge 64
} catch {
    Write-Warning "Error during storage compatibility check: $($_.Exception.Message)"
    $diskCompatible = $false
}

# Display Check (reusing existing GPU info)
try {
    $displayCompatible = $gpu.CurrentHorizontalResolution * $gpu.CurrentVerticalResolution -ge (1280 * 720)
} catch {
    Write-Warning "Error during display compatibility check: $($_.Exception.Message)"
    $displayCompatible = $false
}

# DirectX Check
try {
    $gpu = Get-WmiDataSafely -Class Win32_VideoController
    
    # Known DX12 compatible GPU series
    $dx12CompatibleGPUs = @(
        # NVIDIA
        'GTX [789]\d0', 'GTX 1\d{3}', 'RTX [234]\d{3}', 'RTX 30\d0', 'RTX 40\d0',
        # AMD
        'RX \d{3}', 'RX \d{4}', 'Vega', 'RDNA', 'Radeon R[79]',
        # Intel
        'UHD Graphics [6789]\d{2}', 'Iris Xe', 'Arc A[357]\d{2}'
    )
    
    $isDX12Compatible = $false
    foreach ($pattern in $dx12CompatibleGPUs) {
        if ($gpu.Name -match $pattern) {
            $isDX12Compatible = $true
            break
        }
    }

    # If GPU not in known list but relatively modern, check additional indicators
    if (-not $isDX12Compatible) {
        # Check if GPU has enough memory (2GB minimum for DX12)
        $gpuMemoryGB = [math]::Round($gpu.AdapterRAM/1GB, 2)
        $hasEnoughMemory = $gpuMemoryGB -ge 2

        # Check if running on Windows 10 or higher (indirect DX12 capability check)
        $isWin10OrHigher = [System.Environment]::OSVersion.Version.Major -ge 10

        $isDX12Compatible = $hasEnoughMemory -and $isWin10OrHigher
    }

    $dxVersion = if ($isDX12Compatible) { "12.0 Compatible" } else { "Pre-DX12" }
} catch {
    Write-Warning "Error during DirectX compatibility check: $($_.Exception.Message)"
    $isDX12Compatible = $false
    $dxVersion = "Unknown"
}

# Output Windows 11 Compatibility Results
Write-Host "CPU (2 cores, 1GHz+): $($cpuCompatible)"
Write-Host "TPM 2.0 Capable: $($tpmCompatible)"
Write-Host "TPM Enabled: $($tpmEnabled)"
Write-Host "Secure Boot Capable: $($secureBootCompatible)"
Write-Host "Secure Boot State: $($secureBootState)"
Write-Host "RAM (>= 4GB): $($ramCompatible) ($ramGB GB)"
Write-Host "Storage (>= 64GB): $($diskCompatible) ($diskGB GB)"
Write-Host "Display (>= 720p): $($displayCompatible)"
Write-Host "DirectX 12: $($isDX12Compatible) (Version: $dxVersion)"

$allCompatible = $cpuCompatible -and $tpmCompatible -and $secureBootCompatible -and 
                 $ramCompatible -and $diskCompatible -and $displayCompatible -and 
                 $isDX12Compatible

Write-Host "`nOverall Windows 11 Compatible: $($allCompatible)"

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
    GPU_Name = $gpu.Name
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
    Win11_CPU_Compatible = $cpuCompatible
    Win11_TPM_Capable = $tpmCompatible
    Win11_TPM_Enabled = $tpmEnabled
    Win11_SecureBoot_Capable = $secureBootCompatible
    Win11_SecureBoot_State = $secureBootState
    Win11_RAM_Compatible = $ramCompatible
    Win11_Storage_Compatible = $diskCompatible
    Win11_Display_Compatible = $displayCompatible
    Win11_DirectX_Compatible = $isDX12Compatible
    Win11_Overall_Compatible = $allCompatible
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