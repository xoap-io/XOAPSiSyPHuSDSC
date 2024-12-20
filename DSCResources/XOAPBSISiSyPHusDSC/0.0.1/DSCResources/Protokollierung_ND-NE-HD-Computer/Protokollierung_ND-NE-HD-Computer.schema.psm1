configuration Protokollierung_ND-NE-HD-Computer
{

    param(
        [bool]$ProcessCreationIncludeCmdLineEnabled = $true,
        [bool]$MaxSizeApplicationLog = $true,
        [bool]$RetentionApplicationLog = $true,
        [bool]$RetentionSecurityLog = $true,
        [bool]$MaxSizeSecurityLog = $true,
        [bool]$MaxSizeSetupLog = $true,
        [bool]$RetentionSetupLog = $true,
        [bool]$MaxSizeSystemLog = $true,
        [bool]$RetentionSystemLog = $true,
        [bool]$EnableModuleLogging = $true,
        [bool]$ModuleNames = $true,
        [bool]$EnableScriptBlockLogging = $true,
        [bool]$EnableScriptBlockInvocationLogging_Delete = $true,
        [bool]$EnableTranscripting = $true,
        [bool]$OutputDirectory = $true,
        [bool]$EnableInvocationHeader = $true,
        [bool]$PolicyVersion = $true,
        [bool]$LogFilePath = $true,
        [bool]$LogFileSizeDomainProfile = $true,
        [bool]$LogDroppedPacketsDomainProfile = $true,
        [bool]$LogSuccessfulConnectionsDomainProfile = $true,
        [bool]$LogFilePathPrivateProfile = $true,
        [bool]$LogFileSizePrivateProfile = $true,
        [bool]$LogDroppedPacketsPrivateProfile = $true,
        [bool]$LogSuccessfulConnectionsPrivateProfile = $true,
        [bool]$LogFilePathPublicProfile = $true,
        [bool]$LogFileSizePublicProfile = $true,
        [bool]$LogDroppedPacketsPublicProfile = $true,
        [bool]$LogSuccessfulConnections = $true,
        [bool]$WarningLevel = $true,
        [bool]$ForceAuditPolicySubcategorySettings = $true,
        [bool]$ShutdownIfUnableToLogAudits = $true
    )
    
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($ProcessCreationIncludeCmdLineEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
        }
    }
    
    if ($MaxSizeApplicationLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            ValueType = 'Dword'
            ValueData = 32768
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
        }
    }
    
    if ($RetentionApplicationLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\Retention'
        {
            ValueType = 'String'
            ValueData = '0'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Retention'
        }
    }
    
    if ($RetentionSecurityLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention'
        {
            ValueType = 'String'
            ValueData = '0'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Retention'
        }
    }
    if ($MaxSizeSecurityLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            ValueType = 'Dword'
            ValueData = 524288
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
        }
    }
    
    if ($MaxSizeSetupLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\MaxSize'
        {
            ValueType = 'Dword'
            ValueData = 32768
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
        }
    }
    
    if ($RetentionSetupLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\Retention'
        {
            ValueType = 'String'
            ValueData = '0'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Retention'
        }
    }
    
    if ($MaxSizeSystemLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            ValueType = 'Dword'
            ValueData = 32768
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
        }
    }
    
    if ($RetentionSystemLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\Retention'
        {
            ValueType = 'String'
            ValueData = '0'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Retention'
        }
    }
    if ($EnableModuleLogging) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableModuleLogging'
        }
    }
    
    if ($ModuleNames) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames\*'
        {
            ValueType = 'String'
            ValueData = '*'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
            TargetType = 'ComputerConfiguration'
            ValueName = '*'
        }
    }
    
    if ($EnableScriptBlockLogging) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableScriptBlockLogging'
        }
    }
    
    if ($EnableScriptBlockInvocationLogging_Delete) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
        {
            ValueType = 'String'
            ValueData = ''
            Ensure = 'Absent'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableScriptBlockInvocationLogging'
        }
    }
    
    if ($EnableTranscripting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableTranscripting'
        }
    }
    if ($OutputDirectory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
        {
            ValueType = 'String'
            ValueData = $null  # Set to $null as required for policy configurations
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            TargetType = 'ComputerConfiguration'
            ValueName = 'OutputDirectory'
        }
    }
    
    if ($EnableInvocationHeader) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableInvocationHeader'
        }
    }
    
    if ($PolicyVersion) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PolicyVersion'
        {
            ValueType = 'Dword'
            ValueData = 541
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PolicyVersion'
        }
    }
    
    if ($LogFilePath) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath'
        {
            ValueType = 'String'
            ValueData = '%systemroot%\system32\logfiles\firewall\domainfw.log'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogFilePath'
        }
    }

    if ($LogFileSizeDomainProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
        {
            ValueType = 'Dword'
            ValueData = 16384
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogFileSize'
        }
    }
    
    if ($LogDroppedPacketsDomainProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogDroppedPackets'
        }
    }
    
    if ($LogSuccessfulConnectionsDomainProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogSuccessfulConnections'
        }
    }
    
    if ($LogFilePathPrivateProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFilePath'
        {
            ValueType = 'String'
            ValueData = '%systemroot%\system32\logfiles\firewall\privatefw.log'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogFilePath'
        }
    }
    
    if ($LogFileSizePrivateProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize'
        {
            ValueType = 'Dword'
            ValueData = 16384
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogFileSize'
        }
    }
    if ($LogDroppedPacketsPrivateProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogDroppedPackets'
        }
    }
    
    if ($LogSuccessfulConnectionsPrivateProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogSuccessfulConnections'
        }
    }
    
    if ($LogFilePathPublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFilePath'
        {
            ValueType = 'String'
            ValueData = '%systemroot%\system32\logfiles\firewall\publicfw.log'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogFilePath'
        }
    }
    
    if ($LogFileSizePublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize'
        {
            ValueType = 'Dword'
            ValueData = 16384
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogFileSize'
        }
    }
    
    if ($LogDroppedPacketsPublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogDroppedPackets'
        }
    }
    if ($LogSuccessfulConnections) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogSuccessfulConnections'
        }
    }
    
    if ($WarningLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel'
        {
            ValueType = 'Dword'
            ValueData = 90
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
            TargetType = 'ComputerConfiguration'
            ValueName = 'WarningLevel'
        }
    }
    
    if ($ForceAuditPolicySubcategorySettings) {
        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        }
    }
    
    if ($ShutdownIfUnableToLogAudits) {
        SecurityOption 'SecurityRegistry(INF): Audit_Shut_down_system_immediately_if_unable_to_log_security_audits'
        {
            Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'
            Name = 'Audit_Shut_down_system_immediately_if_unable_to_log_security_audits'
        }
    }
    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }

}

