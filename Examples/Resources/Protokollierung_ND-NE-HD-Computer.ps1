Configuration 'XOAPBSISiSyPHusDSC'
{
    Import-DSCResource -Module 'XOAPBSISiSyPHusDSC' -Name 'Protokollierung_ND-NE-HD-Computer' -ModuleVersion '0.0.1'

    param
        (
        )

    Node 'XOAPBSISiSyPHusDSC'
    {
        Protokollierung_ND-NE-HD-Computer 'Example'
        {
            ProcessCreationIncludeCmdLineEnabled = $true,
            MaxSizeApplicationLog = $true,
            RetentionApplicationLog = $true,
            RetentionSecurityLog = $true,
            MaxSizeSecurityLog = $true,
            MaxSizeSetupLog = $true,
            RetentionSetupLog = $true,
            MaxSizeSystemLog = $true,
            RetentionSystemLog = $true,
            EnableModuleLogging = $true,
            ModuleNames = $true,
            EnableScriptBlockLogging = $true,
            EnableScriptBlockInvocationLogging_Delete = $true,
            EnableTranscripting = $true,
            OutputDirectory = $true,
            EnableInvocationHeader = $true,
            PolicyVersion = $true,
            LogFilePath = $true,
            LogFileSizeDomainProfile = $true,
            LogDroppedPacketsDomainProfile = $true,
            LogSuccessfulConnectionsDomainProfile = $true,
            LogFilePathPrivateProfile = $true,
            LogFileSizePrivateProfile = $true,
            LogDroppedPacketsPrivateProfile = $true,
            LogSuccessfulConnectionsPrivateProfile = $true,
            LogFilePathPublicProfile = $true,
            LogFileSizePublicProfile = $true,
            LogDroppedPacketsPublicProfile = $true,
            LogSuccessfulConnections = $true,
            WarningLevel = $true,
            ForceAuditPolicySubcategorySettings = $true,
            ShutdownIfUnableToLogAudits = $true
        }

    }
}
XOAPBSISiSyPHusDSC -OutputPath 'C:\XOAPBSISiSyPHusDSC'
