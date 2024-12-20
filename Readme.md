# XOAPBSISiSyPHusDSC

This repository contains the **XOAPBSISiSyPHusDSC** DSC module.

## Code of Conduct

This project has adopted this [Code of Conduct](CODE_OF_CONDUCT.md).

## Contributing

Please check out common DSC Community [contributing guidelines](https://dsccommunity.org/guidelines/contributing).

## Change log

A full list of changes in each version can be found in the  [Releases](https://github.com/xoap-io/XOAPSTIGAugust2023DSC/releases).

## Prerequisites

Be sure that the following DSC modules are installed on your system:

- GPRegistryPolicyDsc (1.2.0)
- AuditPolicyDSC (1.4.0.0)
- SecurityPolicyDSC (2.10.0.0)

## Documentation

The XOAP BSI SiSyPHus DSC contains the following resources:

- Hoher_Schutzbedarf_Domanenmitglied_HD_-Computer
- Normaler_Schutzbedarf_Domanenmitglied_ND-Computer
- Normaler_Schutzbedarf_Einzelrechner_NE-Computer
- Protokollierung_ND-NE-HD-Computer


## Configuration example

To implement the XOAP BSI SiSyPHus DSC module, add the following resources to your DSC configuration and adjust accordingly:

### Protokollierung_ND-NE-HD-Computer

```PowerShell
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
