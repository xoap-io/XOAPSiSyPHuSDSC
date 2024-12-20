configuration Hoher_Schutzbedarf_Domanenmitglied_HD_-Computer
{
    param(
        [bool]$NoOnlinePrintsWizard = $true,
        [bool]$NoPublishingWizard = $true,
        [bool]$AllowOnlineTips = $true,
        [bool]$BlockHostedAppAccessWinRT = $true,
        [bool]$DevicePKInitEnabled = $true,
        [bool]$DevicePKInitBehavior = $true,
        [bool]$AllowCamera = $true,
        [bool]$BlockUserInputMethodsForSignIn = $true,
        [bool]$NtpServerEnabled = $true,
        [bool]$DisabledByGroupPolicy = $true,
        [bool]$AllowSharedLocalAppData = $true,
        [bool]$NoCloudApplicationNotification = $true,
        [bool]$DisableEnterpriseAuthProxy = $true,
        [bool]$NoUseStoreOpenWith = $true,
        [bool]$PreventHandwritingErrorReports = $true,
        [bool]$SafeForScripting = $true,
        [bool]$ExitOnMSICW = $true,
        [bool]$EnableLLTDIO = $true,
        [bool]$AllowLLTDIOOnDomain = $true,
        [bool]$AllowLLTDIOOnPublicNet = $true,
        [bool]$ProhibitLLTDIOOnPrivateNet = $true,
        [bool]$EnableRspndr = $true,
        [bool]$AllowRspndrOnDomain = $true,
        [bool]$AllowRspndrOnPublicNet = $true,
        [bool]$ProhibitRspndrOnPrivateNet = $true,
        [bool]$DisableLocation = $true,
        [bool]$AllowMessageSync = $true,
        [bool]$EnableScripts = $true,
        [bool]$ExecutionPolicy = $true,
        [bool]$NoRegistration = $true,
        [bool]$DisableQueryRemoteServer = $true,
        [bool]$EnableFontProviders = $true,
        [bool]$UploadUserActivities = $true,
        [bool]$AllowCrossDeviceClipboard = $true,
        [bool]$PreventHandwritingDataSharing = $true,
        [bool]$EnableRegistrars = $true,
        [bool]$DisableUPnPRegistrar = $true,
        [bool]$DisableInBand802DOT11Registrar = $true,
        [bool]$DisableFlashConfigRegistrar = $true,
        [bool]$DisableWPDRegistrar = $true,
        [bool]$MaxWCNDeviceNumberRemoved = $true,
        [bool]$HigherPrecedenceRegistrarRemoved = $true,
        [bool]$DisableWcnUi = $true,
        [bool]$ScenarioExecutionEnabled = $true,
        [bool]$WindowsErrorReportingDisabled = $true,
        [bool]$AllowCloudSearch = $true,
        [bool]$AllowAutoConfig = $true,
        [bool]$IPv4FilterRemoved = $true,
        [bool]$IPv6FilterRemoved = $true,
        [bool]$AllowRemoteShellAccess = $true,
        [bool]$SpynetReportingRemoved = $true,
        [bool]$NoGenTicket = $true,
        [bool]$DisableHTTPPrinting = $true,
        [bool]$fDisableCcm = $true,
        [bool]$fDisableLPT = $true,
        [bool]$fDisablePNPRedir = $true,
        [bool]$MaxIdleTime = $true,
        [bool]$MaxDisconnectionTime = $true,
        [bool]$fDenyTSConnections = $true,
        [bool]$AllowSuggestedAppsInWindowsInkWorkspace = $true,
        [bool]$RequirePrivateStoreOnly = $true,
        [bool]$RemoveWindowsStore = $true,
        [bool]$DisableStoreApps = $true,
        [bool]$DisableSavePassword = $true,
        [bool]$KeepAliveTime = $true,
        [bool]$PerformRouterDiscovery = $true,
        [bool]$TcpMaxDataRetransmissions = $true,
        [bool]$Tcp6MaxDataRetransmissions = $true,
        [bool]$RestrictNTLMOutgoingTraffic = $true,
        [bool]$OptionalSubsystems = $true,
        [bool]$ForceStrongKeyProtection = $true,
        [bool]$PreventPrinterDriverInstallation = $true,
        [bool]$CachePreviousLogons = $true,
        [bool]$RestrictNTLMIncomingTraffic = $true
    )


    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($NoOnlinePrintsWizard) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoOnlinePrintsWizard'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoOnlinePrintsWizard'
            ValueData = 1
        }
    }
    
    if ($NoPublishingWizard) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPublishingWizard'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoPublishingWizard'
            ValueData = 1
        }
    }
    
    if ($AllowOnlineTips) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\AllowOnlineTips'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            ValueName = 'AllowOnlineTips'
            ValueData = 0
        }
    }
    
    if ($BlockHostedAppAccessWinRT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\BlockHostedAppAccessWinRT'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            ValueName = 'BlockHostedAppAccessWinRT'
            ValueData = 1
        }
    }
    if ($DevicePKInitEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            ValueType = 'Dword'
            ValueName = 'DevicePKInitEnabled'
            ValueData = 1
        }
    }
    
    if ($DevicePKInitBehavior) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitBehavior'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            ValueType = 'Dword'
            ValueName = 'DevicePKInitBehavior'
            ValueData = 0
        }
    }
    
    if ($AllowCamera) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Camera\AllowCamera'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Camera'
            ValueType = 'Dword'
            ValueName = 'AllowCamera'
            ValueData = 0
        }
    }
    
    if ($BlockUserInputMethodsForSignIn) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Control Panel\International'
            ValueType = 'Dword'
            ValueName = 'BlockUserInputMethodsForSignIn'
            ValueData = 1
        }
    }
    if ($NtpServerEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\W32time\TimeProviders\NtpServer\Enabled'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\W32time\TimeProviders\NtpServer'
            ValueType = 'Dword'
            ValueName = 'Enabled'
            ValueData = 0
        }
    }
    
    if ($DisabledByGroupPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AdvertisingInfo\DisabledByGroupPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\AdvertisingInfo'
            ValueType = 'Dword'
            ValueName = 'DisabledByGroupPolicy'
            ValueData = 1
        }
    }
    
    if ($AllowSharedLocalAppData) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\AllowSharedLocalAppData'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager'
            ValueType = 'Dword'
            ValueName = 'AllowSharedLocalAppData'
            ValueData = 0
        }
    }
    
    if ($NoCloudApplicationNotification) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoCloudApplicationNotification'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\CurrentVersion\PushNotifications'
            ValueType = 'Dword'
            ValueName = 'NoCloudApplicationNotification'
            ValueData = 1
        }
    }
    
    if ($DisableEnterpriseAuthProxy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DataCollection\DisableEnterpriseAuthProxy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\DataCollection'
            ValueType = 'Dword'
            ValueName = 'DisableEnterpriseAuthProxy'
            ValueData = 1
        }
    }
    
    if ($NoUseStoreOpenWith) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoUseStoreOpenWith'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoUseStoreOpenWith'
            ValueData = 1
        }
    }
    if ($PreventHandwritingErrorReports) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\HandwritingErrorReports'
            ValueType = 'Dword'
            ValueName = 'PreventHandwritingErrorReports'
            ValueData = 1
        }
    }
    
    if ($SafeForScripting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\SafeForScripting'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            ValueName = 'SafeForScripting'
            ValueData = 0
        }
    }
    
    if ($ExitOnMSICW) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Internet Connection Wizard\ExitOnMSICW'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\Internet Connection Wizard'
            ValueType = 'Dword'
            ValueName = 'ExitOnMSICW'
            ValueData = 1
        }
    }
    
    if ($EnableLLTDIO) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableLLTDIO'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            ValueName = 'EnableLLTDIO'
            ValueData = 0
        }
    }
    
    if ($AllowLLTDIOOnDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            ValueName = 'AllowLLTDIOOnDomain'
            ValueData = 0
        }
    }
    
    if ($AllowLLTDIOOnPublicNet) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            ValueName = 'AllowLLTDIOOnPublicNet'
            ValueData = 0
        }
    }
    
    if ($ProhibitLLTDIOOnPrivateNet) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            ValueName = 'ProhibitLLTDIOOnPrivateNet'
            ValueData = 0
        }
    }
    if ($EnableRspndr) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableRspndr'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            ValueName = 'EnableRspndr'
            ValueData = 0
        }
    }
    
    if ($AllowRspndrOnDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            ValueName = 'AllowRspndrOnDomain'
            ValueData = 0
        }
    }
    
    if ($AllowRspndrOnPublicNet) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            ValueName = 'AllowRspndrOnPublicNet'
            ValueData = 0
        }
    }
    
    if ($ProhibitRspndrOnPrivateNet) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            ValueName = 'ProhibitRspndrOnPrivateNet'
            ValueData = 0
        }
    }
    
    if ($DisableLocation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LocationAndSensors\DisableLocation'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\LocationAndSensors'
            ValueType = 'Dword'
            ValueName = 'DisableLocation'
            ValueData = 1
        }
    }
    
    if ($AllowMessageSync) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Messaging\AllowMessageSync'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\Messaging'
            ValueType = 'Dword'
            ValueName = 'AllowMessageSync'
            ValueData = 0
        }
    }
    
    if ($EnableScripts) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\PowerShell\EnableScripts'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\PowerShell'
            ValueType = 'Dword'
            ValueName = 'EnableScripts'
            ValueData = 1
        }
    }
    if ($ExecutionPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\PowerShell\ExecutionPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\PowerShell'
            ValueType = 'String'
            ValueName = 'ExecutionPolicy'
            ValueData = 'AllSigned'
        }
    }
    
    if ($NoRegistration) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Registration Wizard Control\NoRegistration'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\Registration Wizard Control'
            ValueType = 'Dword'
            ValueName = 'NoRegistration'
            ValueData = 1
        }
    }
    
    if ($DisableQueryRemoteServer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
            ValueType = 'Dword'
            ValueName = 'DisableQueryRemoteServer'
            ValueData = 0
        }
    }
    
    if ($EnableFontProviders) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnableFontProviders'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'EnableFontProviders'
            ValueData = 0
        }
    }
    
    if ($UploadUserActivities) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\UploadUserActivities'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'UploadUserActivities'
            ValueData = 0
        }
    }
    
    if ($AllowCrossDeviceClipboard) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\AllowCrossDeviceClipboard'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'AllowCrossDeviceClipboard'
            ValueData = 0
        }
    }
    
    if ($PreventHandwritingDataSharing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\TabletPC'
            ValueType = 'Dword'
            ValueName = 'PreventHandwritingDataSharing'
            ValueData = 1
        }
    }
    
    if ($EnableRegistrars) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'Dword'
            ValueName = 'EnableRegistrars'
            ValueData = 0
        }
    }
    
    if ($DisableUPnPRegistrar) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'Dword'
            ValueName = 'DisableUPnPRegistrar'
            ValueData = 0
        }
    }
    if ($DisableInBand802DOT11Registrar) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'Dword'
            ValueName = 'DisableInBand802DOT11Registrar'
            ValueData = 0
        }
    }
    
    if ($DisableFlashConfigRegistrar) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'Dword'
            ValueName = 'DisableFlashConfigRegistrar'
            ValueData = 0
        }
    }
    
    if ($DisableWPDRegistrar) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'Dword'
            ValueName = 'DisableWPDRegistrar'
            ValueData = 0
        }
    }
    
    if ($MaxWCNDeviceNumberRemoved) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\MaxWCNDeviceNumber'
        {
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'String'
            ValueName = 'MaxWCNDeviceNumber'
            ValueData = ''
        }
    }
    
    if ($HigherPrecedenceRegistrarRemoved) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\HigherPrecedenceRegistrar'
        {
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'String'
            ValueName = 'HigherPrecedenceRegistrar'
            ValueData = ''
        }
    }
    
    if ($DisableWcnUi) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\UI\DisableWcnUi'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\UI'
            ValueType = 'Dword'
            ValueName = 'DisableWcnUi'
            ValueData = 1
        }
    }
    
    if ($ScenarioExecutionEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'
            ValueType = 'Dword'
            ValueName = 'ScenarioExecutionEnabled'
            ValueData = 0
        }
    }
    if ($WindowsErrorReportingDisabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Windows Error Reporting\Disabled'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\Windows Error Reporting'
            ValueType = 'Dword'
            ValueName = 'Disabled'
            ValueData = 1
        }
    }
    
    if ($AllowCloudSearch) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Windows Search\AllowCloudSearch'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\Windows Search'
            ValueType = 'Dword'
            ValueName = 'AllowCloudSearch'
            ValueData = 0
        }
    }
    
    if ($AllowAutoConfig) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowAutoConfig'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            ValueName = 'AllowAutoConfig'
            ValueData = 0
        }
    }
    
    if ($IPv4FilterRemoved) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WinRM\Service\IPv4Filter'
        {
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'String'
            ValueName = 'IPv4Filter'
            ValueData = ''
        }
    }
    
    if ($IPv6FilterRemoved) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WinRM\Service\IPv6Filter'
        {
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'String'
            ValueName = 'IPv6Filter'
            ValueData = ''
        }
    }
    
    if ($AllowRemoteShellAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\WinRS\AllowRemoteShellAccess'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\WinRS'
            ValueType = 'Dword'
            ValueName = 'AllowRemoteShellAccess'
            ValueData = 0
        }
    }
    
    if ($SpynetReportingRemoved) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows Defender\Spynet\SpynetReporting'
        {
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows Defender\Spynet'
            ValueType = 'String'
            ValueName = 'SpynetReporting'
            ValueData = ''
        }
    }
    if ($NoGenTicket) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\NoGenTicket'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
            ValueType = 'Dword'
            ValueName = 'NoGenTicket'
            ValueData = 1
        }
    }
    
    if ($DisableHTTPPrinting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Printers'
            ValueType = 'Dword'
            ValueName = 'DisableHTTPPrinting'
            ValueData = 1
        }
    }
    
    if ($fDisableCcm) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCcm'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fDisableCcm'
            ValueData = 1
        }
    }
    
    if ($fDisableLPT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableLPT'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fDisableLPT'
            ValueData = 1
        }
    }
    
    if ($fDisablePNPRedir) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fDisablePNPRedir'
            ValueData = 1
        }
    }
    
    if ($MaxIdleTime) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'MaxIdleTime'
            ValueData = 900000
        }
    }
    
    if ($MaxDisconnectionTime) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\MaxDisconnectionTime'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'MaxDisconnectionTime'
            ValueData = 60000
        }
    }
    
    if ($fDenyTSConnections) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDenyTSConnections'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fDenyTSConnections'
            ValueData = 1
        }
    }
    
    if ($AllowSuggestedAppsInWindowsInkWorkspace) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsInkWorkspace\AllowSuggestedAppsInWindowsInkWorkspace'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\WindowsInkWorkspace'
            ValueType = 'Dword'
            ValueName = 'AllowSuggestedAppsInWindowsInkWorkspace'
            ValueData = 0
        }
    }

    if ($RequirePrivateStoreOnly) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsStore\RequirePrivateStoreOnly'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\WindowsStore'
            ValueType = 'Dword'
            ValueName = 'RequirePrivateStoreOnly'
            ValueData = 1
        }
    }
    
    if ($RemoveWindowsStore) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsStore\RemoveWindowsStore'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\WindowsStore'
            ValueType = 'Dword'
            ValueName = 'RemoveWindowsStore'
            ValueData = 1
        }
    }
    
    if ($DisableStoreApps) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsStore\DisableStoreApps'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\policies\Microsoft\WindowsStore'
            ValueType = 'Dword'
            ValueName = 'DisableStoreApps'
            ValueData = 1
        }
    }
    
    if ($DisableSavePassword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\DisableSavePassword'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters'
            ValueType = 'Dword'
            ValueName = 'DisableSavePassword'
            ValueData = 1
        }
    }
    
    if ($KeepAliveTime) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            ValueName = 'KeepAliveTime'
            ValueData = 300000
        }
    }
    
    if ($PerformRouterDiscovery) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            ValueName = 'PerformRouterDiscovery'
            ValueData = 0
        }
    }
    
    if ($TcpMaxDataRetransmissions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            ValueName = 'TcpMaxDataRetransmissions'
            ValueData = 3
        }
    }
    
    if ($Tcp6MaxDataRetransmissions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetransmissions'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueType = 'Dword'
            ValueName = 'TcpMaxDataRetransmissions'
            ValueData = 3
        }
    }
    if ($RestrictNTLMOutgoingTraffic) {
        SecurityOption 'SecurityRegistry(INF): Network_Security_Restrict_NTLM_Outgoing_NTLM_traffic_to_remote_servers'
        {
            Network_Security_Restrict_NTLM_Outgoing_NTLM_traffic_to_remote_servers = 'Deny all'
            Name = 'Network_Security_Restrict_NTLM_Outgoing_NTLM_traffic_to_remote_servers'
        }
    }
    
    if ($OptionalSubsystems) {
        SecurityOption 'SecurityRegistry(INF): System_settings_Optional_subsystems'
        {
            System_settings_Optional_subsystems = 'String'
            Name = 'System_settings_Optional_subsystems'
        }
    }
    
    if ($ForceStrongKeyProtection) {
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        {
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User is prompted when the key is first used'
            Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        }
    }
    
    if ($PreventPrinterDriverInstallation) {
        SecurityOption 'SecurityRegistry(INF): Devices_Prevent_users_from_installing_printer_drivers'
        {
            Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'
            Name = 'Devices_Prevent_users_from_installing_printer_drivers'
        }
    }
    
    if ($CachePreviousLogons) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        }
    }
    
    if ($RestrictNTLMIncomingTraffic) {
        SecurityOption 'SecurityRegistry(INF): Network_Security_Restrict_NTLM_Incoming_NTLM_Traffic'
        {
            Name = 'Network_Security_Restrict_NTLM_Incoming_NTLM_Traffic'
            Network_Security_Restrict_NTLM_Incoming_NTLM_Traffic = 'Deny all accounts'
        }
    }

    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

