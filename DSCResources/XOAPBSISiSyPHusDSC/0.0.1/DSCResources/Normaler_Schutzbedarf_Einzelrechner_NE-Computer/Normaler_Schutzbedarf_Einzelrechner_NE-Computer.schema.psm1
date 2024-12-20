configuration Normaler_Schutzbedarf_Einzelrechner_NE-Computer
{
    param(
        [bool]$AutoConnectAllowedOEM = $true,
        [bool]$EnumerateAdministrators = $true,
        [bool]$NoWebServices = $true,
        [bool]$PreXPSP2ShellProtocolBehavior = $true,
        [bool]$NoDriveTypeAutoRun = $true,
        [bool]$NoAutorun = $true,
        [bool]$LocalAccountTokenFilterPolicy = $true,
        [bool]$MSAOptional = $true,
        [bool]$DisableAutomaticRestartSignOn = $true,
        [bool]$AllowEncryptionOracle = $true,
        [bool]$AllowLinguisticDataCollection = $true,
        [bool]$AutoAdminLogon = $true,
        [bool]$ScreenSaverGracePeriod = $true,
        [bool]$EnhancedAntiSpoofing = $true,
        [bool]$RestrictImplicitTextCollection = $true,
        [bool]$RestrictImplicitInkCollection = $true,
        [bool]$AllowInputPersonalization = $true,
        [bool]$DisableEnclosureDownload = $true,
        [bool]$DisableUserAuth = $true,
        [bool]$PreventOverride = $true,
        [bool]$EnabledV9 = $true,
        [bool]$DCSettingIndex = $true,
        [bool]$ACSettingIndex_0e796bdb = $true,
        [bool]$DCSettingIndex_abfc2519 = $true,
        [bool]$ACSettingIndex_abfc2519 = $true,
        [bool]$DCSettingIndex_f15576e8 = $true,
        [bool]$ACSettingIndex_f15576e8 = $true,
        [bool]$StandardUserAuthorizationFailureDuration = $true,
        [bool]$StandardUserAuthorizationFailureTotalThreshold = $true,
        [bool]$IgnoreDefaultList = $true,
        [bool]$DisableWindowsConsumerFeatures = $true,
        [bool]$RequirePinForPairing = $true,
        [bool]$DisablePasswordReveal = $true,
        [bool]$DoNotShowFeedbackNotifications = $true,
        [bool]$AllowTelemetry = $true,
        [bool]$AllowDeviceNameInTelemetry = $true,
        [bool]$DODownloadMode = $true,
        [bool]$DenyDeviceIDs = $true,
        [bool]$DenyDeviceIDsRetroactive = $true,
        [bool]$DenyDeviceClasses = $true,
        [bool]$DenyDeviceClassesRetroactive = $true,
        [bool]$DenyDeviceClass1 = $true,
        [bool]$DenyDeviceClass2 = $true,
        [bool]$DenyDeviceClass3 = $true,
        [bool]$DenyDeviceClass4 = $true,
        [bool]$DenyDeviceID1 = $true,
        [bool]$NoDataExecutionPrevention = $true,
        [bool]$NoHeapTerminationOnCorruption = $true,
        [bool]$NoAutoplayfornonVolume = $true,
        [bool]$AllowGameDVR = $true,
        [bool]$EnableUserControl = $true,
        [bool]$AlwaysInstallElevated = $true,
        [bool]$DeviceEnumerationPolicy = $true,
        [bool]$AllowInsecureGuestAuth = $true,
        [bool]$NC_AllowNetBridge_NLA = $true,
        [bool]$NC_ShowSharedAccessUI = $true,
        [bool]$DisableFileSyncNGSC = $true,
        [bool]$NoLockScreenSlideshow = $true,
        [bool]$NoLockScreenCamera = $true,
        [bool]$EnableScripts = $true,
        [bool]$ExecutionPolicy = $true,
        [bool]$AllowBuildPreview = $true,
        [bool]$BlockDomainPicturePassword = $true,
        [bool]$DisableLockScreenAppNotifications = $true,
        [bool]$BlockUserFromShowingAccountDetailsOnSignin = $true,
        [bool]$DontDisplayNetworkSelectionUI = $true,
        [bool]$EnableCdp = $true,
        [bool]$EnableSmartScreen = $true,
        [bool]$ShellSmartScreenLevel = $true,
        [bool]$fMinimizeConnections = $true,
        [bool]$fBlockNonDomain = $true,
        [bool]$AllowSearchToUseLocation = $true,
        [bool]$AllowIndexingEncryptedStoresOrItems = $true,
        [bool]$SetDisablePauseUXAccess = $true,
        [bool]$NoAutoUpdate = $true,
        [bool]$AUOptions = $true,
        [bool]$AutomaticMaintenanceEnabled_Delete = $true,
        [bool]$ScheduledInstallDay = $true,
        [bool]$ScheduledInstallTime = $true,
        [bool]$ScheduledInstallEveryWeek = $true,
        [bool]$ScheduledInstallFirstWeek_Delete = $true,
        [bool]$ScheduledInstallSecondWeek_Delete = $true,
        [bool]$ScheduledInstallThirdWeek_Delete = $true,
        [bool]$ScheduledInstallFourthWeek_Delete = $true,
        [bool]$AllowMUUpdateService_Delete = $true,
        [bool]$NoAutoRebootWithLoggedOnUsers = $true,
        [bool]$AllowBasic = $true,
        [bool]$AllowDigest = $true,
        [bool]$AllowUnencryptedTraffic_Client = $true,
        [bool]$AllowBasic_Service = $true,
        [bool]$DisableRunAs = $true,
        [bool]$AllowUnencryptedTraffic_Service = $true,
        [bool]$PUAProtection = $true,
        [bool]$DisableAntiSpyware = $true,
        [bool]$DisableBehaviorMonitoring = $true,
        [bool]$DisableGenericReports = $true,
        [bool]$DisableEmailScanning = $true,
        [bool]$DisableRemovableDriveScanning = $true,
        [bool]$LocalSettingOverrideSpynetReporting = $true,
        [bool]$ExploitGuard_ASR_Rules = $true,
        [bool]$Rule_26190899 = $true,
        [bool]$Rule_3b576869 = $true,
        [bool]$Rule_5beb7efe = $true,
        [bool]$Rule_75668c1f = $true,
        [bool]$Rule_7674ba52 = $true,
        [bool]$Rule_92e97fa1 = $true,
        [bool]$Rule_9e6c4e1f = $true,
        [bool]$Rule_b2b3f03d = $true,
        [bool]$Rule_be9ba2d9 = $true,
        [bool]$Rule_d3e037e1 = $true,
        [bool]$Rule_d4f940ab = $true,
        [bool]$EnableNetworkProtection = $true,
        [bool]$DisallowExploitProtectionOverride = $true,
        [bool]$EnableMulticast = $true,
        [bool]$DisableWebPnPDownload = $true,
        [bool]$RestrictRemoteClients = $true,
        [bool]$EnableAuthEpResolution = $true,
        [bool]$fAllowToGetHelp = $true,
        [bool]$fAllowFullControl_Delete = $true,
        [bool]$MaxTicketExpiry_Delete = $true,
        [bool]$MaxTicketExpiryUnits_Delete = $true,
        [bool]$fUseMailto_Delete = $true,
        [bool]$fAllowUnsolicited = $true,
        [bool]$fAllowUnsolicitedFullControl_Delete = $true,
        [bool]$fDisableCdm = $true,
        [bool]$fPromptForPassword = $true,
        [bool]$UserAuthentication = $true,
        [bool]$fEncryptRPCTraffic = $true,
        [bool]$MinEncryptionLevel = $true,
        [bool]$SecurityLayer = $true,
        [bool]$fResetBroken = $true,
        [bool]$PerSessionTempDir = $true,
        [bool]$DeleteTempDirsOnExit = $true,
        [bool]$DisablePasswordSaving = $true,
        [bool]$PolicyVersion = $true,
        [bool]$DomainProfile_NullValue = $true,
        [bool]$DisableNotifications = $true,
        [bool]$EnableFirewall = $true,
        [bool]$DefaultOutboundAction = $true,
        [bool]$DefaultInboundAction = $true,
        [bool]$PublicProfile_DefaultOutboundAction = $true,
        [bool]$PublicProfile_DisableNotifications = $true,
        [bool]$PublicProfile_AllowLocalPolicyMerge = $true,
        [bool]$PublicProfile_AllowLocalIPsecPolicyMerge = $true,
        [bool]$AllowSuggestedAppsInWindowsInkWorkspace = $true,
        [bool]$AllowWindowsInkWorkspace = $true,
        [bool]$AutoDownload = $true,
        [bool]$DisableOSUpgrade = $true,
        [bool]$RunAsPPL = $true,
        [bool]$UseLogonCredential = $true,
        [bool]$SafeDllSearchMode = $true,
        [bool]$DisableExceptionChainValidation = $true,
        [bool]$DriverLoadPolicy = $true,
        [bool]$SMB1 = $true,
        [bool]$MRxSmb10_Start = $true,
        [bool]$NoNameReleaseOnDemand = $true,
        [bool]$NodeType = $true,
        [bool]$EnableDeadGWDetect = $true,
        [bool]$DisableIPSourceRouting_TCPIP = $true,
        [bool]$EnableICMPRedirect = $true,
        [bool]$DisableIPSourceRouting_TCPIP6 = $true,
        [bool]$MinimumPasswordLength = $true,
        [bool]$EnableGuestAccount = $true,
        [bool]$MinimumPasswordAge = $true,
        [bool]$PasswordHistorySize = $true,
        [bool]$PasswordComplexity = $true,
        [bool]$MaximumPasswordAge = $true,
        [bool]$LSAAnonymousNameLookup = $true,
        [bool]$ClearTextPassword = $true,
        [bool]$EnableAdminAccount = $true,
        [bool]$RemotelyAccessibleRegistryPaths = $true,
        [bool]$DigitallySignCommunications = $true,
        [bool]$DoNotStoreLanManagerHash = $true,
        [bool]$AdminApprovalModeForBuiltInAdmin = $true,
        [bool]$RequireCaseInsensitivityForNonWindowsSubsystems = $true,
        [bool]$StrengthenDefaultPermissionsOfInternalSystemObjects = $true,
        [bool]$VirtualizeFileAndRegistryWriteFailures = $true,
        [bool]$NamedPipesAccessiblyAnonymously = $true,
        [bool]$AllowPKU2UAuthenticationRequests = $true,
        [bool]$OnlyElevateUIAccessInSecureLocations = $true,
        [bool]$SharingAndSecurityModelForLocalAccounts = $true,
        [bool]$ElevationPromptBehavior = $true,
        [bool]$RestrictAnonymousAccessToNamedPipesAndShares = $true,
        [bool]$MinimumSessionSecurityForNTLM = $true,
        [bool]$LANManagerAuthenticationLevel = $true,
        [bool]$PromptUserToChangePasswordBeforeExpiration = $true,
        [bool]$DigitallySignCommunicationsAlways = $true,
        [bool]$BlockMicrosoftAccounts = $true,
        [bool]$InteractiveLogonDoNotDisplayLastUserName = $true,
        [bool]$AllowLocalSystemForNTLM = $true,
        [bool]$EveryonePermissionsForAnonymousUsers = $true,
        [bool]$DisconnectClientsWhenLogonHoursExpire = $true,
        [bool]$DoNotAllowAnonymousEnumerationOfSAMAccounts = $true,
        [bool]$DoNotAllowStorageOfPasswords = $true,
        [bool]$IdleTimeBeforeSuspendingSession = $true,
        [bool]$AllowFormatAndEjectRemovableMedia = $true,
        [bool]$AllowUIAccessPromptsWithoutSecureDesktop = $true,
        [bool]$DetectApplicationInstallationsAndPromptForElevation = $true,
        [bool]$DigitallySignCommunicationsIfServerAgrees = $true,
        [bool]$DoNotRequireCtrlAltDel = $true,
        [bool]$RunAllAdministratorsInAdminApprovalMode = $true,
        [bool]$SendUnencryptedPasswordToSmbServers = $true,
        [bool]$LdapClientSigningRequirements = $true,
        [bool]$RestrictClientsMakingRemoteCallsToSAM = $true,
        [bool]$LimitLocalAccountUseOfBlankPasswords = $true,
        [bool]$SharesAccessibleAnonymously = $true,
        [bool]$MachineInactivityLimit = $true,
        [bool]$ElevationPromptForStandardUsers = $true,
        [bool]$EncryptionTypesAllowedForKerberos = $true,
        [bool]$AllowLocalSystemNullSessionFallback = $true,
        [bool]$SwitchToSecureDesktopWhenPrompting = $true
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($AutoConnectAllowedOEM) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config\AutoConnectAllowedOEM'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutoConnectAllowedOEM'
        }
    }
    
    if ($EnumerateAdministrators) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnumerateAdministrators'
        }
    }
    
    if ($NoWebServices) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoWebServices'
        }
    }
    
    if ($PreXPSP2ShellProtocolBehavior) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreXPSP2ShellProtocolBehavior'
        }
    }
    
    if ($NoDriveTypeAutoRun) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
            ValueType = 'Dword'
            ValueData = 255
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoDriveTypeAutoRun'
        }
    }
    
    if ($NoAutorun) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoAutorun'
        }
    }
    
    if ($LocalAccountTokenFilterPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LocalAccountTokenFilterPolicy'
        }
    }

    if ($MSAOptional) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MSAOptional'
        }
    }
    
    if ($DisableAutomaticRestartSignOn) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableAutomaticRestartSignOn'
        }
    }
    
    if ($AllowEncryptionOracle) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\AllowEncryptionOracle'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowEncryptionOracle'
        }
    }
    
    if ($AllowLinguisticDataCollection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput\AllowLinguisticDataCollection'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowLinguisticDataCollection'
        }
    }
    
    if ($AutoAdminLogon) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon'
        {
            ValueType = 'String'
            ValueData = '0'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutoAdminLogon'
        }
    }
    
    if ($ScreenSaverGracePeriod) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod'
        {
            ValueType = 'String'
            ValueData = '5'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ScreenSaverGracePeriod'
        }
    }
    
    if ($EnhancedAntiSpoofing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnhancedAntiSpoofing'
        }
    }
    
    if ($RestrictImplicitTextCollection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization\RestrictImplicitTextCollection'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RestrictImplicitTextCollection'
        }
    }
    if ($RestrictImplicitInkCollection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization\RestrictImplicitInkCollection'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RestrictImplicitInkCollection'
        }
    }
    
    if ($AllowInputPersonalization) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowInputPersonalization'
        }
    }
    
    if ($DisableEnclosureDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableEnclosureDownload'
        }
    }
    
    if ($DisableUserAuth) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount\DisableUserAuth'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableUserAuth'
        }
    }
    
    if ($PreventOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverride'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreventOverride'
        }
    }
    
    if ($EnabledV9) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\EnabledV9'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnabledV9'
        }
    }
    
    if ($DCSettingIndex) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DCSettingIndex'
        }
    }

    if ($ACSettingIndex_0e796bdb) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ACSettingIndex'
        }
    }
    
    if ($DCSettingIndex_abfc2519) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\DCSettingIndex'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DCSettingIndex'
        }
    }
    
    if ($ACSettingIndex_abfc2519) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\ACSettingIndex'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ACSettingIndex'
        }
    }
    
    if ($DCSettingIndex_f15576e8) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\DCSettingIndex'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DCSettingIndex'
        }
    }
    
    if ($ACSettingIndex_f15576e8) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ACSettingIndex'
        }
    }

    if ($StandardUserAuthorizationFailureDuration) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\TPM\StandardUserAuthorizationFailureDuration'
        {
            ValueType = 'Dword'
            ValueData = 30
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\TPM'
            TargetType = 'ComputerConfiguration'
            ValueName = 'StandardUserAuthorizationFailureDuration'
        }
    }
    
    if ($StandardUserAuthorizationFailureTotalThreshold) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\TPM\StandardUserAuthorizationFailureTotalThreshold'
        {
            ValueType = 'Dword'
            ValueData = 5
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\TPM'
            TargetType = 'ComputerConfiguration'
            ValueName = 'StandardUserAuthorizationFailureTotalThreshold'
        }
    }
    
    if ($IgnoreDefaultList) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\TPM\BlockedCommands\IgnoreDefaultList'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\TPM\BlockedCommands'
            TargetType = 'ComputerConfiguration'
            ValueName = 'IgnoreDefaultList'
        }
    }
    
    if ($DisableWindowsConsumerFeatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableWindowsConsumerFeatures'
        }
    }
    
    if ($RequirePinForPairing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect\RequirePinForPairing'
        {
            ValueType = 'Dword'
            ValueData = 2
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RequirePinForPairing'
        }
    }
    
    if ($DisablePasswordReveal) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisablePasswordReveal'
        }
    }

    if ($DoNotShowFeedbackNotifications) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DoNotShowFeedbackNotifications'
        }
    }
    
    if ($AllowTelemetry) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowTelemetry'
        }
    }
    
    if ($AllowDeviceNameInTelemetry) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowDeviceNameInTelemetry'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowDeviceNameInTelemetry'
        }
    }
    
    if ($DODownloadMode) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
        {
            ValueType = 'Dword'
            ValueData = 99
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DODownloadMode'
        }
    }
    
    if ($DenyDeviceIDs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DenyDeviceIDs'
        }
    }
    
    if ($DenyDeviceIDsRetroactive) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDsRetroactive'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DenyDeviceIDsRetroactive'
        }
    }

    if ($DenyDeviceClasses) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DenyDeviceClasses'
        }
    }
    
    if ($DenyDeviceClassesRetroactive) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClassesRetroactive'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DenyDeviceClassesRetroactive'
        }
    }
    
    if ($DenyDeviceClass1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\1'
        {
            ValueType = 'String'
            ValueData = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
            TargetType = 'ComputerConfiguration'
            ValueName = '1'
        }
    }
    
    if ($DenyDeviceClass2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\2'
        {
            ValueType = 'String'
            ValueData = '{7ebefbc0-3200-11d2-b4c20-0a0C9697d07}'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
            TargetType = 'ComputerConfiguration'
            ValueName = '2'
        }
    }
    
    if ($DenyDeviceClass3) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\3'
        {
            ValueType = 'String'
            ValueData = '{c06ff265-ae09-48f0-812c-16753d7cba83}'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
            TargetType = 'ComputerConfiguration'
            ValueName = '3'
        }
    }
    
    if ($DenyDeviceClass4) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\4'
        {
            ValueType = 'String'
            ValueData = '{6bdd1fc1-810f-11d0-bec7-08002be2092f}'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
            TargetType = 'ComputerConfiguration'
            ValueName = '4'
        }
    }
    
    if ($DenyDeviceID1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs\1'
        {
            ValueType = 'String'
            ValueData = 'PCI\CC_0C0A'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs'
            TargetType = 'ComputerConfiguration'
            ValueName = '1'
        }
    }
    
    if ($NoDataExecutionPrevention) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
        {
             ValueType = 'Dword'
             ValueData = 0
             Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
             TargetType = 'ComputerConfiguration'
             ValueName = 'NoDataExecutionPrevention'
        }
    }
    if ($NoHeapTerminationOnCorruption) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
        {
             ValueType = 'Dword'
             ValueData = 0
             Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
             TargetType = 'ComputerConfiguration'
             ValueName = 'NoHeapTerminationOnCorruption'
        }
    }
    if ($NoAutoplayfornonVolume) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoAutoplayfornonVolume'
        }
    }
    
    if ($AllowGameDVR) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR\AllowGameDVR'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowGameDVR'
        }
    }
    
    if ($EnableUserControl) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableUserControl'
        }
    }
    
    if ($AlwaysInstallElevated) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AlwaysInstallElevated'
        }
    }
    
    if ($DeviceEnumerationPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DeviceEnumerationPolicy'
        }
    }
    if ($AllowInsecureGuestAuth) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowInsecureGuestAuth'
        }
    }
    
    if ($NC_AllowNetBridge_NLA) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NC_AllowNetBridge_NLA'
        }
    }
    
    if ($NC_ShowSharedAccessUI) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NC_ShowSharedAccessUI'
        }
    }
    
    if ($DisableFileSyncNGSC) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableFileSyncNGSC'
        }
    }
    
    if ($NoLockScreenSlideshow) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoLockScreenSlideshow'
        }
    }

    if ($NoLockScreenCamera) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoLockScreenCamera'
        }
    }
    
    if ($EnableScripts) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\EnableScripts'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableScripts'
        }
    }
    
    if ($ExecutionPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy'
        {
            ValueType = 'String'
            ValueData = 'RemoteSigned'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ExecutionPolicy'
        }
    }
    
    if ($AllowBuildPreview) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBuildPreview'
        }
    }
    
    if ($BlockDomainPicturePassword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\BlockDomainPicturePassword'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueName = 'BlockDomainPicturePassword'
        }
    }
    if ($DisableLockScreenAppNotifications) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableLockScreenAppNotifications'
        }
    }
    
    if ($BlockUserFromShowingAccountDetailsOnSignin) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueName = 'BlockUserFromShowingAccountDetailsOnSignin'
        }
    }
    
    if ($DontDisplayNetworkSelectionUI) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DontDisplayNetworkSelectionUI'
        }
    }
    
    if ($EnableCdp) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnableCdp'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableCdp'
        }
    }
    
    if ($EnableSmartScreen) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableSmartScreen'
        }
    }
    
    if ($ShellSmartScreenLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\ShellSmartScreenLevel'
        {
            ValueType = 'String'
            ValueData = 'Block'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ShellSmartScreenLevel'
        }
    }

    if ($fMinimizeConnections) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fMinimizeConnections'
        }
    }
    
    if ($fBlockNonDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fBlockNonDomain'
        }
    }
    
    if ($AllowSearchToUseLocation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowSearchToUseLocation'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowSearchToUseLocation'
        }
    }
    
    if ($AllowIndexingEncryptedStoresOrItems) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
        }
    }
    
    if ($SetDisablePauseUXAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\SetDisablePauseUXAccess'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SetDisablePauseUXAccess'
        }
    }
    
    if ($NoAutoUpdate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoAutoUpdate'
        }
    }
    
    if ($AUOptions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions'
        {
            ValueType = 'Dword'
            ValueData = 4
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AUOptions'
        }
    }
    if ($AutomaticMaintenanceEnabled_Delete) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AutomaticMaintenanceEnabled'
        {
            ValueType = 'String'
            ValueData = ''
            Ensure = 'Absent'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutomaticMaintenanceEnabled'
        }
    }
    
    if ($ScheduledInstallDay) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ScheduledInstallDay'
        }
    }
    
    if ($ScheduledInstallTime) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallTime'
        {
            ValueType = 'Dword'
            ValueData = 3
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ScheduledInstallTime'
        }
    }
    
    if ($ScheduledInstallEveryWeek) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallEveryWeek'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ScheduledInstallEveryWeek'
        }
    }
    
    if ($ScheduledInstallFirstWeek_Delete) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFirstWeek'
        {
            ValueType = 'String'
            ValueData = ''
            Ensure = 'Absent'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ScheduledInstallFirstWeek'
        }
    }
    
    if ($ScheduledInstallSecondWeek_Delete) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallSecondWeek'
        {
            ValueType = 'String'
            ValueData = ''
            Ensure = 'Absent'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ScheduledInstallSecondWeek'
        }
    }

    if ($ScheduledInstallThirdWeek_Delete) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallThirdWeek'
        {
            ValueType = 'String'
            ValueData = ''
            Ensure = 'Absent'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ScheduledInstallThirdWeek'
        }
    }
    
    if ($ScheduledInstallFourthWeek_Delete) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFourthWeek'
        {
            ValueType = 'String'
            ValueData = ''
            Ensure = 'Absent'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ScheduledInstallFourthWeek'
        }
    }
    
    if ($AllowMUUpdateService_Delete) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AllowMUUpdateService'
        {
            ValueType = 'String'
            ValueData = ''
            Ensure = 'Absent'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowMUUpdateService'
        }
    }
    
    if ($NoAutoRebootWithLoggedOnUsers) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoAutoRebootWithLoggedOnUsers'
        }
    }
    
    if ($AllowBasic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasic'
        }
    }
    
    if ($AllowDigest) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowDigest'
        }
    }
    if ($AllowUnencryptedTraffic_Client) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowUnencryptedTraffic'
        }
    }
    
    if ($AllowBasic_Service) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasic'
        }
    }
    
    if ($DisableRunAs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableRunAs'
        }
    }
    
    if ($AllowUnencryptedTraffic_Service) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowUnencryptedTraffic'
        }
    }
    
    if ($PUAProtection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\PUAProtection'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PUAProtection'
        }
    }
    
    if ($DisableAntiSpyware) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableAntiSpyware'
        }
    }
    if ($DisableBehaviorMonitoring) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableBehaviorMonitoring'
        }
    }
    
    if ($DisableGenericReports) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableGenericRePorts'
        }
    }
    
    if ($DisableEmailScanning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableEmailScanning'
        }
    }
    
    if ($DisableRemovableDriveScanning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableRemovableDriveScanning'
        }
    }
    
    if ($LocalSettingOverrideSpynetReporting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LocalSettingOverrideSpynetReporting'
        }
    }
    
    if ($ExploitGuard_ASR_Rules) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ExploitGuard_ASR_Rules'
        }
    }

    if ($Rule_26190899) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\26190899-1602-49e8-8b27-eb1d0a1ce869'
        {
            ValueType = 'String'
            ValueData = '1'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            TargetType = 'ComputerConfiguration'
            ValueName = '26190899-1602-49e8-8b27-eb1d0a1ce869'
        }
    }
    
    if ($Rule_3b576869) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\3b576869-a4ec-4529-8536-b80a7769e899'
        {
            ValueType = 'String'
            ValueData = '1'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            TargetType = 'ComputerConfiguration'
            ValueName = '3b576869-a4ec-4529-8536-b80a7769e899'
        }
    }
    
    if ($Rule_5beb7efe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\5beb7efe-fd9a-4556-801d-275e5ffc04cc'
        {
            ValueType = 'String'
            ValueData = '1'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            TargetType = 'ComputerConfiguration'
            ValueName = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
        }
    }
    
    if ($Rule_75668c1f) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
        {
            ValueType = 'String'
            ValueData = '1'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            TargetType = 'ComputerConfiguration'
            ValueName = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
        }
    }
    
    if ($Rule_7674ba52) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
        {
            ValueType = 'String'
            ValueData = '1'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            TargetType = 'ComputerConfiguration'
            ValueName = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
        }
    }
    
    if ($Rule_92e97fa1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
         {
              ValueType = 'String'
              ValueData = '1'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              TargetType = 'ComputerConfiguration'
              ValueName = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
         }
    }
    if ($Rule_9e6c4e1f) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
         {
              ValueType = 'String'
              ValueData = '1'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              TargetType = 'ComputerConfiguration'
              ValueName = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
         }
    }
    if ($Rule_b2b3f03d) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
        {
            ValueType = 'String'
            ValueData = '1'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            TargetType = 'ComputerConfiguration'
            ValueName = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
        }
    }
    
    if ($Rule_be9ba2d9) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
        {
            ValueType = 'String'
            ValueData = '1'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            TargetType = 'ComputerConfiguration'
            ValueName = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
        }
    }
    
    if ($Rule_d3e037e1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\d3e037e1-3eb8-44c8-a917-57927947596d'
        {
            ValueType = 'String'
            ValueData = '1'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            TargetType = 'ComputerConfiguration'
            ValueName = 'd3e037e1-3eb8-44c8-a917-57927947596d'
        }
    }
    
    if ($Rule_d4f940ab) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\d4f940ab-401b-4efc-aadc-ad5f3c50688a'
        {
            ValueType = 'String'
            ValueData = '1'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            TargetType = 'ComputerConfiguration'
            ValueName = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
        }
    }
    
    if ($EnableNetworkProtection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableNetworkProtection'
        }
    }
    
    if ($DisallowExploitProtectionOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\DisallowExploitProtectionOverride'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisallowExploitProtectionOverride'
        }
    }

    if ($EnableMulticast) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableMulticast'
        }
    }
    
    if ($DisableWebPnPDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableWebPnPDownload'
        }
    }
    
    if ($RestrictRemoteClients) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RestrictRemoteClients'
        }
    }
    
    if ($EnableAuthEpResolution) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableAuthEpResolution'
        }
    }
    
    if ($fAllowToGetHelp) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fAllowToGetHelp'
        }
    }
    if ($fAllowFullControl_Delete) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
        {
            ValueType = 'String'
            ValueData = ''
            Ensure = 'Absent'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fAllowFullControl'
        }
    }
    
    if ($MaxTicketExpiry_Delete) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
        {
            ValueType = 'String'
            ValueData = ''
            Ensure = 'Absent'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxTicketExpiry'
        }
    }
    
    if ($MaxTicketExpiryUnits_Delete) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
        {
            ValueType = 'String'
            ValueData = ''
            Ensure = 'Absent'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxTicketExpiryUnits'
        }
    }
    
    if ($fUseMailto_Delete) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
        {
            ValueType = 'String'
            ValueData = ''
            Ensure = 'Absent'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fUseMailto'
        }
    }
    if ($fAllowUnsolicited) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fAllowUnsolicited'
        }
    }
    
    if ($fAllowUnsolicitedFullControl_Delete) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicitedFullControl'
        {
            ValueType = 'String'
            ValueData = ''
            Ensure = 'Absent'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fAllowUnsolicitedFullControl'
        }
    }
    
    if ($fDisableCdm) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fDisableCdm'
        }
    }
    
    if ($fPromptForPassword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fPromptForPassword'
        }
    }
    
    if ($UserAuthentication) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UserAuthentication'
        }
    }
    
    if ($fEncryptRPCTraffic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fEncryptRPCTraffic'
        }
    }
    if ($MinEncryptionLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            ValueType = 'Dword'
            ValueData = 3
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MinEncryptionLevel'
        }
    }
    
    if ($SecurityLayer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\SecurityLayer'
        {
            ValueType = 'Dword'
            ValueData = 2
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SecurityLayer'
        }
    }
    
    if ($fResetBroken) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fResetBroken'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fResetBroken'
        }
    }
    
    if ($PerSessionTempDir) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PerSessionTempDir'
        }
    }
    
    if ($DeleteTempDirsOnExit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DeleteTempDirsOnExit'
        }
    }
    
    if ($DisablePasswordSaving) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisablePasswordSaving'
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
    
    if ($DomainProfile_NullValue) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
        }
    }
    
    if ($DisableNotifications) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableNotifications'
        }
    }
    
    if ($EnableFirewall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableFirewall'
        }
    }
    
    if ($DefaultOutboundAction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultOutboundAction'
        }
    }
    if ($DefaultInboundAction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultInboundAction'
        }
    }
    
    if ($PublicProfile_DefaultOutboundAction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultOutboundAction'
        }
    }
    
    if ($PublicProfile_DisableNotifications) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableNotifications'
        }
    }
    
    if ($PublicProfile_AllowLocalPolicyMerge) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowLocalPolicyMerge'
        }
    }
    
    if ($PublicProfile_AllowLocalIPsecPolicyMerge) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowLocalIPsecPolicyMerge'
        }
    }
    if ($EnableFirewall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableFirewall'
        }
    }
    
    if ($DefaultInboundAction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultInboundAction'
        }
    }
    
    if ($AllowSuggestedAppsInWindowsInkWorkspace) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowSuggestedAppsInWindowsInkWorkspace'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowSuggestedAppsInWindowsInkWorkspace'
        }
    }
    
    if ($AllowWindowsInkWorkspace) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowWindowsInkWorkspace'
        }
    }
    
    if ($AutoDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\AutoDownload'
        {
            ValueType = 'Dword'
            ValueData = 4
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutoDownload'
        }
    }
    if ($DisableOSUpgrade) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\DisableOSUpgrade'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableOSUpgrade'
        }
    }
    
    if ($RunAsPPL) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RunAsPPL'
        }
    }
    
    if ($UseLogonCredential) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseLogonCredential'
        }
    }
    
    if ($SafeDllSearchMode) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SafeDllSearchMode'
        }
    }
    
    if ($DisableExceptionChainValidation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableExceptionChainValidation'
        }
    }
    if ($DriverLoadPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
        {
            ValueType = 'Dword'
            ValueData = 3
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DriverLoadPolicy'
        }
    }
    
    if ($SMB1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SMB1'
        }
    }
    
    if ($MRxSmb10_Start) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
        {
            ValueType = 'Dword'
            ValueData = 4
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Start'
        }
    }
    
    if ($NoNameReleaseOnDemand) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            ValueType = 'Dword'
            ValueData = 1
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoNameReleaseOnDemand'
        }
    }
    
    if ($NodeType) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NodeType'
        {
            ValueType = 'Dword'
            ValueData = 2
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NodeType'
        }
    }
    
    if ($EnableDeadGWDetect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableDeadGWDetect'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableDeadGWDetect'
        }
    }
    if ($DisableIPSourceRouting_TCPIP) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            ValueType = 'Dword'
            ValueData = 2
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableIPSourceRouting'
        }
    }
    
    if ($EnableICMPRedirect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            ValueType = 'Dword'
            ValueData = 0
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableICMPRedirect'
        }
    }
    
    if ($DisableIPSourceRouting_TCPIP6) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            ValueType = 'Dword'
            ValueData = 2
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableIPSourceRouting'
        }
    }
    
    if ($MinimumPasswordLength) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
        {
            Minimum_Password_Length = 14
            Name = 'Minimum_Password_Length'
        }
    }
    
    if ($EnableGuestAccount) {
        SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
        {
            Name = 'Accounts_Guest_account_status'
            Accounts_Guest_account_status = 'Disabled'
        }
    }
    
    if ($MinimumPasswordAge) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
        {
            Name = 'Minimum_Password_Age'
            Minimum_Password_Age = 1
        }
    }
    
    if ($PasswordHistorySize) {
        AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Name = 'Enforce_password_history'
            Enforce_password_history = 24
        }
    }
    if ($PasswordComplexity) {
        AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
        {
            Name = 'Password_must_meet_complexity_requirements'
            Password_must_meet_complexity_requirements = 'Enabled'
        }
    }
    
    if ($MaximumPasswordAge) {
        AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
        {
            Name = 'Maximum_Password_Age'
            Maximum_Password_Age = 365
        }
    }
    
    if ($LSAAnonymousNameLookup) {
        SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
        {
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
            Name = 'Network_access_Allow_anonymous_SID_Name_translation'
        }
    }
    
    if ($ClearTextPassword) {
        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Name = 'Store_passwords_using_reversible_encryption'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }
    }
    
    if ($EnableAdminAccount) {
        SecurityOption 'SecuritySetting(INF): EnableAdminAccount'
        {
            Name = 'Accounts_Administrator_account_status'
            Accounts_Administrator_account_status = 'Disabled'
        }
    }
    
    if ($RemotelyAccessibleRegistryPaths) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths_and_subpaths'
        {
            Name = 'Network_access_Remotely_accessible_registry_paths_and_subpaths'
            Network_access_Remotely_accessible_registry_paths_and_subpaths = 'System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog'
        }
    }
    
    if ($DigitallySignCommunications) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
        {
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
            Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
        }
    }
    
    if ($DoNotStoreLanManagerHash) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        }
    }
    if ($AdminApprovalModeForBuiltInAdmin) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        }
    }
    
    if ($RequireCaseInsensitivityForNonWindowsSubsystems) {
        SecurityOption 'SecurityRegistry(INF): System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
        {
            System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'
            Name = 'System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
        }
    }
    
    if ($StrengthenDefaultPermissionsOfInternalSystemObjects) {
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        }
    }
    
    if ($VirtualizeFileAndRegistryWriteFailures) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        }
    }
    
    if ($NamedPipesAccessiblyAnonymously) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Named_Pipes_that_can_be_accessed_anonymously'
        {
            Network_access_Named_Pipes_that_can_be_accessed_anonymously = 'String'
            Name = 'Network_access_Named_Pipes_that_can_be_accessed_anonymously'
        }
    }
    
    if ($AllowPKU2UAuthenticationRequests) {
        SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        }
    }
    
    if ($OnlyElevateUIAccessInSecureLocations) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
        }
    }
    if ($SharingAndSecurityModelForLocalAccounts) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Sharing_and_security_model_for_local_accounts'
        {
            Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
            Name = 'Network_access_Sharing_and_security_model_for_local_accounts'
        }
    }
    
    if ($ElevationPromptBehavior) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        }
    }
    
    if ($RestrictAnonymousAccessToNamedPipesAndShares) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        }
    }
    
    if ($MinimumSessionSecurityForNTLM) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        }
    }
    
    if ($LANManagerAuthenticationLevel) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only'
            Name = 'Network_security_LAN_Manager_authentication_level'
        }
    }
    
    if ($RemotelyAccessibleRegistryPaths) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths'
        {
            Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'
            Name = 'Network_access_Remotely_accessible_registry_paths'
        }
    }
    
    if ($PromptUserToChangePasswordBeforeExpiration) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Prompt_user_to_change_password_before_expiration'
        {
            Name = 'Interactive_logon_Prompt_user_to_change_password_before_expiration'
            Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'
        }
    }
    
    if ($DigitallySignCommunicationsAlways) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
        }
    }
    
    if ($BlockMicrosoftAccounts) {
        SecurityOption 'SecurityRegistry(INF): Accounts_Block_Microsoft_accounts'
        {
            Accounts_Block_Microsoft_accounts = 'Users cant add or log on with Microsoft accounts'
            Name = 'Accounts_Block_Microsoft_accounts'
        }
    }
    if ($InteractiveLogonDoNotDisplayLastUserName) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_display_last_user_name'
        {
            Interactive_logon_Do_not_display_last_user_name = 'Enabled'
            Name = 'Interactive_logon_Do_not_display_last_user_name'
        }
    }
    
    if ($AllowLocalSystemForNTLM) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        {
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
            Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        }
    }
    
    if ($EveryonePermissionsForAnonymousUsers) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        }
    }
    
    if ($DisconnectClientsWhenLogonHoursExpire) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
        {
            Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled'
            Name = 'Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
        }
    }
    
    if ($DoNotAllowAnonymousEnumerationOfSAMAccounts) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
        }
    }
    
    if ($DoNotAllowStorageOfPasswords) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication'
        {
            Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication = 'Enabled'
            Name = 'Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication'
        }
    }
    
    if ($IdleTimeBeforeSuspendingSession) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
        {
            Name = 'Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
            Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'
        }
    }
    
    if ($AllowFormatAndEjectRemovableMedia) {
        SecurityOption 'SecurityRegistry(INF): Devices_Allowed_to_format_and_eject_removable_media'
        {
            Devices_Allowed_to_format_and_eject_removable_media = 'Administrators and Interactive Users'
            Name = 'Devices_Allowed_to_format_and_eject_removable_media'
        }
    }
    
    if ($AllowUIAccessPromptsWithoutSecureDesktop) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        {
            User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
            Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        }
    }
    
    if ($DetectApplicationInstallationsAndPromptForElevation) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        }
    }
    
    if ($DigitallySignCommunicationsIfServerAgrees) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
         {
              Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
         }
    }
    if ($DoNotRequireCtrlAltDel) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_require_CTRL_ALT_DEL'
        {
            Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled'
            Name = 'Interactive_logon_Do_not_require_CTRL_ALT_DEL'
        }
    }
    
    if ($RunAllAdministratorsInAdminApprovalMode) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        }
    }
    
    if ($SendUnencryptedPasswordToSmbServers) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        }
    }
    
    if ($MinimumSessionSecurityForNTLM) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        }
    }
    
    if ($DoNotAllowAnonymousEnumerationOfSamAccounts) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        }
    }
    
    if ($LdapClientSigningRequirements) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }
    if ($RestrictClientsMakingRemoteCallsToSAM) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        {
            Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = 'O:BAG:BAD:(A;;RC;;;BA)'
            Name = 'Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        }
    }
    
    if ($LimitLocalAccountUseOfBlankPasswords) {
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }
    
    if ($SharesAccessibleAnonymously) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Shares_that_can_be_accessed_anonymously'
        {
            Network_access_Shares_that_can_be_accessed_anonymously = 'String'
            Name = 'Network_access_Shares_that_can_be_accessed_anonymously'
        }
    }
    
    if ($MachineInactivityLimit) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Interactive_logon_Machine_inactivity_limit = '900'
            Name = 'Interactive_logon_Machine_inactivity_limit'
        }
    }
    
    if ($ElevationPromptForStandardUsers) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Prompt for credentials on the secure desktop'
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        }
    }
    
    if ($DigitallySignCommunicationsAlways) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
        }
    }
    
    if ($EncryptionTypesAllowedForKerberos) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
        }
    }
    
    if ($AllowLocalSystemNullSessionFallback) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }
    
    if ($SwitchToSecureDesktopWhenPrompting) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
        {
            User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
            Name = 'User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
        }
    }

    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

