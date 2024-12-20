configuration Normaler_Schutzbedarf_Domanenmitglied_ND-Computer
{

    param(
        [bool]$AutoConnectAllowedOEM = $true,
        [bool]$EnumerateAdministrators = $true,
        [bool]$NoWebServices = $true,
        [bool]$PreXPSP2ShellProtocolBehavior = $true,
        [bool]$NoDriveTypeAutoRun = $true,
        [bool]$NoAutorun = $true,
        [bool]$LocalAccountTokenFilterPolicy = $true,
        [bool]$DisableAutomaticRestartSignOn = $true,
        [bool]$DisableBkGndGroupPolicyRemoved = $true,
        [bool]$MSAOptional = $true,
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
        [bool]$DCSettingIndex1 = $true,
        [bool]$ACSettingIndex1 = $true,
        [bool]$DCSettingIndex2 = $true,
        [bool]$ACSettingIndex2 = $true,
        [bool]$DCSettingIndex3 = $true,
        [bool]$ACSettingIndex3 = $true,
        [bool]$ACRSCertificates = $true,
        [bool]$ACRSCRLs = $true,
        [bool]$ACRSTLs = $true,
        [bool]$CACertificates = $true,
        [bool]$CACRLs = $true,
        [bool]$CACTLs = $true,
        [bool]$DisallowedCertificates = $true,
        [bool]$DisallowedCRLs = $true,
        [bool]$DisallowedCTLs = $true,
        [bool]$DPNGRA_Certificates = $true,
        [bool]$DPNGRA_CRLs = $true,
        [bool]$DPNGRA_CTLs = $true,
        [bool]$FVE_Certificates = $true,
        [bool]$FVE_CRLs = $true,
        [bool]$FVE_CTLs = $true,
        [bool]$FVE_NKP_Certificates = $true,
        [bool]$FVE_NKP_CRLs = $true,
        [bool]$FVE_NKP_CTLs = $true,
        [bool]$Root_Certificates = $true,
        [bool]$Root_CRLs = $true,
        [bool]$Root_CTLs = $true,
        [bool]$Trust_Certificates = $true,
        [bool]$Trust_CRLs = $true,
        [bool]$Trust_CTLs = $true,
        [bool]$TrustedPeople_Certificates = $true,
        [bool]$TrustedPeople_CRLs = $true,
        [bool]$TrustedPeople_CTLs = $true,
        [bool]$TrustedPublisher_Certificates = $true,
        [bool]$TrustedPublisher_CRLs = $true,
        [bool]$TrustedPublisher_CTLs = $true,
        [bool]$StandardUserAuthorizationFailureDuration = $true,
        [bool]$StandardUserAuthorizationFailureTotalThreshold = $true,
        [bool]$IgnoreDefaultList = $true,
        [bool]$DisableWindowsConsumerFeatures = $true,
        [bool]$RequirePinForPairing = $true,
        [bool]$AllowProtectedCreds = $true,
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
        [bool]$NoAutoplayForNonVolume = $true,
        [bool]$AllowGameDVR = $true,
        [bool]$NoBackgroundPolicy = $true,
        [bool]$NoGPOListChanges1 = $true,
        [bool]$NoGPOListChanges2 = $true,
        [bool]$EnableUserControl = $true,
        [bool]$AlwaysInstallElevated = $true,
        [bool]$DeviceEnumerationPolicy = $true,
        [bool]$AllowInsecureGuestAuth = $true,
        [bool]$NC_StdDomainUserSetLocation = $true,
        [bool]$AllowNetBridge_NLA = $true,
        [bool]$ShowSharedAccessUI = $true,
        [bool]$HardenedPaths_NETLOGON = $true,
        [bool]$HardenedPaths_SYSVOL = $true,
        [bool]$DisableFileSyncNGSC = $true,
        [bool]$NoLockScreenSlideshow = $true,
        [bool]$NoLockScreenCamera = $true,
        [bool]$EnableScripts = $true,
        [bool]$ExecutionPolicy = $true,
        [bool]$AllowBuildPreview = $true,
        [bool]$SaferPolicies = $true,
        [bool]$BlockDomainPicturePassword = $true,
        [bool]$DisableLockScreenAppNotifications = $true,
        [bool]$BlockUserFromShowingAccountDetailsOnSignin = $true,
        [bool]$DontDisplayNetworkSelectionUI = $true,
        [bool]$EnableCdp = $true,
        [bool]$AllowDomainPINLogon = $true,
        [bool]$EnumerateLocalUsers = $true,
        [bool]$DontEnumerateConnectedUsers = $true,
        [bool]$EnableSmartScreen = $true,
        [bool]$ShellSmartScreenLevel = $true,
        [bool]$fMinimizeConnections = $true,
        [bool]$fBlockNonDomain = $true,
        [bool]$AllowSearchToUseLocation = $true,
        [bool]$AllowIndexingEncryptedStoresOrItems = $true,
        [bool]$SetDisablePauseUXAccess = $true,
        [bool]$NoAutoUpdate = $true,
        [bool]$AUOptions = $true,
        [bool]$AutomaticMaintenanceEnabledRemoved = $true,
        [bool]$ScheduledInstallDay = $true,
        [bool]$ScheduledInstallTime = $true,
        [bool]$ScheduledInstallEveryWeek = $true,
        [bool]$ScheduledInstallFirstWeekRemoved = $true,
        [bool]$ScheduledInstallSecondWeekRemoved = $true,
        [bool]$ScheduledInstallThirdWeekRemoved = $true,
        [bool]$ScheduledInstallFourthWeekRemoved = $true,
        [bool]$AllowMUUpdateServiceRemoved = $true,
        [bool]$NoAutoRebootWithLoggedOnUsers = $true,
        [bool]$AllowBasic = $true,
        [bool]$AllowDigest = $true,
        [bool]$AllowUnencryptedTrafficClient = $true,
        [bool]$DisableRunAs = $true,
        [bool]$AllowUnencryptedTrafficService = $true,
        [bool]$PUAProtection = $true,
        [bool]$DisableAntiSpyware = $true,
        [bool]$DisableBehaviorMonitoring = $true,
        [bool]$DisableGenericRePorts = $true,
        [bool]$DisableEmailScanning = $true,
        [bool]$DisableRemovableDriveScanning = $true,
        [bool]$LocalSettingOverrideSpynetReporting = $true,
        [bool]$ExploitGuard_ASR_Rules = $true,
        [bool]$ASR_Rule1 = $true,
        [bool]$ASR_Rule2 = $true,
        [bool]$ASR_Rule3 = $true,
        [bool]$ASR_Rule4 = $true,
        [bool]$ASR_Rule5 = $true,
        [bool]$ASR_Rule6 = $true,
        [bool]$ASR_Rule7 = $true,
        [bool]$ASR_Rule8 = $true,
        [bool]$ASR_Rule9 = $true,
        [bool]$ASR_Rule10 = $true,
        [bool]$ASR_Rule11 = $true,
        [bool]$EnableNetworkProtection = $true,
        [bool]$DisallowExploitProtectionOverride = $true,
        [bool]$EnableMulticast = $true,
        [bool]$DisableWebPnPDownload = $true,
        [bool]$RestrictRemoteClients = $true,
        [bool]$EnableAuthEpResolution = $true,
        [bool]$AllowToGetHelp = $true,
        [bool]$AllowFullControlRemoved = $true,
        [bool]$MaxTicketExpiryRemoved = $true,
        [bool]$MaxTicketExpiryUnitsRemoved = $true,
        [bool]$UseMailtoRemoved = $true,
        [bool]$AllowUnsolicited = $true,
        [bool]$AllowUnsolicitedFullControlRemoved = $true,
        [bool]$DisableCdm = $true,
        [bool]$PromptForPassword = $true,
        [bool]$UserAuthentication = $true,
        [bool]$EncryptRPCTraffic = $true,
        [bool]$MinEncryptionLevel = $true,
        [bool]$SecurityLayer = $true,
        [bool]$fResetBroken = $true,
        [bool]$PerSessionTempDir = $true,
        [bool]$DeleteTempDirsOnExit = $true,
        [bool]$DisablePasswordSaving = $true,
        [bool]$PolicyVersion = $true,
        [bool]$DisableNotificationsDomain = $true,
        [bool]$EnableFirewallDomain = $true,
        [bool]$DefaultOutboundActionDomain = $true,
        [bool]$DefaultInboundActionDomain = $true,
        [bool]$DisableNotificationsPrivate = $true,
        [bool]$EnableFirewallPrivate = $true,
        [bool]$DefaultOutboundActionPrivate = $true,
        [bool]$DefaultInboundActionPrivateProfile = $true,
        [bool]$DefaultOutboundActionPublicProfile = $true,
        [bool]$DisableNotificationsPublicProfile = $true,
        [bool]$AllowLocalPolicyMergePublicProfile = $true,
        [bool]$AllowLocalIPsecPolicyMergePublicProfile = $true,
        [bool]$EnableFirewallPublicProfile = $true,
        [bool]$DefaultInboundActionPublicProfile = $true,
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
        [bool]$DisableIPSourceRouting = $true,
        [bool]$EnableICMPRedirect = $true,
        [bool]$DisableIPSourceRoutingIPv6 = $true,
        [bool]$LockoutDuration = $true,
        [bool]$EnableAdminAccount = $true,
        [bool]$ClearTextPassword = $true,
        [bool]$EnableGuestAccount = $true,
        [bool]$LSAAnonymousNameLookup = $true,
        [bool]$MinimumPasswordAge = $true,
        [bool]$MinimumPasswordLength = $true,
        [bool]$ResetLockoutCount = $true,
        [bool]$ForceLogoffWhenHourExpire = $true,
        [bool]$PasswordHistorySize = $true,
        [bool]$MaximumPasswordAge = $true,
        [bool]$PasswordComplexity = $true,
        [bool]$LockoutBadCount = $true,
        [bool]$RemotelyAccessibleRegistryPaths = $true,
        [bool]$MaxMachineAccountPasswordAge = $true,
        [bool]$SharingAndSecurityModel = $true,
        [bool]$DigitallySignSecureChannelData = $true,
        [bool]$DoNotStoreLANManagerHash = $true,
        [bool]$LimitLocalAccountUseOfBlankPasswords = $true,
        [bool]$RequireCaseInsensitivityForNonWindowsSubsystems = $true,
        [bool]$StrengthenDefaultPermissions = $true,
        [bool]$DigitallySignCommunicationsIfClientAgrees = $true,
        [bool]$UACBehaviorForElevationPrompt = $true,
        [bool]$UACAdminApprovalForBuiltInAdmin = $true,
        [bool]$AllowPKU2UAuthentication = $true,
        [bool]$OnlyElevateUIAccessFromSecureLocations = $true,
        [bool]$RequireStrongSessionKey = $true,
        [bool]$DigitallySignCommunicationsAlways = $true,
        [bool]$VirtualizeFileAndRegistryWriteFailures = $true,
        [bool]$MinimumSessionSecurityForNTLM = $true,
        [bool]$SendUnencryptedPasswordToSMBServers = $true,
        [bool]$LanManagerAuthenticationLevel = $true,
        [bool]$PromptUserToChangePasswordBeforeExpiration = $true,
        [bool]$DoNotDisplayLastUserName = $true,
        [bool]$IdleTimeBeforeSuspendingSession = $true,
        [bool]$DontAllowAnonymousEnumerationSAM = $true,
        [bool]$AllowLocalSystemToUseComputerIdentity = $true,
        [bool]$LetEveryonePermissionsApplyAnonymousUsers = $true,
        [bool]$DisconnectClientsWhenLogonHoursExpire = $true,
        [bool]$EncryptOrSignSecureChannelDataAlways = $true,
        [bool]$DontAllowAnonymousEnumerationSAMAccounts = $true,
        [bool]$DoNotAllowStorageOfPasswords = $true,
        [bool]$DisableMachineAccountPasswordChanges = $true,
        [bool]$DoNotRequireCtrlAltDel = $true,
        [bool]$AllowUIAccessApplicationsElevation = $true,
        [bool]$DetectApplicationInstallationsPrompt = $true,
        [bool]$DigitallySignCommunicationsIfServerAgrees = $true,
        [bool]$RestrictClientsToSAM = $true,
        [bool]$RunAllAdministratorsInAdminApprovalMode = $true,
        [bool]$AllowFormatAndEjectRemovableMedia = $true,
        [bool]$SmartCardRemovalBehavior = $true,
        [bool]$SPNTargetNameValidationLevel = $true,
        [bool]$DigitallyEncryptSecureChannel = $true,
        [bool]$LDAPClientSigningRequirements = $true,
        [bool]$RestrictAnonymousAccessToNamedPipes = $true,
        [bool]$SharesAccessibleAnonymously = $true,
        [bool]$MachineInactivityLimit = $true,
        [bool]$ElevationPromptForStandardUsers = $true,
        [bool]$NamedPipesAccessibleAnonymously = $true,
        [bool]$MachineAccountLockoutThreshold = $true,
        [bool]$KerberosEncryptionTypes = $true,
        [bool]$BlockMicrosoftAccounts = $true,
        [bool]$AllowLocalSystemNullSessionFallback = $true,
        [bool]$SwitchToSecureDesktopOnElevation = $true
    )
	
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($AutoConnectAllowedOEM) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config\AutoConnectAllowedOEM'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config'
            ValueType = 'Dword'
            ValueName = 'AutoConnectAllowedOEM'
            ValueData = 0
        }
    }
    
    if ($EnumerateAdministrators) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            ValueType = 'Dword'
            ValueName = 'EnumerateAdministrators'
            ValueData = 0
        }
    }
    
    if ($NoWebServices) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoWebServices'
            ValueData = 1
        }
    }
    
    if ($PreXPSP2ShellProtocolBehavior) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            ValueName = 'PreXPSP2ShellProtocolBehavior'
            ValueData = 0
        }
    }
    
    if ($NoDriveTypeAutoRun) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoDriveTypeAutoRun'
            ValueData = 255
        }
    }
    
    if ($NoAutorun) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoAutorun'
            ValueData = 1
        }
    }
    
    if ($LocalAccountTokenFilterPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            ValueName = 'LocalAccountTokenFilterPolicy'
            ValueData = 0
        }
    }

    f ($DisableAutomaticRestartSignOn) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            ValueName = 'DisableAutomaticRestartSignOn'
            ValueData = 1
        }
    }
    
    if ($DisableBkGndGroupPolicyRemoved) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy'
        {
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'String'
            ValueName = 'DisableBkGndGroupPolicy'
            ValueData = ''
        }
    }
    
    if ($MSAOptional) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            ValueName = 'MSAOptional'
            ValueData = 1
        }
    }
    
    if ($AllowEncryptionOracle) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\AllowEncryptionOracle'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
            ValueType = 'Dword'
            ValueName = 'AllowEncryptionOracle'
            ValueData = 0
        }
    }
    
    if ($AllowLinguisticDataCollection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput\AllowLinguisticDataCollection'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput'
            ValueType = 'Dword'
            ValueName = 'AllowLinguisticDataCollection'
            ValueData = 0
        }
    }
    
    if ($AutoAdminLogon) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            ValueType = 'String'
            ValueName = 'AutoAdminLogon'
            ValueData = '0'
        }
    }
    
    if ($ScreenSaverGracePeriod) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            ValueType = 'String'
            ValueName = 'ScreenSaverGracePeriod'
            ValueData = '5'
        }
    }

    if ($EnhancedAntiSpoofing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'
            ValueType = 'Dword'
            ValueName = 'EnhancedAntiSpoofing'
            ValueData = 1
        }
    }
    
    if ($RestrictImplicitTextCollection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization\RestrictImplicitTextCollection'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
            ValueType = 'Dword'
            ValueName = 'RestrictImplicitTextCollection'
            ValueData = 1
        }
    }
    
    if ($RestrictImplicitInkCollection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization\RestrictImplicitInkCollection'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
            ValueType = 'Dword'
            ValueName = 'RestrictImplicitInkCollection'
            ValueData = 1
        }
    }
    
    if ($AllowInputPersonalization) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
            ValueType = 'Dword'
            ValueName = 'AllowInputPersonalization'
            ValueData = 0
        }
    }
    
    if ($DisableEnclosureDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueType = 'Dword'
            ValueName = 'DisableEnclosureDownload'
            ValueData = 1
        }
    }
    
    if ($DisableUserAuth) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount\DisableUserAuth'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount'
            ValueType = 'Dword'
            ValueName = 'DisableUserAuth'
            ValueData = 1
        }
    }
    
    if ($PreventOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverride'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
            ValueType = 'Dword'
            ValueName = 'PreventOverride'
            ValueData = 1
        }
    }

    if ($EnabledV9) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\EnabledV9'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
            ValueType = 'Dword'
            ValueName = 'EnabledV9'
            ValueData = 1
        }
    }
    
    if ($DCSettingIndex1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueType = 'Dword'
            ValueName = 'DCSettingIndex'
            ValueData = 1
        }
    }
    
    if ($ACSettingIndex1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueType = 'Dword'
            ValueName = 'ACSettingIndex'
            ValueData = 1
        }
    }
    
    if ($DCSettingIndex2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\DCSettingIndex'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
            ValueType = 'Dword'
            ValueName = 'DCSettingIndex'
            ValueData = 0
        }
    }
    
    if ($ACSettingIndex2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\ACSettingIndex'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
            ValueType = 'Dword'
            ValueName = 'ACSettingIndex'
            ValueData = 0
        }
    }
    
    if ($DCSettingIndex3) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\DCSettingIndex'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
            ValueType = 'Dword'
            ValueName = 'DCSettingIndex'
            ValueData = 0
        }
    }
    
    if ($ACSettingIndex3) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex'
        {
             ValueType = 'Dword'
             ValueData = 0
             Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
             TargetType = 'ComputerConfiguration'
             ValueName = 'ACSettingIndex'
        }
    }
    if ($ACRSCertificates) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\ACRS\Certificates\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\ACRS\Certificates'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($ACRSCRLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\ACRS\CRLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\ACRS\CRLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($ACRSTLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\ACRS\CTLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\ACRS\CTLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($CACertificates) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($CACRLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CRLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CRLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    if ($CACTLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CTLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CTLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($DisallowedCertificates) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\Certificates\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\Certificates'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($DisallowedCRLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\CRLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\CRLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($DisallowedCTLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\CTLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\CTLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    if ($DPNGRA_Certificates) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\DPNGRA\Certificates\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\DPNGRA\Certificates'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($DPNGRA_CRLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\DPNGRA\CRLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\DPNGRA\CRLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($DPNGRA_CTLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\DPNGRA\CTLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\DPNGRA\CTLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($FVE_Certificates) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE\Certificates\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE\Certificates'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($FVE_CRLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE\CRLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE\CRLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($FVE_CTLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE\CTLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE\CTLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($FVE_NKP_Certificates) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE_NKP\Certificates\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE_NKP\Certificates'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }

    if ($FVE_NKP_CRLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE_NKP\CRLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE_NKP\CRLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($FVE_NKP_CTLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE_NKP\CTLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE_NKP\CTLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($Root_Certificates) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($Root_CRLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\CRLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\CRLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($Root_CTLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\CTLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\CTLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($Trust_Certificates) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Trust\Certificates\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Trust\Certificates'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($Trust_CRLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Trust\CRLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Trust\CRLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    if ($Trust_CTLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Trust\CTLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Trust\CTLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($TrustedPeople_Certificates) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\Certificates\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\Certificates'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($TrustedPeople_CRLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\CRLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\CRLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($TrustedPeople_CTLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\CTLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\CTLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($TrustedPublisher_Certificates) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($TrustedPublisher_CRLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($TrustedPublisher_CTLs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    if ($StandardUserAuthorizationFailureDuration) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\TPM\StandardUserAuthorizationFailureDuration'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\TPM'
            ValueType = 'Dword'
            ValueName = 'StandardUserAuthorizationFailureDuration'
            ValueData = 30
        }
    }
    
    if ($StandardUserAuthorizationFailureTotalThreshold) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\TPM\StandardUserAuthorizationFailureTotalThreshold'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\TPM'
            ValueType = 'Dword'
            ValueName = 'StandardUserAuthorizationFailureTotalThreshold'
            ValueData = 5
        }
    }
    
    if ($IgnoreDefaultList) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\TPM\BlockedCommands\IgnoreDefaultList'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\TPM\BlockedCommands'
            ValueType = 'Dword'
            ValueName = 'IgnoreDefaultList'
            ValueData = 0
        }
    }
    
    if ($DisableWindowsConsumerFeatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueType = 'Dword'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueData = 1
        }
    }
    
    if ($RequirePinForPairing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect\RequirePinForPairing'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect'
            ValueType = 'Dword'
            ValueName = 'RequirePinForPairing'
            ValueData = 2
        }
    }
    
    if ($AllowProtectedCreds) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
            ValueType = 'Dword'
            ValueName = 'AllowProtectedCreds'
            ValueData = 1
        }
    }
    
    if ($DisablePasswordReveal) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI'
            ValueType = 'Dword'
            ValueName = 'DisablePasswordReveal'
            ValueData = 1
        }
    }
    
    if ($DoNotShowFeedbackNotifications) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueType = 'Dword'
            ValueName = 'DoNotShowFeedbackNotifications'
            ValueData = 1
        }
    }

    if ($AllowTelemetry) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueType = 'Dword'
            ValueName = 'AllowTelemetry'
            ValueData = 0
        }
    }
    
    if ($AllowDeviceNameInTelemetry) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowDeviceNameInTelemetry'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueType = 'Dword'
            ValueName = 'AllowDeviceNameInTelemetry'
            ValueData = 0
        }
    }
    
    if ($DODownloadMode) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
            ValueType = 'Dword'
            ValueName = 'DODownloadMode'
            ValueData = 99
        }
    }
    
    if ($DenyDeviceIDs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
            ValueType = 'Dword'
            ValueName = 'DenyDeviceIDs'
            ValueData = 1
        }
    }
    
    if ($DenyDeviceIDsRetroactive) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDsRetroactive'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
            ValueType = 'Dword'
            ValueName = 'DenyDeviceIDsRetroactive'
            ValueData = 1
        }
    }
    
    if ($DenyDeviceClasses) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
            ValueType = 'Dword'
            ValueName = 'DenyDeviceClasses'
            ValueData = 1
        }
    }
    
    if ($DenyDeviceClassesRetroactive) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClassesRetroactive'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
            ValueType = 'Dword'
            ValueName = 'DenyDeviceClassesRetroactive'
            ValueData = 1
        }
    }
    if ($DenyDeviceClass1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\1'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
            ValueType = 'String'
            ValueName = '1'
            ValueData = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}'
        }
    }
    
    if ($DenyDeviceClass2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\2'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
            ValueType = 'String'
            ValueName = '2'
            ValueData = '{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}'
        }
    }
    
    if ($DenyDeviceClass3) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\3'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
            ValueType = 'String'
            ValueName = '3'
            ValueData = '{c06ff265-ae09-48f0-812c-16753d7cba83}'
        }
    }
    
    if ($DenyDeviceClass4) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\4'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
            ValueType = 'String'
            ValueName = '4'
            ValueData = '{6bdd1fc1-810f-11d0-bec7-08002be2092f}'
        }
    }
    if ($DenyDeviceID1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs\1'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs'
            ValueType = 'String'
            ValueName = '1'
            ValueData = 'PCI\CC_0C0A'
        }
    }
    
    if ($NoDataExecutionPrevention) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoDataExecutionPrevention'
            ValueData = 0
        }
    }
    
    if ($NoHeapTerminationOnCorruption) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoHeapTerminationOnCorruption'
            ValueData = 0
        }
    }
    
    if ($NoAutoplayForNonVolume) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            ValueName = 'NoAutoplayfornonVolume'
            ValueData = 1
        }
    }
    
    if ($AllowGameDVR) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR\AllowGameDVR'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
            ValueType = 'Dword'
            ValueName = 'AllowGameDVR'
            ValueData = 0
        }
    }
    
    if ($NoBackgroundPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueType = 'Dword'
            ValueName = 'NoBackgroundPolicy'
            ValueData = 0
        }
    }
    if ($NoGPOListChanges1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueType = 'Dword'
            ValueName = 'NoGPOListChanges'
            ValueData = 0
        }
    }
    
    if ($NoBackgroundPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\NoBackgroundPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
            ValueType = 'Dword'
            ValueName = 'NoBackgroundPolicy'
            ValueData = 0
        }
    }
    
    if ($NoGPOListChanges2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\NoGPOListChanges'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
            ValueType = 'Dword'
            ValueName = 'NoGPOListChanges'
            ValueData = 0
        }
    }
    
    if ($EnableUserControl) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            ValueName = 'EnableUserControl'
            ValueData = 0
        }
    }
    
    if ($AlwaysInstallElevated) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            ValueName = 'AlwaysInstallElevated'
            ValueData = 0
        }
    }
    
    if ($DeviceEnumerationPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
            ValueType = 'Dword'
            ValueName = 'DeviceEnumerationPolicy'
            ValueData = 0
        }
    }
    
    if ($AllowInsecureGuestAuth) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueType = 'Dword'
            ValueName = 'AllowInsecureGuestAuth'
            ValueData = 0
        }
    }
    
    if ($NC_StdDomainUserSetLocation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation'
         {
              ValueType = 'Dword'
              ValueData = 1
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
              TargetType = 'ComputerConfiguration'
              ValueName = 'NC_StdDomainUserSetLocation'
         }
    }

    if ($AllowNetBridge_NLA) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueType = 'Dword'
            ValueName = 'NC_AllowNetBridge_NLA'
            ValueData = 0
        }
    }
    
    if ($ShowSharedAccessUI) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueType = 'Dword'
            ValueName = 'NC_ShowSharedAccessUI'
            ValueData = 0
        }
    }
    
    if ($HardenedPaths_NETLOGON) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueType = 'String'
            ValueName = '\\*\NETLOGON'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
        }
    }
    
    if ($HardenedPaths_SYSVOL) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueType = 'String'
            ValueName = '\\*\SYSVOL'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
        }
    }
    
    if ($DisableFileSyncNGSC) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
            ValueType = 'Dword'
            ValueName = 'DisableFileSyncNGSC'
            ValueData = 1
        }
    }

    if ($NoLockScreenSlideshow) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueType = 'Dword'
            ValueName = 'NoLockScreenSlideshow'
            ValueData = 1
        }
    }
    
    if ($NoLockScreenCamera) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueType = 'Dword'
            ValueName = 'NoLockScreenCamera'
            ValueData = 1
        }
    }
    
    if ($EnableScripts) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\EnableScripts'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
            ValueType = 'Dword'
            ValueName = 'EnableScripts'
            ValueData = 1
        }
    }
    
    if ($ExecutionPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
            ValueType = 'String'
            ValueName = 'ExecutionPolicy'
            ValueData = 'RemoteSigned'
        }
    }

    if ($AllowBuildPreview) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'
            ValueType = 'Dword'
            ValueName = 'AllowBuildPreview'
            ValueData = 0
        }
    }
    
    if ($SaferPolicies) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\'
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer'
            TargetType = 'ComputerConfiguration'
            ValueName = ''
            # Value is intentionally omitted (null)
        }
    }
    
    if ($BlockDomainPicturePassword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\BlockDomainPicturePassword'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'BlockDomainPicturePassword'
            ValueData = 1
        }
    }
    
    if ($DisableLockScreenAppNotifications) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'DisableLockScreenAppNotifications'
            ValueData = 1
        }
    }
    
    if ($BlockUserFromShowingAccountDetailsOnSignin) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'BlockUserFromShowingAccountDetailsOnSignin'
            ValueData = 1
        }
    }
    
    if ($DontDisplayNetworkSelectionUI) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'DontDisplayNetworkSelectionUI'
            ValueData = 1
        }
    }

    if ($EnableCdp) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnableCdp'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'EnableCdp'
            ValueData = 0
        }
    }
    
    if ($AllowDomainPINLogon) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'AllowDomainPINLogon'
            ValueData = 0
        }
    }
    
    if ($EnumerateLocalUsers) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'EnumerateLocalUsers'
            ValueData = 0
        }
    }
    
    if ($DontEnumerateConnectedUsers) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'DontEnumerateConnectedUsers'
            ValueData = 1
        }
    }
    
    if ($EnableSmartScreen) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            ValueName = 'EnableSmartScreen'
            ValueData = 1
        }
    }
    
    if ($ShellSmartScreenLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\ShellSmartScreenLevel'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'String'
            ValueName = 'ShellSmartScreenLevel'
            ValueData = 'Block'
        }
    }

    if ($fMinimizeConnections) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueType = 'Dword'
            ValueName = 'fMinimizeConnections'
            ValueData = 1
        }
    }
    
    if ($fBlockNonDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueType = 'Dword'
            ValueName = 'fBlockNonDomain'
            ValueData = 1
        }
    }
    
    if ($AllowSearchToUseLocation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowSearchToUseLocation'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueType = 'Dword'
            ValueName = 'AllowSearchToUseLocation'
            ValueData = 0
        }
    }
    
    if ($AllowIndexingEncryptedStoresOrItems) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueType = 'Dword'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
            ValueData = 0
        }
    }

    if ($SetDisablePauseUXAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\SetDisablePauseUXAccess'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            ValueType = 'Dword'
            ValueName = 'SetDisablePauseUXAccess'
            ValueData = 1
        }
    }
    
    if ($NoAutoUpdate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueType = 'Dword'
            ValueName = 'NoAutoUpdate'
            ValueData = 0
        }
    }
    
    if ($AUOptions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueType = 'Dword'
            ValueName = 'AUOptions'
            ValueData = 4
        }
    }
    
    if ($AutomaticMaintenanceEnabledRemoved) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AutomaticMaintenanceEnabled'
        {
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueType = 'String'
            ValueName = 'AutomaticMaintenanceEnabled'
            ValueData = ''
        }
    }
    
    if ($ScheduledInstallDay) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueType = 'Dword'
            ValueName = 'ScheduledInstallDay'
            ValueData = 0
        }
    }
    
    if ($ScheduledInstallTime) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallTime'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueType = 'Dword'
            ValueName = 'ScheduledInstallTime'
            ValueData = 3
        }
    }
    
    if ($ScheduledInstallEveryWeek) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallEveryWeek'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueType = 'Dword'
            ValueName = 'ScheduledInstallEveryWeek'
            ValueData = 1
        }
    }
    
    if ($ScheduledInstallFirstWeekRemoved) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFirstWeek'
        {
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueType = 'String'
            ValueName = 'ScheduledInstallFirstWeek'
            ValueData = ''
        }
    }
    
    if ($ScheduledInstallSecondWeekRemoved) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallSecondWeek'
        {
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueType = 'String'
            ValueName = 'ScheduledInstallSecondWeek'
            ValueData = ''
        }
    }

    if ($ScheduledInstallThirdWeekRemoved) {
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
    
    if ($ScheduledInstallFourthWeekRemoved) {
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
    
    if ($AllowMUUpdateServiceRemoved) {
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
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueType = 'Dword'
            ValueName = 'NoAutoRebootWithLoggedOnUsers'
            ValueData = 0
        }
    }
    
    if ($AllowBasic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if ($AllowDigest) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            ValueName = 'AllowDigest'
            ValueData = 0
        }
    }
    if ($AllowUnencryptedTrafficClient) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            ValueName = 'AllowUnencryptedTraffic'
            ValueData = 0
        }
    }
    
    if ($AllowBasic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if ($DisableRunAs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            ValueName = 'DisableRunAs'
            ValueData = 1
        }
    }
    
    if ($AllowUnencryptedTrafficService) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            ValueName = 'AllowUnencryptedTraffic'
            ValueData = 0
        }
    }
    
    if ($PUAProtection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\PUAProtection'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
            ValueType = 'Dword'
            ValueName = 'PUAProtection'
            ValueData = 1
        }
    }
    
    if ($DisableAntiSpyware) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
            ValueType = 'Dword'
            ValueName = 'DisableAntiSpyware'
            ValueData = 0
        }
    }

    if ($DisableBehaviorMonitoring) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueType = 'Dword'
            ValueName = 'DisableBehaviorMonitoring'
            ValueData = 0
        }
    }
    
    if ($DisableGenericRePorts) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'
            ValueType = 'Dword'
            ValueName = 'DisableGenericRePorts'
            ValueData = 1
        }
    }
    
    if ($DisableEmailScanning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
            ValueType = 'Dword'
            ValueName = 'DisableEmailScanning'
            ValueData = 0
        }
    }
    
    if ($DisableRemovableDriveScanning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
            ValueType = 'Dword'
            ValueName = 'DisableRemovableDriveScanning'
            ValueData = 0
        }
    }
    
    if ($LocalSettingOverrideSpynetReporting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            ValueType = 'Dword'
            ValueName = 'LocalSettingOverrideSpynetReporting'
            ValueData = 0
        }
    }
    
    if ($ExploitGuard_ASR_Rules) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
            ValueType = 'Dword'
            ValueName = 'ExploitGuard_ASR_Rules'
            ValueData = 1
        }
    }

    if ($ASR_Rule1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\26190899-1602-49e8-8b27-eb1d0a1ce869'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            ValueName = '26190899-1602-49e8-8b27-eb1d0a1ce869'
            ValueData = '1'
        }
    }
    
    if ($ASR_Rule2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\3b576869-a4ec-4529-8536-b80a7769e899'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            ValueName = '3b576869-a4ec-4529-8536-b80a7769e899'
            ValueData = '1'
        }
    }
    
    if ($ASR_Rule3) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\5beb7efe-fd9a-4556-801d-275e5ffc04cc'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            ValueName = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
            ValueData = '1'
        }
    }
    
    if ($ASR_Rule4) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            ValueName = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
            ValueData = '1'
        }
    }
    
    if ($ASR_Rule5) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            ValueName = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
            ValueData = '1'
        }
    }
    if ($ASR_Rule6) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
         {
              ValueType = 'String'
              ValueData = '1'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              TargetType = 'ComputerConfiguration'
              ValueName = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
         }
    }
    if ($ASR_Rule7) {
         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
         {
              ValueType = 'String'
              ValueData = '1'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              TargetType = 'ComputerConfiguration'
              ValueName = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
         }
        }
    if ($ASR_Rule8) {
         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
         {
              ValueType = 'String'
              ValueData = '1'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              TargetType = 'ComputerConfiguration'
              ValueName = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
         }
    }
    if ($ASR_Rule9) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            ValueName = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
            ValueData = '1'
        }
    }
    
    if ($ASR_Rule10) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\d3e037e1-3eb8-44c8-a917-57927947596d'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            ValueName = 'd3e037e1-3eb8-44c8-a917-57927947596d'
            ValueData = '1'
        }
    }
    
    if ($ASR_Rule11) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\d4f940ab-401b-4efc-aadc-ad5f3c50688a'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            ValueName = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
            ValueData = '1'
        }
    }

    if ($EnableNetworkProtection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
            ValueType = 'Dword'
            ValueName = 'EnableNetworkProtection'
            ValueData = 1
        }
    }
    
    if ($DisallowExploitProtectionOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\DisallowExploitProtectionOverride'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'
            ValueType = 'Dword'
            ValueName = 'DisallowExploitProtectionOverride'
            ValueData = 1
        }
    }
    
    if ($EnableMulticast) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueType = 'Dword'
            ValueName = 'EnableMulticast'
            ValueData = 0
        }
    }
    
    if ($DisableWebPnPDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            ValueType = 'Dword'
            ValueName = 'DisableWebPnPDownload'
            ValueData = 1
        }
    }
    
    if ($RestrictRemoteClients) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueType = 'Dword'
            ValueName = 'RestrictRemoteClients'
            ValueData = 1
        }
    }

    if ($EnableAuthEpResolution) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueType = 'Dword'
            ValueName = 'EnableAuthEpResolution'
            ValueData = 1
        }
    }
    
    if ($AllowToGetHelp) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fAllowToGetHelp'
            ValueData = 0
        }
    }
    
    if ($AllowFullControlRemoved) {
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
    
    if ($MaxTicketExpiryRemoved) {
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
    
    if ($MaxTicketExpiryUnitsRemoved) {
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
    if ($UseMailtoRemoved) {
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
    
    if ($AllowUnsolicited) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fAllowUnsolicited'
            ValueData = 0
        }
    }
    
    if ($AllowUnsolicitedFullControlRemoved) {
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
    
    if ($DisableCdm) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fDisableCdm'
            ValueData = 1
        }
    }
    
    if ($PromptForPassword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fPromptForPassword'
            ValueData = 1
        }
    }
    
    if ($UserAuthentication) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'UserAuthentication'
            ValueData = 1
        }
    }
    
    if ($EncryptRPCTraffic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fEncryptRPCTraffic'
            ValueData = 1
        }
    }
    if ($MinEncryptionLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'MinEncryptionLevel'
            ValueData = 3
        }
    }
    
    if ($SecurityLayer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\SecurityLayer'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'SecurityLayer'
            ValueData = 2
        }
    }
    
    if ($fResetBroken) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fResetBroken'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'fResetBroken'
            ValueData = 1
        }
    }
    
    if ($PerSessionTempDir) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'PerSessionTempDir'
            ValueData = 1
        }
    }
    
    if ($DeleteTempDirsOnExit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'DeleteTempDirsOnExit'
            ValueData = 1
        }
    }
    
    if ($DisablePasswordSaving) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            ValueName = 'DisablePasswordSaving'
            ValueData = 1
        }
    }
    
    if ($PolicyVersion) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PolicyVersion'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
            ValueType = 'Dword'
            ValueName = 'PolicyVersion'
            ValueData = 541
        }
    }

    if ($DisableNotificationsDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueType = 'Dword'
            ValueName = 'DisableNotifications'
            ValueData = 1
        }
    }
    
    if ($EnableFirewallDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueType = 'Dword'
            ValueName = 'EnableFirewall'
            ValueData = 1
        }
    }
    
    if ($DefaultOutboundActionDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueType = 'Dword'
            ValueName = 'DefaultOutboundAction'
            ValueData = 0
        }
    }
    
    if ($DefaultInboundActionDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueType = 'Dword'
            ValueName = 'DefaultInboundAction'
            ValueData = 1
        }
    }
    
    if ($DisableNotificationsPrivate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueType = 'Dword'
            ValueName = 'DisableNotifications'
            ValueData = 1
        }
    }
    
    if ($EnableFirewallPrivate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueType = 'Dword'
            ValueName = 'EnableFirewall'
            ValueData = 1
        }
    }
    
    if ($DefaultOutboundActionPrivate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueType = 'Dword'
            ValueName = 'DefaultOutboundAction'
            ValueData = 0
        }
    }
    if ($DefaultInboundActionPrivateProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueType = 'Dword'
            ValueName = 'DefaultInboundAction'
            ValueData = 1
        }
    }
    
    if ($DefaultOutboundActionPublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            ValueName = 'DefaultOutboundAction'
            ValueData = 0
        }
    }
    
    if ($DisableNotificationsPublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            ValueName = 'DisableNotifications'
            ValueData = 1
        }
    }
    
    if ($AllowLocalPolicyMergePublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            ValueName = 'AllowLocalPolicyMerge'
            ValueData = 0
        }
    }
    
    if ($AllowLocalIPsecPolicyMergePublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueData = 0
        }
    }
    
    if ($EnableFirewallPublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            ValueName = 'EnableFirewall'
            ValueData = 1
        }
    }
    
    if ($DefaultInboundActionPublicProfile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            ValueName = 'DefaultInboundAction'
            ValueData = 1
        }
    }
    
    if ($AllowWindowsInkWorkspace) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
            ValueType = 'Dword'
            ValueName = 'AllowWindowsInkWorkspace'
            ValueData = 1
        }
    }

    if ($AutoDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\AutoDownload'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
            ValueType = 'Dword'
            ValueName = 'AutoDownload'
            ValueData = 4
        }
    }
    
    if ($DisableOSUpgrade) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\DisableOSUpgrade'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
            ValueType = 'Dword'
            ValueName = 'DisableOSUpgrade'
            ValueData = 1
        }
    }
    
    if ($RunAsPPL) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueType = 'Dword'
            ValueName = 'RunAsPPL'
            ValueData = 1
        }
    }
    
    if ($UseLogonCredential) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            ValueType = 'Dword'
            ValueName = 'UseLogonCredential'
            ValueData = 0
        }
    }
    
    if ($SafeDllSearchMode) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            ValueType = 'Dword'
            ValueName = 'SafeDllSearchMode'
            ValueData = 1
        }
    }
    
    if ($DisableExceptionChainValidation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            ValueType = 'Dword'
            ValueName = 'DisableExceptionChainValidation'
            ValueData = 0
        }
    }

    if ($DriverLoadPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueType = 'Dword'
            ValueName = 'DriverLoadPolicy'
            ValueData = 3
        }
    }
    
    if ($SMB1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueType = 'Dword'
            ValueName = 'SMB1'
            ValueData = 0
        }
    }
    
    if ($MRxSmb10_Start) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10'
            ValueType = 'Dword'
            ValueName = 'Start'
            ValueData = 4
        }
    }
    
    if ($NoNameReleaseOnDemand) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
            ValueType = 'Dword'
            ValueName = 'NoNameReleaseOnDemand'
            ValueData = 1
        }
    }
    
    if ($NodeType) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NodeType'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
            ValueType = 'Dword'
            ValueName = 'NodeType'
            ValueData = 2
        }
    }
    
    if ($EnableDeadGWDetect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableDeadGWDetect'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            ValueName = 'EnableDeadGWDetect'
            ValueData = 0
        }
    }
    
    if ($DisableIPSourceRouting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            ValueName = 'DisableIPSourceRouting'
            ValueData = 2
        }
    }
    if ($EnableICMPRedirect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            ValueName = 'EnableICMPRedirect'
            ValueData = 0
        }
    }
    
    if ($DisableIPSourceRoutingIPv6) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueType = 'Dword'
            ValueName = 'DisableIPSourceRouting'
            ValueData = 2
        }
    }
    
    if ($LockoutDuration) {
        AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Name = 'Account_lockout_duration'
            Account_lockout_duration = 15
        }
    }
    
    if ($EnableAdminAccount) {
        SecurityOption 'SecuritySetting(INF): EnableAdminAccount'
        {
            Name = 'Accounts_Administrator_account_status'
            Accounts_Administrator_account_status = 'Disabled'
        }
    }
    
    if ($ClearTextPassword) {
        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Name = 'Store_passwords_using_reversible_encryption'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }
    }
    
    if ($EnableGuestAccount) {
        SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
        {
            Name = 'Accounts_Guest_account_status'
            Accounts_Guest_account_status = 'Disabled'
        }
    }
    
    if ($LSAAnonymousNameLookup) {
        SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
        {
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
            Name = 'Network_access_Allow_anonymous_SID_Name_translation'
        }
    }
    
    if ($MinimumPasswordAge) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
        {
            Name = 'Minimum_Password_Age'
            Minimum_Password_Age = 1
        }
    }

    if ($MinimumPasswordLength) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
        {
            Minimum_Password_Length = 14
            Name = 'Minimum_Password_Length'
        }
    }
    
    if ($ResetLockoutCount) {
        AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
        {
            Name = 'Reset_account_lockout_counter_after'
            Reset_account_lockout_counter_after = 15
        }
    }
    
    if ($ForceLogoffWhenHourExpire) {
        SecurityOption 'SecuritySetting(INF): ForceLogoffWhenHourExpire'
        {
            Name = 'Network_security_Force_logoff_when_logon_hours_expire'
            Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'
        }
    }
    
    if ($PasswordHistorySize) {
        AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Name = 'Enforce_password_history'
            Enforce_password_history = 24
        }
    }
    
    if ($MaximumPasswordAge) {
        AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
        {
            Name = 'Maximum_Password_Age'
            Maximum_Password_Age = 365
        }
    }
    
    if ($PasswordComplexity) {
        AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
        {
            Name = 'Password_must_meet_complexity_requirements'
            Password_must_meet_complexity_requirements = 'Enabled'
        }
    }
    
    if ($LockoutBadCount) {
        AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
        {
            Name = 'Account_lockout_threshold'
            Account_lockout_threshold = 10
        }
    }
    
    if ($RemotelyAccessibleRegistryPaths) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths_and_subpaths'
        {
            Name = 'Network_access_Remotely_accessible_registry_paths_and_subpaths'
            Network_access_Remotely_accessible_registry_paths_and_subpaths = 'System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentControlSet\Services\SysmonLog'
        }
    }
    
    if ($MaxMachineAccountPasswordAge) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Domain_member_Maximum_machine_account_password_age = '30'
            Name = 'Domain_member_Maximum_machine_account_password_age'
        }
    }
    
    if ($SharingAndSecurityModel) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Sharing_and_security_model_for_local_accounts'
        {
            Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
            Name = 'Network_access_Sharing_and_security_model_for_local_accounts'
        }
    }
    
    if ($DigitallySignSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
        }
    }

    if ($DoNotStoreLANManagerHash) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        }
    }
    
    if ($LimitLocalAccountUseOfBlankPasswords) {
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }
    
    if ($RequireCaseInsensitivityForNonWindowsSubsystems) {
        SecurityOption 'SecurityRegistry(INF): System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
        {
            System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'
            Name = 'System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
        }
    }
    
    if ($StrengthenDefaultPermissions) {
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        }
    }
    
    if ($DigitallySignCommunicationsIfClientAgrees) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
        {
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
            Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
        }
    }
    
    if ($UACBehaviorForElevationPrompt) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        }
    }
    
    if ($UACAdminApprovalForBuiltInAdmin) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        }
    }
    
    if ($AllowPKU2UAuthentication) {
        SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        }
    }
    
    if ($OnlyElevateUIAccessFromSecureLocations) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
        }
    }

    if ($RequireStrongSessionKey) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
        }
    }
    
    if ($DigitallySignCommunicationsAlways) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
        }
    }
    if ($VirtualizeFileAndRegistryWriteFailures) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        }
    }
    
    if ($MinimumSessionSecurityForNTLM) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        }
    }
    
    if ($SendUnencryptedPasswordToSMBServers) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        }
    }
    
    if ($LanManagerAuthenticationLevel) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only'
            Name = 'Network_security_LAN_Manager_authentication_level'
        }
    }
    
    if ($PromptUserToChangePasswordBeforeExpiration) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Prompt_user_to_change_password_before_expiration'
        {
            Name = 'Interactive_logon_Prompt_user_to_change_password_before_expiration'
            Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'
        }
    }
    
    if ($DoNotDisplayLastUserName) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_display_last_user_name'
        {
            Interactive_logon_Do_not_display_last_user_name = 'Enabled'
            Name = 'Interactive_logon_Do_not_display_last_user_name'
        }
    }
    
    if ($DigitallySignCommunicationsAlways) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
        }
    }

    if ($IdleTimeBeforeSuspendingSession) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
        {
            Name = 'Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
            Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'
        }
    }
    
    if ($DontAllowAnonymousEnumerationSAM) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        }
    }
    
    if ($AllowLocalSystemToUseComputerIdentity) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        {
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
            Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        }
    }
    
    if ($LetEveryonePermissionsApplyAnonymousUsers) {
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
    
    if ($EncryptOrSignSecureChannelDataAlways) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        }
    }
    
    if ($DontAllowAnonymousEnumerationSAMAccounts) {
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
    
    if ($DisableMachineAccountPasswordChanges) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
            Name = 'Domain_member_Disable_machine_account_password_changes'
        }
    }
    
    if ($DoNotRequireCtrlAltDel) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_require_CTRL_ALT_DEL'
        {
            Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled'
            Name = 'Interactive_logon_Do_not_require_CTRL_ALT_DEL'
        }
    }
    
    if ($AllowUIAccessApplicationsElevation) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        {
            User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
            Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        }
    }
    
    if ($DetectApplicationInstallationsPrompt) {
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
    
    if ($RestrictClientsToSAM) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        {
            Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = 'O:BAG:BAD:(A;;RC;;;BA)'
            Name = 'Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        }
    }
    
    if ($RemotelyAccessibleRegistryPaths) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths'
        {
            Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'
            Name = 'Network_access_Remotely_accessible_registry_paths'
        }
    }
    
    if ($RunAllAdministratorsInAdminApprovalMode) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        }
    }

    if ($AllowFormatAndEjectRemovableMedia) {
        SecurityOption 'SecurityRegistry(INF): Devices_Allowed_to_format_and_eject_removable_media'
        {
            Devices_Allowed_to_format_and_eject_removable_media = 'Administrators and Interactive Users'
            Name = 'Devices_Allowed_to_format_and_eject_removable_media'
        }
    }
    
    if ($MinimumSessionSecurityForNTLM) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        }
    }
    
    if ($SmartCardRemovalBehavior) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Name = 'Interactive_logon_Smart_card_removal_behavior'
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
        }
    }
    
    if ($SPNTargetNameValidationLevel) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Server_SPN_target_name_validation_level'
        {
            Microsoft_network_server_Server_SPN_target_name_validation_level = 'Accept if provided by client'
            Name = 'Microsoft_network_server_Server_SPN_target_name_validation_level'
        }
    }
    
    if ($DigitallyEncryptSecureChannel) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        }
    }
    
    if ($LDAPClientSigningRequirements) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }

    if ($RestrictAnonymousAccessToNamedPipes) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
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
    
    if ($NamedPipesAccessibleAnonymously) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Named_Pipes_that_can_be_accessed_anonymously'
        {
            Network_access_Named_Pipes_that_can_be_accessed_anonymously = 'String'
            Name = 'Network_access_Named_Pipes_that_can_be_accessed_anonymously'
        }
    }
    
    if ($MachineAccountLockoutThreshold) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_account_lockout_threshold'
        {
            Name = 'Interactive_logon_Machine_account_lockout_threshold'
            Interactive_logon_Machine_account_lockout_threshold = '10'
        }
    }
    
    if ($KerberosEncryptionTypes) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
        }
    }
    
    if ($BlockMicrosoftAccounts) {
        SecurityOption 'SecurityRegistry(INF): Accounts_Block_Microsoft_accounts'
        {
            Accounts_Block_Microsoft_accounts = 'Users cant add or log on with Microsoft accounts'
            Name = 'Accounts_Block_Microsoft_accounts'
        }
    }
    
    if ($AllowLocalSystemNullSessionFallback) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }
    
    if ($SwitchToSecureDesktopOnElevation) {
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

