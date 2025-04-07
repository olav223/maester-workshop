BeforeDiscovery {
$SettingsApiAvailable = (Invoke-MtGraphRequest -RelativeUri 'settings' -ApiVersion beta).values.name
$EnabledAuthMethods = (Get-MtAuthenticationMethodPolicyConfig -State Enabled).Id
$EnabledAdminConsentWorkflow = (Invoke-MtGraphRequest -RelativeUri 'policies/adminConsentRequestPolicy' -ApiVersion beta).isenabled
}
Describe "Default Authorization Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.AP01" {
    It "EIDSCA.AP01: Default Authorization Settings - Enabled Self service password reset for administrators. See https://maester.dev/docs/tests/EIDSCA.AP01" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authorizationPolicy"
            .allowedToUseSSPR -eq 'false'
        #>
        Test-MtEidscaControl -CheckId AP01 | Should -Be 'false'
    }
}
Describe "Default Authorization Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.AP04" {
    It "EIDSCA.AP04: Default Authorization Settings - Guest invite restrictions. See https://maester.dev/docs/tests/EIDSCA.AP04" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authorizationPolicy"
            .allowInvitesFrom -in @('adminsAndGuestInviters','none')
        #>
        Test-MtEidscaControl -CheckId AP04 | Should -BeIn @('adminsAndGuestInviters','none')
    }
}
Describe "Default Authorization Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.AP05" {
    It "EIDSCA.AP05: Default Authorization Settings - Sign-up for email based subscription. See https://maester.dev/docs/tests/EIDSCA.AP05" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authorizationPolicy"
            .allowedToSignUpEmailBasedSubscriptions -eq 'false'
        #>
        Test-MtEidscaControl -CheckId AP05 | Should -Be 'false'
    }
}
Describe "Default Authorization Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.AP06" {
    It "EIDSCA.AP06: Default Authorization Settings - User can join the tenant by email validation. See https://maester.dev/docs/tests/EIDSCA.AP06" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authorizationPolicy"
            .allowEmailVerifiedUsersToJoinOrganization -eq 'false'
        #>
        Test-MtEidscaControl -CheckId AP06 | Should -Be 'false'
    }
}
Describe "Default Authorization Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.AP07" {
    It "EIDSCA.AP07: Default Authorization Settings - Guest user access. See https://maester.dev/docs/tests/EIDSCA.AP07" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authorizationPolicy"
            .guestUserRoleId -eq '2af84b1e-32c8-42b7-82bc-daa82404023b'
        #>
        Test-MtEidscaControl -CheckId AP07 | Should -Be '2af84b1e-32c8-42b7-82bc-daa82404023b'
    }
}
Describe "Default Authorization Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.AP08" {
    It "EIDSCA.AP08: Default Authorization Settings - User consent policy assigned for applications. See https://maester.dev/docs/tests/EIDSCA.AP08" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authorizationPolicy"
            .permissionGrantPolicyIdsAssignedToDefaultUserRole | Sort-Object -Descending | select-object -first 1 -eq 'ManagePermissionGrantsForSelf.microsoft-user-default-low'
        #>
        Test-MtEidscaControl -CheckId AP08 | Should -Be 'ManagePermissionGrantsForSelf.microsoft-user-default-low'
    }
}
Describe "Default Authorization Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.AP09" {
    It "EIDSCA.AP09: Default Authorization Settings - Risk-based step-up consent. See https://maester.dev/docs/tests/EIDSCA.AP09" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authorizationPolicy"
            .allowUserConsentForRiskyApps -eq 'false'
        #>
        Test-MtEidscaControl -CheckId AP09 | Should -Be 'false'
    }
}
Describe "Default Authorization Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.AP10" {
    It "EIDSCA.AP10: Default Authorization Settings - Default User Role Permissions - Allowed to create Apps. See https://maester.dev/docs/tests/EIDSCA.AP10" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authorizationPolicy"
            .defaultUserRolePermissions.allowedToCreateApps -eq 'false'
        #>
        Test-MtEidscaControl -CheckId AP10 | Should -Be 'false'
    }
}
Describe "Default Authorization Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.AP14" {
    It "EIDSCA.AP14: Default Authorization Settings - Default User Role Permissions - Allowed to read other users. See https://maester.dev/docs/tests/EIDSCA.AP14" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authorizationPolicy"
            .defaultUserRolePermissions.allowedToReadOtherUsers -eq 'true'
        #>
        Test-MtEidscaControl -CheckId AP14 | Should -Be 'true'
    }
}

Describe "Default Settings - Consent Policy Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.CP01" {
    It "EIDSCA.CP01: Default Settings - Consent Policy Settings - Group owner consent for apps accessing data. See https://maester.dev/docs/tests/EIDSCA.CP01" -TestCases @{ SettingsApiAvailable = $SettingsApiAvailable } {
        <#
            Check if "https://graph.microsoft.com/beta/settings"
            .values | where-object name -eq 'EnableGroupSpecificConsent' | select-object -expand value -eq 'False'
        #>
        Test-MtEidscaControl -CheckId CP01 | Should -Be 'False'
    }
}
Describe "Default Settings - Consent Policy Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.CP03" {
    It "EIDSCA.CP03: Default Settings - Consent Policy Settings - Block user consent for risky apps. See https://maester.dev/docs/tests/EIDSCA.CP03" -TestCases @{ SettingsApiAvailable = $SettingsApiAvailable } {
        <#
            Check if "https://graph.microsoft.com/beta/settings"
            .values | where-object name -eq 'BlockUserConsentForRiskyApps' | select-object -expand value -eq 'true'
        #>
        Test-MtEidscaControl -CheckId CP03 | Should -Be 'true'
    }
}
Describe "Default Settings - Consent Policy Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.CP04" {
    It "EIDSCA.CP04: Default Settings - Consent Policy Settings - Users can request admin consent to apps they are unable to consent to. See https://maester.dev/docs/tests/EIDSCA.CP04" -TestCases @{ SettingsApiAvailable = $SettingsApiAvailable } {
        <#
            Check if "https://graph.microsoft.com/beta/settings"
            .values | where-object name -eq 'EnableAdminConsentRequests' | select-object -expand value -eq 'true'
        #>
        Test-MtEidscaControl -CheckId CP04 | Should -Be 'true'
    }
}

Describe "Default Settings - Password Rule Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.PR01" {
    It "EIDSCA.PR01: Default Settings - Password Rule Settings - Password Protection - Mode. See https://maester.dev/docs/tests/EIDSCA.PR01" -TestCases @{ SettingsApiAvailable = $SettingsApiAvailable } {
        <#
            Check if "https://graph.microsoft.com/beta/settings"
            .values | where-object name -eq 'BannedPasswordCheckOnPremisesMode' | select-object -expand value -eq 'Enforce'
        #>
        Test-MtEidscaControl -CheckId PR01 | Should -Be 'Enforce'
    }
}
Describe "Default Settings - Password Rule Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.PR02" {
    It "EIDSCA.PR02: Default Settings - Password Rule Settings - Password Protection - Enable password protection on Windows Server Active Directory. See https://maester.dev/docs/tests/EIDSCA.PR02" {
        <#
            Check if "https://graph.microsoft.com/beta/settings"
            .values | where-object name -eq 'EnableBannedPasswordCheckOnPremises' | select-object -expand value -eq 'True'
        #>
        Test-MtEidscaControl -CheckId PR02 | Should -Be 'True'
    }
}
Describe "Default Settings - Password Rule Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.PR03" {
    It "EIDSCA.PR03: Default Settings - Password Rule Settings - Enforce custom list. See https://maester.dev/docs/tests/EIDSCA.PR03" -TestCases @{ SettingsApiAvailable = $SettingsApiAvailable } {
        <#
            Check if "https://graph.microsoft.com/beta/settings"
            .values | where-object name -eq 'EnableBannedPasswordCheck' | select-object -expand value -eq 'True'
        #>
        Test-MtEidscaControl -CheckId PR03 | Should -Be 'True'
    }
}
Describe "Default Settings - Password Rule Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.PR05" {
    It "EIDSCA.PR05: Default Settings - Password Rule Settings - Smart Lockout - Lockout duration in seconds. See https://maester.dev/docs/tests/EIDSCA.PR05" {
        <#
            Check if "https://graph.microsoft.com/beta/settings"
            .values | where-object name -eq 'LockoutDurationInSeconds' | select-object -expand value -ge '60'
        #>
        Test-MtEidscaControl -CheckId PR05 | Should -BeGreaterOrEqual '60'
    }
}
Describe "Default Settings - Password Rule Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.PR06" {
    It "EIDSCA.PR06: Default Settings - Password Rule Settings - Smart Lockout - Lockout threshold. See https://maester.dev/docs/tests/EIDSCA.PR06" {
        <#
            Check if "https://graph.microsoft.com/beta/settings"
            .values | where-object name -eq 'LockoutThreshold' | select-object -expand value -eq '10'
        #>
        Test-MtEidscaControl -CheckId PR06 | Should -Be '10'
    }
}

Describe "Default Settings - Classification and M365 Groups" -Tag "EIDSCA", "Security", "All", "EIDSCA.ST08" {
    It "EIDSCA.ST08: Default Settings - Classification and M365 Groups - M365 groups - Allow Guests to become Group Owner. See https://maester.dev/docs/tests/EIDSCA.ST08" {
        <#
            Check if "https://graph.microsoft.com/beta/settings"
            .values | where-object name -eq 'AllowGuestsToBeGroupOwner' | select-object -expand value -eq 'false'
        #>
        Test-MtEidscaControl -CheckId ST08 | Should -Be 'false'
    }
}
Describe "Default Settings - Classification and M365 Groups" -Tag "EIDSCA", "Security", "All", "EIDSCA.ST09" {
    It "EIDSCA.ST09: Default Settings - Classification and M365 Groups - M365 groups - Allow Guests to have access to groups content. See https://maester.dev/docs/tests/EIDSCA.ST09" {
        <#
            Check if "https://graph.microsoft.com/beta/settings"
            .values | where-object name -eq 'AllowGuestsToAccessGroups' | select-object -expand value -eq 'True'
        #>
        Test-MtEidscaControl -CheckId ST09 | Should -Be 'True'
    }
}

Describe "Authentication Method - General Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.AG01" {
    It "EIDSCA.AG01: Authentication Method - General Settings - Manage migration. See https://maester.dev/docs/tests/EIDSCA.AG01" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy"
            .policyMigrationState -eq 'migrationComplete'
        #>
        Test-MtEidscaControl -CheckId AG01 | Should -Be 'migrationComplete'
    }
}
Describe "Authentication Method - General Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.AG02" {
    It "EIDSCA.AG02: Authentication Method - General Settings - Report suspicious activity - State. See https://maester.dev/docs/tests/EIDSCA.AG02" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy"
            .reportSuspiciousActivitySettings.state -eq 'enabled'
        #>
        Test-MtEidscaControl -CheckId AG02 | Should -Be 'enabled'
    }
}
Describe "Authentication Method - General Settings" -Tag "EIDSCA", "Security", "All", "EIDSCA.AG03" {
    It "EIDSCA.AG03: Authentication Method - General Settings - Report suspicious activity - Included users/groups. See https://maester.dev/docs/tests/EIDSCA.AG03" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy"
            .reportSuspiciousActivitySettings.includeTarget.id -eq 'all_users'
        #>
        Test-MtEidscaControl -CheckId AG03 | Should -Be 'all_users'
    }
}

Describe "Authentication Method - Microsoft Authenticator" -Tag "EIDSCA", "Security", "All", "EIDSCA.AM01" {
    It "EIDSCA.AM01: Authentication Method - Microsoft Authenticator - State. See https://maester.dev/docs/tests/EIDSCA.AM01" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('MicrosoftAuthenticator')"
            .state -eq 'enabled'
        #>
        Test-MtEidscaControl -CheckId AM01 | Should -Be 'enabled'
    }
}
Describe "Authentication Method - Microsoft Authenticator" -Tag "EIDSCA", "Security", "All", "EIDSCA.AM02" {
    It "EIDSCA.AM02: Authentication Method - Microsoft Authenticator - Allow use of Microsoft Authenticator OTP. See https://maester.dev/docs/tests/EIDSCA.AM02" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('MicrosoftAuthenticator')"
            .isSoftwareOathEnabled -eq 'true'
        #>
        Test-MtEidscaControl -CheckId AM02 | Should -Be 'true'
    }
}
Describe "Authentication Method - Microsoft Authenticator" -Tag "EIDSCA", "Security", "All", "EIDSCA.AM03" {
    It "EIDSCA.AM03: Authentication Method - Microsoft Authenticator - Require number matching for push notifications. See https://maester.dev/docs/tests/EIDSCA.AM03" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('MicrosoftAuthenticator')"
            .featureSettings.numberMatchingRequiredState.state -eq 'enabled'
        #>
        Test-MtEidscaControl -CheckId AM03 | Should -Be 'enabled'
    }
}
Describe "Authentication Method - Microsoft Authenticator" -Tag "EIDSCA", "Security", "All", "EIDSCA.AM04" {
    It "EIDSCA.AM04: Authentication Method - Microsoft Authenticator - Included users/groups of number matching for push notifications. See https://maester.dev/docs/tests/EIDSCA.AM04" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('MicrosoftAuthenticator')"
            .featureSettings.numberMatchingRequiredState.includeTarget.id -eq 'all_users'
        #>
        Test-MtEidscaControl -CheckId AM04 | Should -Be 'all_users'
    }
}
Describe "Authentication Method - Microsoft Authenticator" -Tag "EIDSCA", "Security", "All", "EIDSCA.AM06" {
    It "EIDSCA.AM06: Authentication Method - Microsoft Authenticator - Show application name in push and passwordless notifications. See https://maester.dev/docs/tests/EIDSCA.AM06" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('MicrosoftAuthenticator')"
            .featureSettings.displayAppInformationRequiredState.state -eq 'enabled'
        #>
        Test-MtEidscaControl -CheckId AM06 | Should -Be 'enabled'
    }
}
Describe "Authentication Method - Microsoft Authenticator" -Tag "EIDSCA", "Security", "All", "EIDSCA.AM07" {
    It "EIDSCA.AM07: Authentication Method - Microsoft Authenticator - Included users/groups to show application name in push and passwordless notifications. See https://maester.dev/docs/tests/EIDSCA.AM07" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('MicrosoftAuthenticator')"
            .featureSettings.displayAppInformationRequiredState.includeTarget.id -eq 'all_users'
        #>
        Test-MtEidscaControl -CheckId AM07 | Should -Be 'all_users'
    }
}
Describe "Authentication Method - Microsoft Authenticator" -Tag "EIDSCA", "Security", "All", "EIDSCA.AM09" {
    It "EIDSCA.AM09: Authentication Method - Microsoft Authenticator - Show geographic location in push and passwordless notifications. See https://maester.dev/docs/tests/EIDSCA.AM09" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('MicrosoftAuthenticator')"
            .featureSettings.displayLocationInformationRequiredState.state -eq 'enabled'
        #>
        Test-MtEidscaControl -CheckId AM09 | Should -Be 'enabled'
    }
}
Describe "Authentication Method - Microsoft Authenticator" -Tag "EIDSCA", "Security", "All", "EIDSCA.AM10" {
    It "EIDSCA.AM10: Authentication Method - Microsoft Authenticator - Included users/groups to show geographic location in push and passwordless notifications. See https://maester.dev/docs/tests/EIDSCA.AM10" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('MicrosoftAuthenticator')"
            .featureSettings.displayLocationInformationRequiredState.includeTarget.id -eq 'all_users'
        #>
        Test-MtEidscaControl -CheckId AM10 | Should -Be 'all_users'
    }
}

Describe "Authentication Method - FIDO2 security key" -Tag "EIDSCA", "Security", "All", "EIDSCA.AF01" {
    It "EIDSCA.AF01: Authentication Method - FIDO2 security key - State. See https://maester.dev/docs/tests/EIDSCA.AF01" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Fido2')"
            .state -eq 'enabled'
        #>
        Test-MtEidscaControl -CheckId AF01 | Should -Be 'enabled'
    }
}
Describe "Authentication Method - FIDO2 security key" -Tag "EIDSCA", "Security", "All", "EIDSCA.AF02" {
    It "EIDSCA.AF02: Authentication Method - FIDO2 security key - Allow self-service set up. See https://maester.dev/docs/tests/EIDSCA.AF02" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Fido2')"
            .isSelfServiceRegistrationAllowed -eq 'true'
        #>
        Test-MtEidscaControl -CheckId AF02 | Should -Be 'true'
    }
}
Describe "Authentication Method - FIDO2 security key" -Tag "EIDSCA", "Security", "All", "EIDSCA.AF03" {
    It "EIDSCA.AF03: Authentication Method - FIDO2 security key - Enforce attestation. See https://maester.dev/docs/tests/EIDSCA.AF03" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Fido2')"
            .isAttestationEnforced -eq 'true'
        #>
        Test-MtEidscaControl -CheckId AF03 | Should -Be 'true'
    }
}
Describe "Authentication Method - FIDO2 security key" -Tag "EIDSCA", "Security", "All", "EIDSCA.AF04" {
    It "EIDSCA.AF04: Authentication Method - FIDO2 security key - Enforce key restrictions. See https://maester.dev/docs/tests/EIDSCA.AF04" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Fido2')"
            .keyRestrictions.isEnforced -eq 'true'
        #>
        Test-MtEidscaControl -CheckId AF04 | Should -Be 'true'
    }
}
Describe "Authentication Method - FIDO2 security key" -Tag "EIDSCA", "Security", "All", "EIDSCA.AF05" {
    It "EIDSCA.AF05: Authentication Method - FIDO2 security key - Restricted. See https://maester.dev/docs/tests/EIDSCA.AF05" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Fido2')"
            .keyRestrictions.aaGuids -notcontains $null -eq 'true'
        #>
        Test-MtEidscaControl -CheckId AF05 | Should -Be 'true'
    }
}
Describe "Authentication Method - FIDO2 security key" -Tag "EIDSCA", "Security", "All", "EIDSCA.AF06" {
    It "EIDSCA.AF06: Authentication Method - FIDO2 security key - Restrict specific keys. See https://maester.dev/docs/tests/EIDSCA.AF06" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Fido2')"
            .keyRestrictions.aaGuids -notcontains $null -and ($result.keyRestrictions.enforcementType -eq 'allow' -or $result.keyRestrictions.enforcementType -eq 'block') -eq 'true'
        #>
        Test-MtEidscaControl -CheckId AF06 | Should -Be 'true'
    }
}

Describe "Authentication Method - Temporary Access Pass" -Tag "EIDSCA", "Security", "All", "EIDSCA.AT01" {
    It "EIDSCA.AT01: Authentication Method - Temporary Access Pass - State. See https://maester.dev/docs/tests/EIDSCA.AT01" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('TemporaryAccessPass')"
            .state -eq 'enabled'
        #>
        Test-MtEidscaControl -CheckId AT01 | Should -Be 'enabled'
    }
}
Describe "Authentication Method - Temporary Access Pass" -Tag "EIDSCA", "Security", "All", "EIDSCA.AT02" {
    It "EIDSCA.AT02: Authentication Method - Temporary Access Pass - One-time. See https://maester.dev/docs/tests/EIDSCA.AT02" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('TemporaryAccessPass')"
            .isUsableOnce -eq 'true'
        #>
        Test-MtEidscaControl -CheckId AT02 | Should -Be 'true'
    }
}

Describe "Authentication Method - Voice call" -Tag "EIDSCA", "Security", "All", "EIDSCA.AV01" {
    It "EIDSCA.AV01: Authentication Method - Voice call - State. See https://maester.dev/docs/tests/EIDSCA.AV01" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Voice')"
            .state -eq 'disabled'
        #>
        Test-MtEidscaControl -CheckId AV01 | Should -Be 'disabled'
    }
}

Describe "Authentication Method - SMS" -Tag "EIDSCA", "Security", "All", "EIDSCA.AS04" {
    It "EIDSCA.AS04: Authentication Method - SMS - Use for sign-in. See https://maester.dev/docs/tests/EIDSCA.AS04" -TestCases @{ EnabledAuthMethods = $EnabledAuthMethods } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Sms')"
            .includeTargets.isUsableForSignIn -eq 'false'
        #>
        Test-MtEidscaControl -CheckId AS04 | Should -Be 'false'
    }
}

Describe "Consent Framework - Admin Consent Request" -Tag "EIDSCA", "Security", "All", "EIDSCA.CR01" {
    It "EIDSCA.CR01: Consent Framework - Admin Consent Request - Policy to enable or disable admin consent request feature. See https://maester.dev/docs/tests/EIDSCA.CR01" {
        <#
            Check if "https://graph.microsoft.com/beta/policies/adminConsentRequestPolicy"
            .isEnabled -eq 'true'
        #>
        Test-MtEidscaControl -CheckId CR01 | Should -Be 'true'
    }
}
Describe "Consent Framework - Admin Consent Request" -Tag "EIDSCA", "Security", "All", "EIDSCA.CR02" {
    It "EIDSCA.CR02: Consent Framework - Admin Consent Request - Reviewers will receive email notifications for requests. See https://maester.dev/docs/tests/EIDSCA.CR02" -TestCases @{ EnabledAdminConsentWorkflow = ($EnabledAdminConsentWorkflow) } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/adminConsentRequestPolicy"
            .notifyReviewers -eq 'true'
        #>
        Test-MtEidscaControl -CheckId CR02 | Should -Be 'true'
    }
}
Describe "Consent Framework - Admin Consent Request" -Tag "EIDSCA", "Security", "All", "EIDSCA.CR03" {
    It "EIDSCA.CR03: Consent Framework - Admin Consent Request - Reviewers will receive email notifications when admin consent requests are about to expire. See https://maester.dev/docs/tests/EIDSCA.CR03" -TestCases @{ EnabledAdminConsentWorkflow = ($EnabledAdminConsentWorkflow) } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/adminConsentRequestPolicy"
            .remindersEnabled -eq 'true'
        #>
        Test-MtEidscaControl -CheckId CR03 | Should -Be 'true'
    }
}
Describe "Consent Framework - Admin Consent Request" -Tag "EIDSCA", "Security", "All", "EIDSCA.CR04" {
    It "EIDSCA.CR04: Consent Framework - Admin Consent Request - Consent request duration (days). See https://maester.dev/docs/tests/EIDSCA.CR04" -TestCases @{ EnabledAdminConsentWorkflow = ($EnabledAdminConsentWorkflow) } {
        <#
            Check if "https://graph.microsoft.com/beta/policies/adminConsentRequestPolicy"
            .requestDurationInDays -le '30'
        #>
        Test-MtEidscaControl -CheckId CR04 | Should -BeLessOrEqual '30'
    }
}



# SIG # Begin signature block
# MIIuqgYJKoZIhvcNAQcCoIIumzCCLpcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDlaF5nNnBgEkNc
# jTVrJMbJlfnTbieaoPECMD3Ppyib9aCCE5QwggWQMIIDeKADAgECAhAFmxtXno4h
# MuI5B72nd3VcMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0xMzA4MDExMjAwMDBaFw0z
# ODAxMTUxMjAwMDBaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/z
# G6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZ
# anMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7s
# Wxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL
# 2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfb
# BHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3
# JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3c
# AORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqx
# YxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0
# viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aL
# T8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjQjBAMA8GA1Ud
# EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzANBgkqhkiG9w0BAQwFAAOCAgEAu2HZfalsvhfEkRvDoaIAjeNk
# aA9Wz3eucPn9mkqZucl4XAwMX+TmFClWCzZJXURj4K2clhhmGyMNPXnpbWvWVPjS
# PMFDQK4dUPVS/JA7u5iZaWvHwaeoaKQn3J35J64whbn2Z006Po9ZOSJTROvIXQPK
# 7VB6fWIhCoDIc2bRoAVgX+iltKevqPdtNZx8WorWojiZ83iL9E3SIAveBO6Mm0eB
# cg3AFDLvMFkuruBx8lbkapdvklBtlo1oepqyNhR6BvIkuQkRUNcIsbiJeoQjYUIp
# 5aPNoiBB19GcZNnqJqGLFNdMGbJQQXE9P01wI4YMStyB0swylIQNCAmXHE/A7msg
# dDDS4Dk0EIUhFQEI6FUy3nFJ2SgXUE3mvk3RdazQyvtBuEOlqtPDBURPLDab4vri
# RbgjU2wGb2dVf0a1TD9uKFp5JtKkqGKX0h7i7UqLvBv9R0oN32dmfrJbQdA75PQ7
# 9ARj6e/CVABRoIoqyc54zNXqhwQYs86vSYiv85KZtrPmYQ/ShQDnUBrkG5WdGaG5
# nLGbsQAe79APT0JsyQq87kP6OnGlyE0mpTX9iV28hWIdMtKgK1TtmlfB2/oQzxm3
# i0objwG2J5VT6LaJbVu8aNQj6ItRolb58KaAoNYes7wPD1N1KarqE3fk3oyBIa0H
# EEcRrYc9B9F1vM/zZn4wggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67ZMA0G
# CSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTla
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVtC9C
# 0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0F9ce
# 2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lvy0da
# E6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrMxe6T
# SXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vkunKoA
# FdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNHR7Oh
# D26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/rJvmM
# 1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i4F4z
# 8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyDKK05
# huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgRQRNY
# mtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhFMJlP
# /2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHwYD
# VR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNV
# HR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATAN
# BgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm95Ry
# sQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+N3HL
# IvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE5Btf
# Q/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4ImhvTnh
# OE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KVssIh
# dXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwfiThV
# 9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSchh/j
# wVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3xGFYH
# Ki8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJsQfmC
# XBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pKHJ6l
# /aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52MbOoZW
# eE4wggdIMIIFMKADAgECAhAKgjCQR6s2I8rDH7I9rOuaMA0GCSqGSIb3DQEBCwUA
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwHhcNMjIwNTE4MDAwMDAwWhcNMjUwNTE3MjM1OTU5WjBNMQsw
# CQYDVQQGEwJERTEQMA4GA1UEBxMHSGFtYnVyZzEVMBMGA1UEChMMRmFiaWFuIEJh
# ZGVyMRUwEwYDVQQDEwxGYWJpYW4gQmFkZXIwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQDBI8VJts4gUJjzaL//82nAioe/sYkIOqO74ImDtMCiMNXYINLP
# vao3Y9iNXlqd+H+N4lUa0DsGsJ4paQvNUf0/ilbnaO4SHBF7t9u/uz4+SlOEsF3B
# BeH8kcReki/2MuQ4YfdjGvGghLlt2fMp+7JSvyon8n5Tpr1KCQ6QU0zqkYcUZjZO
# xEDzAyNN2mFgZMp/nzmEfiYPv8arV1vvYhAOmigpdg9mhtD4sC4u0X9GBNUfVi2D
# /rWZ3bylXflDJm6MBxyhgmOANbN5zHs7tx1i7ACWw9+Hov5gVU7H0vK5pUVCDrDr
# d7UM1gSC4iY+Xq1a0Aw4eaBfF3hrjD8fS29SSqM4fkrh1TgJaZwhKeR2Hax0c3DH
# yCN9h7dPClbGUU5TUcRp7ocA0Xq1W0jJWFBHBLsnUM0k7Uog4ZkMGEqGI+SWvXtY
# ydHl5gQI51xpyQcNP3JkndAeRPQYxrcqdlJHnpGE5vPs0fyWUlFJn/bLMM48CGIU
# 6sqNk9hgvxHnbjxmTE7FtMlalOFbnd0o8zpv02i2qIlbmu7h45WrTKNIx208u21A
# C7ocS00ojX3QCK/lc89BgzIjU8dUtjmxXumbfqEiljkRbbcecmzfTbgCIXjkU3Wb
# EeVSSbtz4Jiw0BufJEmUhxTIXXbVqQU1W4ZBTBshCe2ZChr+TF3++ljakQIDAQAB
# o4ICBjCCAgIwHwYDVR0jBBgwFoAUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHQYDVR0O
# BBYEFPUKlMJ9lsMeVu5KQOaYqYXKAg45MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
# DDAKBggrBgEFBQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZT
# SEEzODQyMDIxQ0ExLmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNB
# MS5jcmwwPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDov
# L3d3dy5kaWdpY2VydC5jb20vQ1BTMIGUBggrBgEFBQcBAQSBhzCBhDAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFwGCCsGAQUFBzAChlBodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2ln
# bmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqG
# SIb3DQEBCwUAA4ICAQAJwchVKGCBGuhUPGL5IN8k6pUzZn3ZPbli/zHJYYxSbXhs
# YQ4GCd8eIhQmYr0GmbST+GdgSlXkiWXz9F/bSX7K+XBOPWbiy3ZGvhzzhFIaatbz
# eaRjEyGDlgu0uJl1p80JyS737bp2BnnfsrtgOEa4h5aDvTxVyECcMRvwKWKpYxgv
# Doni9qBD3UTl6Y+mrsWEOzao0wSWeuNZQuNCRhEaUN/DbYBymy0KsQGRz7XxZmXo
# EPY7DUPXCExXo/XjvZmBNyjo9ynwEqGuqihRerYIPBhclv+IU3BGe7sKzvy752Uu
# 76xc3Gxsa49P0iD7k68LUWIcx45rhpLwdlKlNu7jDxxyUv0R1eqWBVcULY+UOKv/
# Zb1WP2zq2JKneF2Uft0g7kURCHwkut08XApdnx2uC8/box/XWMK/KQz5BCb2OEH9
# WECfCKySBSh0iR+jHRGMm0JCQ1PWheolUSvAGqX8hVBQ1AJHtDt8DxTaNTwUFORi
# vJRABBogSrFq/dz4aoz3hOHcLkW+s67gJTbz8dm5ONlkIE/uzYRb//htFRBKdcHi
# ZqzNRH7/xH5tf77J8f867UdAvloaj2rYvfqhpUWNozbzbDWnMUARR/SOClSQF4k4
# VR4W+KthbKp7H6grDLxXOCz4Ep3sU5KEtrvAJqLV+N9i+k7sbFul1gmpqc0yYDGC
# GmwwghpoAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBS
# U0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQCoIwkEerNiPKwx+yPazrmjANBglghkgB
# ZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJ
# AzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8G
# CSqGSIb3DQEJBDEiBCC2BaBuyrG5bfy1vXesECo7XzV9qmeuULTvfekb2nldqjAN
# BgkqhkiG9w0BAQEFAASCAgBRGrV+ym/ovwya3m0sxU3mu1nzb+w90r9ARvBokvcA
# wKfx1ZD1MJ4Bmi3IsrP3IbLvq9j7mrY9dYTrk9grCtY3zF0o4qBqHUEJS/0hpZ+A
# cqqsNbPcwRL1PBhRubKG0IcSjw4qjSV0vbPP8Qx3lstJOFKzDQbKrcvHccQnyBPK
# dfZ1SoQf0rlDWkVivVC3M8ZTpERK6NFCXfZs0SzpKYmzv3CBpaRVVRQjO0Lf3LN6
# dIprYzbvNPt66m+FnyaPxjkypdjRwpSUbTfBb2AkcUyHhp7XUwip6xattykJAVKJ
# ekSYl2J7jzmYCqt1dLZ7smZhwYOmmmhAThwIGGqoL5o/kDiaUsice7TaI1d5Iuu8
# sHzGRWn9AhYJtY8Tk+j0jYt32XUBgy5qhbKNwLli+RWKLLRsK6+sx0vdVb9QchR+
# 1+GbRsp5Ovij+NJTBuv1CebTGLLNmG3SByHjxmpcqQfiyZj+cG+AagCunftpXKo2
# iJ0w3CAfRYv2QpT/Hb5ls+fcFRhYVvAULphhu9pNBhjsSvVpWH4Aou4rOseNe6CW
# d7r2COFgT8zMWOfjLU7yru06phJoQpqqKbDGT3nEzZ4QllFJlRS8iYjwgceoH8/D
# EJNcxqMbTygjqPcbdLiB6/JB5dx3MNqf42FktAxJSlgj5Omgiv090G1MJzHJzeL5
# SaGCFzkwghc1BgorBgEEAYI3AwMBMYIXJTCCFyEGCSqGSIb3DQEHAqCCFxIwghcO
# AgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCG
# SAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCDxmdPMAoB80QO6/gQDsFPp9nW/S2Ey
# 0CPX19YeP1xS0gIQSd3lbrH5f+CLbtT8vBjULhgPMjAyNDEyMTExMjQ5MTBaoIIT
# AzCCBrwwggSkoAMCAQICEAuuZrxaun+Vh8b56QTjMwQwDQYJKoZIhvcNAQELBQAw
# YzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQD
# EzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGlu
# ZyBDQTAeFw0yNDA5MjYwMDAwMDBaFw0zNTExMjUyMzU5NTlaMEIxCzAJBgNVBAYT
# AlVTMREwDwYDVQQKEwhEaWdpQ2VydDEgMB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0
# YW1wIDIwMjQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+anOf9pUh
# q5Ywultt5lmjtej9kR8YxIg7apnjpcH9CjAgQxK+CMR0Rne/i+utMeV5bUlYYSuu
# M4vQngvQepVHVzNLO9RDnEXvPghCaft0djvKKO+hDu6ObS7rJcXa/UKvNminKQPT
# v/1+kBPgHGlP28mgmoCw/xi6FG9+Un1h4eN6zh926SxMe6We2r1Z6VFZj75MU/HN
# mtsgtFjKfITLutLWUdAoWle+jYZ49+wxGE1/UXjWfISDmHuI5e/6+NfQrxGFSKx+
# rDdNMsePW6FLrphfYtk/FLihp/feun0eV+pIF496OVh4R1TvjQYpAztJpVIfdNsE
# vxHofBf1BWkadc+Up0Th8EifkEEWdX4rA/FE1Q0rqViTbLVZIqi6viEk3RIySho1
# XyHLIAOJfXG5PEppc3XYeBH7xa6VTZ3rOHNeiYnY+V4j1XbJ+Z9dI8ZhqcaDHOoj
# 5KGg4YuiYx3eYm33aebsyF6eD9MF5IDbPgjvwmnAalNEeJPvIeoGJXaeBQjIK13S
# lnzODdLtuThALhGtyconcVuPI8AaiCaiJnfdzUcb3dWnqUnjXkRFwLtsVAxFvGqs
# xUA2Jq/WTjbnNjIUzIs3ITVC6VBKAOlb2u29Vwgfta8b2ypi6n2PzP0nVepsFk8n
# lcuWfyZLzBaZ0MucEdeBiXL+nUOGhCjl+QIDAQABo4IBizCCAYcwDgYDVR0PAQH/
# BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYD
# VR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1N
# hS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSfVywDdw4oFZBmpWNe7k+SH3agWzBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggr
# BgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0G
# CSqGSIb3DQEBCwUAA4ICAQA9rR4fdplb4ziEEkfZQ5H2EdubTggd0ShPz9Pce4FL
# Jl6reNKLkZd5Y/vEIqFWKt4oKcKz7wZmXa5VgW9B76k9NJxUl4JlKwyjUkKhk3aY
# x7D8vi2mpU1tKlY71AYXB8wTLrQeh83pXnWwwsxc1Mt+FWqz57yFq6laICtKjPIC
# YYf/qgxACHTvypGHrC8k1TqCeHk6u4I/VBQC9VK7iSpU5wlWjNlHlFFv/M93748Y
# TeoXU/fFa9hWJQkuzG2+B7+bMDvmgF8VlJt1qQcl7YFUMYgZU1WM6nyw23vT6QSg
# wX5Pq2m0xQ2V6FJHu8z4LXe/371k5QrN9FQBhLLISZi2yemW0P8ZZfx4zvSWzVXp
# Ab9k4Hpvpi6bUe8iK6WonUSV6yPlMwerwJZP/Gtbu3CKldMnn+LmmRTkTXpFIEB0
# 6nXZrDwhCGED+8RsWQSIXZpuG4WLFQOhtloDRWGoCwwc6ZpPddOFkM2LlTbMcqFS
# zm4cd0boGhBq7vkqI1uHRz6Fq1IX7TaRQuR+0BGOzISkcqwXu7nMpFu3mgrlgbAW
# +BzikRVQ3K2YHcGkiKjA4gi4OA/kz1YCsdhIBHXqBzR0/Zd2QwQ/l4Gxftt/8wY3
# grcc/nS//TVkej9nmUYu83BDtccHHXKibMs/yXHhDXNkoPIdynhVAku7aRZOwqw6
# pDCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBU
# cnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh
# 1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+Feo
# An39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1
# decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxnd
# X7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6
# Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPj
# Q2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlREr
# WHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JM
# q++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh
# 3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8j
# u2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnS
# DmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# dwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAG
# A1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOC
# AgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp
# /GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40B
# IiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2d
# fNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibB
# t94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7
# T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZA
# myEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdB
# eHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnK
# cPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/
# pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yY
# lvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggWNMIIEdaADAgEC
# AhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4
# MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQAD
# ggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVir
# dprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcW
# WVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5O
# yJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7K
# e13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1
# gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn
# 3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7n
# DmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIR
# t7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEd
# slQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j
# 7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMB
# AAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNV
# HQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8v
# b2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4w
# PDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQAD
# ggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3
# bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP
# 0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZ
# NUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPL
# ILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9
# W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN2MIIDcgIBATB3MGMxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1
# c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAuuZrxaun+V
# h8b56QTjMwQwDQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
# DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDEyMTExMjQ5MTBaMCsGCyqGSIb3DQEJ
# EAIMMRwwGjAYMBYEFNvThe5i29I+e+T2cUhQhyTVhltFMC8GCSqGSIb3DQEJBDEi
# BCBR/Ev9DUX0u5C7/fWcs2aLNi+dSn7rNxL/Mg7DyxVspzA3BgsqhkiG9w0BCRAC
# LzEoMCYwJDAiBCB2dp+o8mMvH0MLOiMwrtZWdf7Xc9sF1mW5BZOYQ4+a2zANBgkq
# hkiG9w0BAQEFAASCAgCnBr0TYQTIfvAA1f0tLVcopCVXgev+eeJfvgMhHORHLVCv
# hcqFYtLO3DKF+80JSG1LOAHfufJqTerl+a2vR1QrCNbdXYBTfIVyF3IzYw51I1I+
# XsuK1i+GQuxE4Bp29yZhAM0yxGIJrH0mhgnYNM0fRiHJU03B7GB9Zdq/tdP23mz8
# 4y5ENT9cjJuRsTcPcHbrS78BEuN41/V1PxY0lHicC4rZWDsGCsw5nWBlXjcNcAiw
# vUdaigG8c4zxsDJKjQkJRm/2MT7txght5QhbxhZt7WMdiYZMk/hdnNx1e7adWTZF
# xUTR/cQC0lw9vAaePZzF5Ms6jwWoSQlS70mkOEI7Krn+GYB3JZ2rhjBiZoOsNCDo
# sH4oASFT3bNQFLOt35RNen/yV95LiGfbAOeY7MUkaGDQqswsiWdlYGKOrhBmYDxr
# wGSrjtEowcqyVbJobVFWs/nVZ9z+RXiC/E7dF3riyDBApxFroFx93zRln1S5f9Ig
# UXSbmlFmaVpylmdS88tL49oVTbH2m91ClZkXUYH67Ziq02LI13Xdj0533AEw0QX/
# 9eXqnp1ZGJEQ5M6ExVO8NoDN+V4gU+4HJlCV+9F+PKF/9wWS7TZ4A9hJlgrxM2Mq
# RaCDX9eTFGGW4j0rrwn+VIU3v8/CkFOzCKx/gU/SEsoyD606l6HIjvF/36R05Q==
# SIG # End signature block
