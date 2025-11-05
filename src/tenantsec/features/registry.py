from __future__ import annotations
from typing import List
from tenantsec.review.rules import Rule
from tenantsec.features.org_config.rules_org import RuleSecurityDefaultsCompensated, RuleSsprConfigured

from tenantsec.features.org_config.rules_org import (
    RuleSecurityDefaultsCompensated,
    RuleSsprConfigured,        
)

from tenantsec.features.mfa_enforcement.rules import RuleMfaForAdminsNoExcludes
from tenantsec.features.legacy_auth.rules import RuleBlockLegacyAuth
from tenantsec.features.conditional_access.rules_org import (
    RuleMfaAllUsers, RuleUnknownLocationsStepUpOrBlock,
    RuleSessionControlsConfigured, RuleAdminAuthStrength,
)


from tenantsec.features.intune_policies.rules_org import (
    RuleBaselinePoliciesPresent,
    RuleJailbreakBlock,
    RuleRequireCompliantDevice,
)

from tenantsec.features.conditional_access.rules_expand import (
    RuleMfaForRiskySignIns,
    RuleGuestMfaRequired,
    RuleDisabledPolicyAudit,
    RuleDeviceComplianceEnforced,
    RuleStalePolicies,
    RuleExcessiveExclusions,
)


from tenantsec.features.admin_roles.rules_org import (
    RuleGlobalAdminCount,
    RuleAdminsWithoutMfa,
    RuleEmergencyAccounts,
)

from tenantsec.features.exchange.rules_org import (
    RuleExternalForwardingBlocked,
    RuleLegacyAuthDisabled,
    RuleMalwarePolicyStrict,
)
from tenantsec.features.oauth_apps.rules_org import (
    RuleOverPrivilegedApps,
    RuleUnusedAppSecrets,
    RuleUserConsentRisky,
)

def ca_rule_set() -> List[Rule]:
    return [
        RuleMfaForAdminsNoExcludes(
            id="ca.mfa.admins.strict",
            title="Require MFA for admin roles (no exclusions)",
            severity="high", weight=8,
            description="At least one enabled CA policy must require MFA for privileged roles and contain no user/group/role exclusions.",
            remediation="Create a CA policy targeting admin roles with 'Require multifactor authentication' and remove exclusions.",
            docs="https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa",
            tags=["ca","mfa","identity"],
        ),
        RuleBlockLegacyAuth(
            id="ca.legacy.block",
            title="Block legacy (basic) authentication",
            severity="high", weight=7,
            description="Ensure legacy client apps (EAS/Other) are blocked by an enabled CA policy.",
            remediation="Create CA policies that include legacy client app types and block access.",
            docs="https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-conditions#client-apps",
            tags=["ca","legacy","identity"],
        ),
        RuleMfaAllUsers(
            id="ca.mfa.all_users",
            title="Require MFA for all users (allow minimal excludes)",
            severity="high", weight=7,
            description="An enabled CA policy should require MFA for all users. Small break-glass exclusions are acceptable but flagged.",
            remediation="Create a CA policy with includeUsers=All and Grant: MFA; keep exclusions to a minimum.",
            tags=["ca","mfa","org"],
        ),
        RuleUnknownLocationsStepUpOrBlock(
            id="ca.locations.stepup",
            title="Unknown locations require MFA or are blocked",
            severity="medium", weight=5,
            description="Access from non-trusted locations must be blocked or require MFA.",
            remediation="Configure CA: includeLocations=All, excludeLocations=AllTrusted; Grant: MFA or block.",
            tags=["ca","locations","org"],
        ),
        RuleSessionControlsConfigured(
            id="ca.session.controls",
            title="Session controls configured (sign-in frequency / persistent browser)",
            severity="medium", weight=4,
            description="Set sign-in frequency and disable persistent browser for tighter session management.",
            remediation="Enable Sign-in frequency and set Persistent browser to 'Never' on sensitive policies.",
            tags=["ca","session","org"],
        ),
        RuleAdminAuthStrength(
            id="ca.mfa.admins.authstrength",
            title="Admins protected by Authentication Strength (phishing-resistant)",
            severity="high", weight=7,
            description="Privileged roles should require strong MFAs via Authentication Strength.",
            remediation="Use Authentication Strength (phishing-resistant) for admin CA policies.",
            tags=["ca","mfa","authstrength","org"],
        ),

        RuleMfaForRiskySignIns(
            id="ca.mfa.risky_signins",
            title="Require MFA for risky sign-ins",
            severity="high", weight=7,
            description="Policies responding to risky sign-ins must enforce MFA or block access.",
            remediation="Create a CA policy with signInRiskLevels or userRiskLevels set and Grant: MFA or Block.",
            tags=["ca","risk","mfa"],
        ),
        RuleGuestMfaRequired(
            id="ca.mfa.guests",
            title="Require MFA for guest/external users",
            severity="medium", weight=6,
            description="Guests should always require MFA or step-up authentication.",
            remediation="Create a CA policy targeting Guests/External users with MFA required.",
            tags=["ca","guest","mfa"],
        ),
        RuleDisabledPolicyAudit(
            id="ca.disabled.audit",
            title="Disabled important Conditional Access policies",
            severity="medium", weight=5,
            description="Detect disabled CA policies whose names indicate MFA/admin/legacy functions.",
            remediation="Re-enable or replace critical CA policies marked disabled.",
            tags=["ca","audit","org"],
        ),
        RuleDeviceComplianceEnforced(
            id="ca.devices.compliance",
            title="Enforce device compliance or hybrid join",
            severity="high", weight=8,
            description="Enforce device compliance or hybrid join conditions for access policies.",
            remediation="Set 'deviceFilter' to 'compliant' or 'hybrid' for all applicable policies.",
            tags=["ca","devices","compliance","org"],
        ),
        RuleStalePolicies(
            id="ca.stale.policies",
            title="Audit stale policies (not modified in 180 days)",
            severity="medium", weight=4,
            description="Ensure that policies are updated and relevant; stale policies pose a risk.",
            remediation="Review and re-enable/modify stale policies, or delete them.",
            tags=["ca","audit","org"],
        ),
        RuleExcessiveExclusions(
            id="ca.excessive.exclusions",
            title="Excessive exclusions in Conditional Access policies",
            severity="medium", weight=5,
            description="Excessive exclusions in CA policies reduce their effectiveness.",
            remediation="Limit exclusions (users/groups/roles) to a minimum and re-evaluate.",
            tags=["ca","audit","org"],
        ),
    ]

def admin_roles_rule_set() -> List[Rule]:
    return [
        RuleGlobalAdminCount(
            id="roles.ga.count",
            title="Global Administrator count within recommended limit (≤ 2)",
            severity="high", weight=6,
            description="Limit the number of GA accounts to reduce attack surface.",
            remediation="Reduce GA membership to ≤ 2; use PIM for elevation.",
            tags=["roles","org"],
        ),

        RuleAdminsWithoutMfa(
            id="roles.admins.mfa",
            title="Admins without strong MFA",
            severity="critical", weight=9,
            description="Any admin without strong MFA is a critical risk.",
            remediation="Require MFA enrollment and apply strict CA policies.",
            tags=["roles","mfa","org"],
        ),

        RuleEmergencyAccounts(
            id="roles.emergency_accounts",
            title="Emergency (break-glass) accounts are present and controlled",
            severity="medium", weight=5,
            description="Expect 1–2 break-glass accounts with strict controls, not used in normal operations.",
            remediation="Create 1–2 emergency accounts, exclude only from admin-MFA policy, store creds offline, monitor usage.",
            tags=["roles","org","breakglass"],
        ),
    ]

def org_config_rule_set() -> List[Rule]:
    return [
        RuleSecurityDefaultsCompensated(
            id="org.security_defaults",
            title="Security Defaults off → compensating CA MFA in place",
            severity="high",
            weight=7,
            description="If Security Defaults are disabled, you must enforce MFA via Conditional Access for all users and admins.",
            remediation="Enable Security Defaults OR ensure CA policies require MFA for all users and privileged roles.",
            tags=["org","defaults","mfa"],
        ),
        RuleSsprConfigured(
            id="org.sspr",
            title="SSPR enabled and gated by MFA",
            severity="medium",
            weight=4,
            description="Enable SSPR and require MFA for resets.",
            remediation="In Entra ID > Password reset, enable SSPR and require MFA.",
            tags=["org","sspr"],
        ),
    ]

def oauth_rule_set() -> List[Rule]:
    return [
        RuleOverprivilegedApps(
            id="oauth.overprivileged_apps",
            title="Over-privileged OAuth apps",
            severity="high", weight=8,
            description="Detect OAuth apps with high-priv scopes/roles (e.g., Directory.ReadWrite.All).",
            remediation="Review app permissions; remove high-priv scopes or restrict to least privilege; require admin review.",
            tags=["oauth","apps","permissions"],
        ),
        RuleUnusedAppSecrets(
            id="oauth.unused_app_secrets",
            title="Expired / long-lived app credentials",
            severity="medium", weight=5,
            description="Detect expired, soon-expiring, or long-lived credentials on apps/SPs.",
            remediation="Rotate secrets/certs frequently; set short lifetimes; remove unused credentials.",
            tags=["oauth","apps","credentials"],
        ),
        RuleUserConsentRisky(
            id="oauth.user_consent_enabled",
            title="Risky user consent posture",
            severity="medium", weight=5,
            description="Tenant user consent may allow risky self-consent to sensitive scopes.",
            remediation="Restrict user consent policies; require admin consent for high-priv scopes.",
            tags=["oauth","consent","policy"],
        ),
    ]

def exchange_rule_set() -> List[Rule]:
    return [
        RuleExternalForwardingBlocked(
            id="exo.external_forwarding_blocked",
            title="External auto-forwarding blocked",
            severity="high", weight=7,
            description="Tenant should block automatic forwarding of mail to external addresses.",
            remediation="Create or verify a transport rule blocking external auto-forwarding.",
            tags=["exchange","forwarding","org"],
        ),
        RuleLegacyAuthDisabled(
            id="exo.legacy_auth_disabled",
            title="Legacy (POP/IMAP/SMTP AUTH) protocols disabled",
            severity="high", weight=7,
            description="POP, IMAP, and SMTP AUTH must be disabled tenant-wide.",
            remediation="In Exchange Online, disable legacy protocols under mail flow or org settings.",
            tags=["exchange","legacyauth","org"],
        ),
        RuleMalwarePolicyStrict(
            id="exo.malware_policy",
            title="Malware and ATP policies present and strict",
            severity="medium", weight=5,
            description="Ensure malware filter, Safe Attachments, and Safe Links policies exist and are enabled.",
            remediation="Enable Defender for Office 365 protection policies and review configuration.",
            tags=["exchange","atp","malware","org"],
        ),
    ]

def intune_rule_set() -> List[Rule]:
    return [
        RuleBaselinePoliciesPresent(
            id="intune.baseline_policies_present",
            title="Intune baselines (compliance + configuration) present",
            severity="medium", weight=5,
            description="Have at least one compliance policy AND one configuration/profile baseline.",
            remediation="Create baseline compliance and configuration (or settings catalog) policies and assign to all devices/users.",
            tags=["intune","baseline","org"],
        ),
        RuleJailbreakBlock(
            id="intune.jailbreak_block",
            title="Block jailbroken/rooted devices",
            severity="high", weight=7,
            description="Compliance policies must explicitly block jailbroken/rooted devices.",
            remediation="Enable the 'block jailbroken/rooted devices' setting in iOS/Android compliance policies.",
            tags=["intune","compliance","devices","org"],
        ),
        RuleRequireCompliantDevice(
            id="intune.require_compliant_device",
            title="Require compliant device (CA tie-in)",
            severity="high", weight=7,
            description="At least one enabled Conditional Access policy should require a compliant device.",
            remediation="Add a CA policy with Grant control 'Require device to be marked as compliant'.",
            tags=["intune","ca","devices","org"],
        ),
    ]

def org_config_rule_set() -> List[Rule]:
    return [
        RuleSecurityDefaultsCompensated(
            id="org.security_defaults",
            title="Security Defaults off → compensating CA MFA in place",
            severity="high", weight=7,
            description="If Security Defaults are disabled, enforce MFA via CA for all users and privileged roles.",
            remediation="Enable Security Defaults OR ensure CA policies require MFA for all users and admins.",
            tags=["org","defaults","mfa"],
        ),
        RuleSsprConfigured(
            id="org.sspr",
            title="SSPR enabled and gated by MFA",
            severity="medium", weight=4,
            description="Enable SSPR and require MFA for resets.",
            remediation="Entra ID > Password reset: enable SSPR and require MFA.",
            tags=["org","sspr"],
        ),
    ]