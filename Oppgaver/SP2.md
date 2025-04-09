# SP2 - Hard

Guest access to SPO is available for guests, but certain domains are blocked. (And guests are denied from certain domains)

<details>
  <summary>To Remediate or Check This Issue (Click to expand!)</summary>

- Configure External Collaboration Settings in Microsoft Entra ID:
- **Microsoft Entra ID** → **External Identities** → **External Collaboration Settings** → Under **Collaboration restrictions**, set to:
  - **"Deny invitations to the specified domains"** for a blocklist.
  - **"Allow invitations only to the specified domains"** for an allowlist.
  - Ensure guest access is enabled but restricted as per policy.
- **SharePoint Online Domain Settings**:
  - Go to **SharePoint Admin Center** → **Policies** → **Sharing**.
  - Set `SharingDomainRestrictionMode` to either:
    - **Blocklist**: Specify blocked domains.
    - **Allowlist**: Specify allowed domains.
  - Avoid setting to "None" unless paired with a restrictive Entra ID policy.

</details>
