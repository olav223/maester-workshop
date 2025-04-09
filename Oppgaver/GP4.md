### GP4 - Easy

Expiration reminders for orphaned Microsoft 365 groups are sent to a designated Entra ID security group

The designated Entra ID security groupe should be marius.vika@soprasteria.com

### Hint/Help

<details>
  <summary>To remediate or check this issue (Click to expand!)</summary>

  - Configure expiration settings in Microsoft Entra ID
  - **Azure Portal** → **Microsoft Entra ID** → **Groups** → **Settings** → **Expiration** → Check "Email contact for groups with no owners":
  - Verify a designated Entra ID security group email is specified for orphaned group notifications.

</details>
