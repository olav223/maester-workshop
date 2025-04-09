## SC9 - Easy

Guest user access in Entra ID external collaboration settings is set to most restrictive

### Hint/Help

<details>
  <summary>To remediate or check this issue (Click to expand!)</summary>

  - Configure settings in Microsoft Entra ID
  - **Microsoft Entra ID** → **External Identities** → **External collaboration settings** → Set _"Guest user access"_ to **"Guest user access is restricted to properties and memberships of their own directory objects."**:
  - Verify that the most restrictive option is selected.

</details>

[Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions)
