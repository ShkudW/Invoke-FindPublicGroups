# Invoke-FindPublicGroups


In Microsoft Entra ID (formerly Azure Active Directory), a Public Group typically refers to a Microsoft 365 Group (GroupTypes=Unified) where the Visibility attribute is set to Public.
When a group is public:
 - Any user within the tenant can view the group's membership and freely join the group without requiring approval.
 - Public groups are often used for open collaboration (e.g., Teams, Outlook, Planner).
Note: Traditional Security Groups (securityEnabled = true) do not support the Public visibility model — only Microsoft 365 Groups do.

![image](https://github.com/user-attachments/assets/7ca97448-5591-4020-be32-44f6a764dadc)


From a Red Team perspective, Public Groups offer critical opportunities:
1. Privilege Escalation: Some public groups may have elevated permissions attached (e.g., access to sensitive SharePoint sites, applications, or delegated roles).
2. Lateral Movement: Joining a group can provide access to communication channels (Teams, SharePoint, Outlook) where sensitive information is shared.
3. Access Expansion: Membership in certain groups may automatically grant additional entitlements across integrated systems (e.g., Entra ID Governance policies, Conditional Access exclusions).
4. Reconnaissance: Mapping public groups helps understand the organization's internal structure, team names, projects, and technologies.
5. Thus, identifying public, joinable groups in a tenant is an important attack path in Red Team engagements and internal penetration tests.


## About the Project

**Invoke-FindUpdatableGroups** is a PowerShell tool that helps Red Teamers and security researchers identify Microsoft 365 groups (Public groups) where they can self-add as members.

By discovering joinable groups, attackers can map potential privilege escalation paths, lateral movement opportunities, or access sensitive collaboration platforms such as Teams, SharePoint, and Outlook.

The tool authenticates to Microsoft Graph using a Refresh Token or Client Credentials, fetches all Microsoft 365 groups, and checks group updatability using the `estimateAccess` API.

### Key Highlights
- Full Graph API pagination handling.
- Detection of publicly joinable Microsoft 365 groups.
- Automatic token refresh every 7 minutes.
- Intelligent rate-limit handling based on `Retry-After` values.
- Output saved to `Public_Groups.txt`.

---
## Usage Example

supporting Device Code Flow:
```powershell
Invoke-FindUpdatableGroups -DeviceCodeFlow
```
if you have Refresh Token:
```powershell
Invoke-FindUpdatableGroups -RefreshToken <your_refresh_token>
```
If you have a SecretID of appliacation:

```powershell
Invoke-FindUpdatableGroups -ClientID <Application_Cliend_ID> -SecretID <Application_Secret_ID>
```
