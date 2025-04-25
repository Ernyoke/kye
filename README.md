# Know Your Enemies - AWS Account Analysis Tool

This tool analyzes IAM Role trust policies and S3 bucket policies in your AWS account to identify third-party vendors with access to your resources. It compares the AWS account IDs found in these policies against a reference list of [known AWS accounts from fwd:cloudsec](https://github.com/fwdcloudsec/known_aws_accounts/) to identify the vendors behind these accounts.

## Features

- 🔍 Analyzes IAM Role trust policies to identify who can assume your roles
- 🔍 Checks S3 bucket policies to identify who has access to your data
- 📊 Uses reference data from [known AWS accounts](https://github.com/fwdcloudsec/known_aws_accounts) to identify vendors
- 🔒 Supports defining your own trusted AWS accounts to distinguish between internal and external access
- 🏷️ Automatically detects and displays AWS account aliases for better readability
- ⚠️ Identifies IAM roles vulnerable to the confused deputy problem (missing ExternalId condition)
- 📝 Generates nice-looking console output with tables
- 📄 Creates a markdown report you can share with your security team

## Installation

1. Clone this repository:

   ```
   git clone https://github.com/yourusername/know-your-enemies.git
   cd know-your-enemies
   ```

2. Install the required dependencies:

   ```
   pip install -r requirements.txt
   ```

3. Configure your AWS credentials:
   ```
   aws configure
   ```
   or set environment variables:
   ```
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_DEFAULT_REGION="your-region"
   ```

## Required AWS Permissions

To run this script successfully, your AWS user or role needs the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:ListRoles", "iam:GetRole"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListAllMyBuckets", "s3:GetBucketPolicy"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["sts:GetCallerIdentity", "iam:ListAccountAliases"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["organizations:ListAccounts"],
      "Resource": "*"
    }
  ]
}
```

You can use the AWS built-in policies:

- `IAMReadOnlyAccess` - For IAM role analysis
- `AmazonS3ReadOnlyAccess` - For S3 bucket policy analysis
- `AWSOrganizationsReadOnlyAccess` - For AWS Organizations account listing

Or create a custom policy with just the permissions listed above for more restricted access.

## Trusted Accounts Configuration

You can define your own trusted AWS accounts to distinguish between your internal organization's accounts and external vendors. This helps you focus on identifying truly external access.

1. Create a `trusted_accounts.yaml` file in the same directory as the script:

   ```
   cp trusted_accounts.yaml.sample trusted_accounts.yaml
   ```

2. Edit the file to include your organization's AWS accounts:

   ```yaml
   - name: "My Company Production"
     description: "Production AWS accounts"
     accounts:
       - "123456789012"
       - "234567890123"

   - name: "My Company Development"
     description: "Development AWS accounts"
     accounts:
       - "345678901234"
   ```

If the `trusted_accounts.yaml` file doesn't exist or is empty, the script will analyze all accounts as potential external access points.

## Security Checks Performed

### Confused Deputy Problem Detection

The tool checks if IAM roles with cross-account access are properly protected with an ExternalId condition. The ExternalId condition helps prevent the [confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html), which occurs when a third-party (the deputy) is tricked into misusing its access to act on behalf of another account.

Roles that allow external accounts to assume them without an ExternalId condition are flagged as vulnerable in the report.

## Usage

Simply run the script:

```
python check.py
```

The script will:

1. Fetch the latest reference data of known AWS accounts
2. Load any trusted accounts from your configuration (if available)
3. Get the current AWS account alias for better identification
4. Check all IAM role trust policies in your account
5. Check all S3 bucket policies in your account
6. Identify IAM roles vulnerable to the confused deputy problem
7. Display the results in a nice format in the console
8. Generate a markdown report file

## Sample Output

```
┌─────────────────────── 🔍 AWS Analysis ───────────────────────┐
│ Know Your Enemies - AWS Account Analysis Tool                 │
│ This tool analyzes IAM Role trust policies and S3 bucket      │
│ policies to identify third-party vendors with access to your  │
│ resources.                                                    │
└───────────────────────────────────────────────────────────────┘

Fetching reference data of known AWS accounts...
✅ Found 480 known AWS accounts in the reference data
Loading trusted AWS accounts...
✅ Loaded 5 trusted AWS accounts

Analyzing AWS Account: 123456789012 (my-company-dev)

Checking IAM role trust policies...
Checking S3 bucket policies...

┌────────── 🔒 Trusted Entities with IAM Role Access ───────────────┐
│ Entity           │ IAM Roles                                      │
│ ─────────────────┼─────────────────────────────────────────────── │
│ My Company Prod  │ CrossAccountRole                               │
└───────────────────────────────────────────────────────────────────┘

┌────────────── ✅ Known Vendors with IAM Role Access ────────────┐
│ Vendor           │ IAM Roles                                    │
│ ─────────────────┼───────────────────────────────────────────── │
│ Datadog          │ DatadogIntegrationRole                       │
└─────────────────────────────────────────────────────────────────┘

┌───── ❓ Unknown AWS Accounts with IAM Role Access ─────────────┐
│ AWS Account ID  │ IAM Roles                                    │
│ ────────────────┼───────────────────────────────────────────── │
│ 123456789012    │ SomeUnknownVendorRole                        │
└────────────────────────────────────────────────────────────────┘

┌──── ⚠️ Missing ExternalId Condition (VConfused Deputy) ──┐
│ Entity         │ Vulnerable IAM Roles                    │
│ ───────────────┼──────────────────────────────────────── │
│ Datadog        │ DatadogIntegrationRole                  │
└──────────────────────────────────────────────────────────┘

┌────────────────── AWS Account Analysis Results ───────────────────┐
│ Summary:                                                           │
│ 🔒 Trusted entities found: 1                                       │
│ 🔍 Known vendors found: 1                                          │
│ ❓ Unknown AWS accounts found: 1                                   │
│ ⚠️ Vulnerable IAM roles (missing ExternalId): 1                    │
└───────────────────────────────────────────────────────────────────┘

✅ Report generated: aws_account_analysis_20230515_123045.md
```

## Report Format

The generated markdown report will include:

- Trusted entities with IAM role access
- Known vendors with IAM role access
- Unknown AWS accounts with IAM role access
- IAM roles missing ExternalId condition (vulnerable to confused deputy)
- Trusted entities with S3 bucket access
- Known vendors with S3 bucket access
- Unknown AWS accounts with S3 bucket access

## Contributing

Contributions are welcome! If you know of additional AWS account IDs that should be added to the [reference data](https://github.com/fwdcloudsec/known_aws_accounts/), please also contribute to this repository.

## License

This project is licensed under the MIT License.
