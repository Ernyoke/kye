# Know Your Enemies - AWS Account Analysis Tool

This tool analyzes IAM Role trust policies and S3 bucket policies in your AWS account to identify third-party vendors with access to your resources. It compares the AWS account IDs found in these policies against a reference list of [known AWS accounts from fwd:cloudsec](https://github.com/fwdcloudsec/known_aws_accounts/) to identify the vendors behind these accounts.

## Features

- 🔍 Analyzes IAM Role trust policies to identify who can assume your roles
- 🔍 Checks S3 bucket policies to identify who has access to your data
- 📊 Uses reference data from [known AWS accounts](https://github.com/fwdcloudsec/known_aws_accounts) to identify vendors
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

## Usage

Simply run the script:

```
python check.py
```

The script will:

1. Fetch the latest reference data of known AWS accounts
2. Check all IAM role trust policies in your account
3. Check all S3 bucket policies in your account
4. Display the results in a nice format in the console
5. Generate a markdown report file

## Sample Output

```
┌─────────────────────── 🔍 AWS Analysis ───────────────────────┐
│ Know Your Enemies - AWS Account Analysis Tool                 │
│ This tool analyzes IAM Role trust policies and S3 bucket      │
│ policies to identify third-party vendors with access to your  │
│ resources.                                                    │
└────────────────────────────────────────────────────────────────┘

Fetching reference data of known AWS accounts...
✅ Found 47 known AWS accounts in the reference data

Checking IAM role trust policies...
Checking S3 bucket policies...

┌─────────────── ✅ Known Vendors with IAM Role Access ───────────────┐
│ Vendor           │ IAM Roles                                        │
│ ────────────────┼─────────────────────────────────────────────     │
│ Datadog          │ DatadogIntegrationRole                          │
└────────────────────────────────────────────────────────────────────┘

┌───────────── ❓ Unknown AWS Accounts with IAM Role Access ─────────────┐
│ AWS Account ID  │ IAM Roles                                            │
│ ────────────────┼─────────────────────────────────────────────         │
│ 123456789012    │ SomeUnknownVendorRole                               │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────── AWS Account Analysis Results ─────────────────────┐
│ Summary:                                                            │
│ 🔍 Known vendors found: 1                                           │
│ ❓ Unknown AWS accounts found: 1                                     │
└────────────────────────────────────────────────────────────────────┘

✅ Report generated: aws_account_analysis_20230515_123045.md
```

## Report Format

The generated markdown report will include:

- Known vendors with IAM role access
- Unknown AWS accounts with IAM role access
- Known vendors with S3 bucket access
- Unknown AWS accounts with S3 bucket access

## Contributing

Contributions are welcome! If you know of additional AWS account IDs that should be added to the [reference data](https://github.com/fwdcloudsec/known_aws_accounts/), please also contribute to this repository.

## License

This project is licensed under the MIT License.
