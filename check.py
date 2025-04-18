#!/usr/bin/env python3
"""
Know Your Enemies (KYE) - AWS Account Analysis Tool

This script analyzes IAM Role trust policies and S3 bucket policies in your AWS account
to identify third-party vendors with access to your resources. It compares the AWS account IDs
found in these policies against a reference list of [known AWS accounts from fwd:cloudsec](https://github.com/fwdcloudsec/known_aws_accounts/) to identify
the vendors behind these accounts.

Usage:
    python check.py
"""

import boto3
import yaml
import json
import requests
import sys
from datetime import datetime
from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# Initialize rich console for nice output
console = Console()


def fetch_reference_data():
    """
    Fetch the reference data of known AWS accounts from GitHub.

    Returns:
        dict: Mapping of AWS account IDs to vendor names
    """
    try:
        # Fetch latest data from GitHub repository
        url = "https://raw.githubusercontent.com/fwdcloudsec/known_aws_accounts/main/accounts.yaml"
        response = requests.get(url)
        response.raise_for_status()

        # Parse YAML content
        vendors_data = yaml.safe_load(response.text)

        # Create a mapping of account IDs to vendor names
        account_to_vendor = {}
        for vendor in vendors_data:
            for account_id in vendor.get("accounts", []):
                account_to_vendor[account_id] = {
                    "name": vendor.get("name", "Unknown"),
                    "type": vendor.get("type", "third-party"),
                    "source": vendor.get("source", []),
                }

        return account_to_vendor

    except Exception as e:
        console.print(f"[bold red]Error fetching reference data: {str(e)}[/bold red]")
        return {}


def extract_account_ids_from_policy(policy_document):
    """
    Extract AWS account IDs from a policy document.

    Args:
        policy_document (dict): The policy document to analyze

    Returns:
        list: List of unique AWS account IDs found in the policy
    """
    account_ids = set()

    def search_for_accounts(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "AWS":
                    if isinstance(value, str) and "arn:aws" in value:
                        # Extract account ID from ARN
                        parts = value.split(":")
                        if len(parts) >= 5:
                            account_id = parts[4]
                            if account_id.isdigit() and len(account_id) == 12:
                                account_ids.add(account_id)
                    elif (
                        isinstance(value, str) and value.isdigit() and len(value) == 12
                    ):
                        account_ids.add(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and "arn:aws" in item:
                                parts = item.split(":")
                                if len(parts) >= 5:
                                    account_id = parts[4]
                                    if account_id.isdigit() and len(account_id) == 12:
                                        account_ids.add(account_id)
                            elif (
                                isinstance(item, str)
                                and item.isdigit()
                                and len(item) == 12
                            ):
                                account_ids.add(item)
                else:
                    search_for_accounts(value)
        elif isinstance(node, list):
            for item in node:
                search_for_accounts(item)

    search_for_accounts(policy_document)
    return list(account_ids)


def check_iam_role_trust_policies(account_to_vendor):
    """
    Check IAM Role trust policies for known AWS accounts.

    Args:
        account_to_vendor (dict): Mapping of AWS account IDs to vendor names

    Returns:
        tuple: (known_vendors, unknown_accounts)
            known_vendors (dict): Dictionary mapping vendor names to lists of IAM role names
            unknown_accounts (dict): Dictionary mapping unknown account IDs to lists of IAM role names
    """
    console.print("[bold blue]Checking IAM role trust policies...[/bold blue]")

    iam_client = boto3.client("iam")
    known_vendors = {}
    unknown_accounts = {}

    try:
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                trust_policy = role.get("AssumeRolePolicyDocument", {})

                # Extract account IDs from the trust policy
                account_ids = extract_account_ids_from_policy(trust_policy)

                for account_id in account_ids:
                    if account_id in account_to_vendor:
                        vendor_name = account_to_vendor[account_id]["name"]
                        if vendor_name not in known_vendors:
                            known_vendors[vendor_name] = []
                        known_vendors[vendor_name].append(role_name)
                    else:
                        if account_id not in unknown_accounts:
                            unknown_accounts[account_id] = []
                        unknown_accounts[account_id].append(role_name)

        return known_vendors, unknown_accounts

    except Exception as e:
        console.print(
            f"[bold red]Error checking IAM role trust policies: {str(e)}[/bold red]"
        )
        return {}, {}


def check_s3_bucket_policies(account_to_vendor):
    """
    Check S3 bucket policies for known AWS accounts.

    Args:
        account_to_vendor (dict): Mapping of AWS account IDs to vendor names

    Returns:
        tuple: (known_vendors, unknown_accounts)
            known_vendors (dict): Dictionary mapping vendor names to lists of bucket names
            unknown_accounts (dict): Dictionary mapping unknown account IDs to lists of bucket names
    """
    console.print("[bold blue]Checking S3 bucket policies...[/bold blue]")

    s3_client = boto3.client("s3")
    known_vendors = {}
    unknown_accounts = {}

    try:
        response = s3_client.list_buckets()
        for bucket in response["Buckets"]:
            bucket_name = bucket["Name"]

            try:
                # Get bucket policy if it exists
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_document = json.loads(policy_response["Policy"])

                # Extract account IDs from the bucket policy
                account_ids = extract_account_ids_from_policy(policy_document)

                for account_id in account_ids:
                    if account_id in account_to_vendor:
                        vendor_name = account_to_vendor[account_id]["name"]
                        if vendor_name not in known_vendors:
                            known_vendors[vendor_name] = []
                        known_vendors[vendor_name].append(bucket_name)
                    else:
                        if account_id not in unknown_accounts:
                            unknown_accounts[account_id] = []
                        unknown_accounts[account_id].append(bucket_name)

            except ClientError as e:
                # Skip buckets without policies
                if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    continue
                else:
                    console.print(
                        f"[yellow]Warning: Could not check policy for bucket {bucket_name}: {e.response['Error']['Message']}[/yellow]"
                    )

        return known_vendors, unknown_accounts

    except Exception as e:
        console.print(
            f"[bold red]Error checking S3 bucket policies: {str(e)}[/bold red]"
        )
        return {}, {}


def generate_report(
    iam_known_vendors, iam_unknown_accounts, s3_known_vendors, s3_unknown_accounts
):
    """
    Generate a report with the findings.

    Args:
        iam_known_vendors (dict): Known vendors found in IAM role trust policies
        iam_unknown_accounts (dict): Unknown accounts found in IAM role trust policies
        s3_known_vendors (dict): Known vendors found in S3 bucket policies
        s3_unknown_accounts (dict): Unknown accounts found in S3 bucket policies

    Returns:
        str: The path to the generated report
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"aws_account_analysis_{timestamp}.md"

    with open(report_file, "w") as f:
        f.write("# AWS Account Access Analysis Report\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Write IAM known vendors section
        f.write("## Known Vendors with IAM Role Access\n\n")
        if iam_known_vendors:
            f.write("| Vendor | IAM Roles |\n")
            f.write("|--------|----------|\n")
            for vendor, roles in iam_known_vendors.items():
                f.write(f"| {vendor} | {', '.join(roles)} |\n")
        else:
            f.write("No known vendors found in IAM role trust policies.\n")
        f.write("\n")

        # Write IAM unknown accounts section
        f.write("## Unknown AWS Accounts with IAM Role Access\n\n")
        if iam_unknown_accounts:
            f.write("| AWS Account ID | IAM Roles |\n")
            f.write("|---------------|----------|\n")
            for account_id, roles in iam_unknown_accounts.items():
                f.write(f"| {account_id} | {', '.join(roles)} |\n")
        else:
            f.write("No unknown AWS accounts found in IAM role trust policies.\n")
        f.write("\n")

        # Write S3 known vendors section
        f.write("## Known Vendors with S3 Bucket Access\n\n")
        if s3_known_vendors:
            f.write("| Vendor | S3 Buckets |\n")
            f.write("|--------|----------|\n")
            for vendor, buckets in s3_known_vendors.items():
                f.write(f"| {vendor} | {', '.join(buckets)} |\n")
        else:
            f.write("No known vendors found in S3 bucket policies.\n")
        f.write("\n")

        # Write S3 unknown accounts section
        f.write("## Unknown AWS Accounts with S3 Bucket Access\n\n")
        if s3_unknown_accounts:
            f.write("| AWS Account ID | S3 Buckets |\n")
            f.write("|---------------|----------|\n")
            for account_id, buckets in s3_unknown_accounts.items():
                f.write(f"| {account_id} | {', '.join(buckets)} |\n")
        else:
            f.write("No unknown AWS accounts found in S3 bucket policies.\n")

    return report_file


def display_results(
    iam_known_vendors, iam_unknown_accounts, s3_known_vendors, s3_unknown_accounts
):
    """
    Display the results in a nice format with emojis.

    Args:
        iam_known_vendors (dict): Known vendors found in IAM role trust policies
        iam_unknown_accounts (dict): Unknown accounts found in IAM role trust policies
        s3_known_vendors (dict): Known vendors found in S3 bucket policies
        s3_unknown_accounts (dict): Unknown accounts found in S3 bucket policies
    """
    # Display IAM known vendors table
    if iam_known_vendors:
        table = Table(title="✅ Known Vendors with IAM Role Access", box=box.ROUNDED)
        table.add_column("Vendor", style="cyan")
        table.add_column("IAM Roles", style="green")

        for vendor, roles in iam_known_vendors.items():
            table.add_row(
                vendor, "\n".join(roles[:5]) + ("\n..." if len(roles) > 5 else "")
            )

        console.print(table)

    # Display IAM unknown accounts table
    if iam_unknown_accounts:
        table = Table(
            title="❓ Unknown AWS Accounts with IAM Role Access", box=box.ROUNDED
        )
        table.add_column("AWS Account ID", style="yellow")
        table.add_column("IAM Roles", style="green")

        for account_id, roles in iam_unknown_accounts.items():
            table.add_row(
                account_id, "\n".join(roles[:5]) + ("\n..." if len(roles) > 5 else "")
            )

        console.print(table)

    # Display S3 known vendors table
    if s3_known_vendors:
        table = Table(title="✅ Known Vendors with S3 Bucket Access", box=box.ROUNDED)
        table.add_column("Vendor", style="cyan")
        table.add_column("S3 Buckets", style="green")

        for vendor, buckets in s3_known_vendors.items():
            table.add_row(
                vendor, "\n".join(buckets[:5]) + ("\n..." if len(buckets) > 5 else "")
            )

        console.print(table)

    # Display S3 unknown accounts table
    if s3_unknown_accounts:
        table = Table(
            title="❓ Unknown AWS Accounts with S3 Bucket Access", box=box.ROUNDED
        )
        table.add_column("AWS Account ID", style="yellow")
        table.add_column("S3 Buckets", style="green")

        for account_id, buckets in s3_unknown_accounts.items():
            table.add_row(
                account_id,
                "\n".join(buckets[:5]) + ("\n..." if len(buckets) > 5 else ""),
            )

        console.print(table)

    # Display summary
    total_known = len(iam_known_vendors) + len(s3_known_vendors)
    total_unknown = len(iam_unknown_accounts) + len(s3_unknown_accounts)

    console.print(
        Panel(
            f"[bold]Summary:[/bold]\n"
            f"🔍 [cyan]Known vendors found:[/cyan] {total_known}\n"
            f"❓ [yellow]Unknown AWS accounts found:[/yellow] {total_unknown}",
            title="AWS Account Analysis Results",
            box=box.ROUNDED,
        )
    )


def main():
    """
    Main function to run the script.
    """
    try:
        # Display welcome message
        console.print(
            Panel(
                "[bold cyan]Know Your Enemies - AWS Account Analysis Tool[/bold cyan]\n"
                "This tool analyzes IAM Role trust policies and S3 bucket policies\n"
                "to identify third-party vendors with access to your resources.",
                title="🔍 AWS Analysis",
                box=box.ROUNDED,
            )
        )

        # Fetch reference data
        console.print("[bold]Fetching reference data of known AWS accounts...[/bold]")
        account_to_vendor = fetch_reference_data()
        console.print(
            f"[green]✅ Found {len(account_to_vendor)} known AWS accounts in the reference data[/green]"
        )

        # Check IAM role trust policies
        iam_known_vendors, iam_unknown_accounts = check_iam_role_trust_policies(
            account_to_vendor
        )

        # Check S3 bucket policies
        s3_known_vendors, s3_unknown_accounts = check_s3_bucket_policies(
            account_to_vendor
        )

        # Display results
        display_results(
            iam_known_vendors,
            iam_unknown_accounts,
            s3_known_vendors,
            s3_unknown_accounts,
        )

        # Generate report
        report_file = generate_report(
            iam_known_vendors,
            iam_unknown_accounts,
            s3_known_vendors,
            s3_unknown_accounts,
        )
        console.print(f"[bold green]✅ Report generated: {report_file}[/bold green]")

    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
