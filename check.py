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
import os
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


def fetch_trusted_accounts():
    """
    Fetch trusted AWS accounts from a local file.

    Returns:
        dict: Mapping of trusted AWS account IDs to internal names
    """
    try:
        trusted_accounts_file = "trusted_accounts.yaml"

        if not os.path.exists(trusted_accounts_file):
            console.print(
                "[yellow]No trusted accounts file found. Continuing without trusted zone.[/yellow]"
            )
            return {}

        with open(trusted_accounts_file, "r") as file:
            trusted_data = yaml.safe_load(file) or []

        # Create a mapping of account IDs to internal names
        account_to_internal = {}
        for entity in trusted_data:
            for account_id in entity.get("accounts", []):
                account_to_internal[account_id] = {
                    "name": entity.get("name", "Internal"),
                    "type": "trusted",
                    "description": entity.get("description", ""),
                }

        console.print(
            f"[green]✅ Loaded {len(account_to_internal)} trusted AWS accounts[/green]"
        )
        return account_to_internal

    except Exception as e:
        console.print(
            f"[bold yellow]Warning: Could not load trusted accounts: {str(e)}[/bold yellow]"
        )
        return {}


def get_account_aliases():
    """
    Get AWS account aliases for all AWS accounts found during analysis.

    Returns:
        dict: Mapping of AWS account IDs to their aliases
    """
    try:
        sts_client = boto3.client("sts")
        iam_client = boto3.client("iam")

        # Get current account ID
        current_account_id = sts_client.get_caller_identity()["Account"]

        # Get account alias for current account
        aliases = {}
        try:
            response = iam_client.list_account_aliases()
            if response["AccountAliases"]:
                aliases[current_account_id] = response["AccountAliases"][0]
            else:
                aliases[current_account_id] = current_account_id
        except Exception:
            aliases[current_account_id] = current_account_id

        return aliases

    except Exception as e:
        console.print(
            f"[bold yellow]Warning: Could not get account aliases: {str(e)}[/bold yellow]"
        )
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


def check_external_id_condition(policy_document):
    """
    Check if a trust policy has ExternalId condition to prevent confused deputy problem.

    Args:
        policy_document (dict): The policy document to analyze

    Returns:
        bool: True if ExternalId condition exists, False otherwise
    """
    if not policy_document or "Statement" not in policy_document:
        return False

    # Convert to list if it's a single statement
    statements = policy_document["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        # Check if the statement is for cross-account access
        principal = statement.get("Principal", {})
        if not isinstance(principal, dict):
            continue

        aws_principal = principal.get("AWS", "")
        if not aws_principal:
            continue

        # Now check if there's a proper ExternalId condition
        condition = statement.get("Condition", {})
        if not condition:
            return False

        for condition_type, condition_values in condition.items():
            if condition_type in ["StringEquals", "StringLike", "ArnLike"]:
                if "sts:ExternalId" in condition_values:
                    return True

    return False


def check_iam_role_trust_policies(account_to_vendor, trusted_accounts, account_aliases):
    """
    Check IAM Role trust policies for known AWS accounts.

    Args:
        account_to_vendor (dict): Mapping of AWS account IDs to vendor names
        trusted_accounts (dict): Mapping of trusted AWS account IDs to internal names
        account_aliases (dict): Mapping of AWS account IDs to their aliases

    Returns:
        tuple: (known_vendors, unknown_accounts, trusted_entities, vulnerable_roles)
            known_vendors (dict): Dictionary mapping vendor names to lists of IAM role names
            unknown_accounts (dict): Dictionary mapping unknown account IDs to lists of IAM role names
            trusted_entities (dict): Dictionary mapping trusted entity names to lists of IAM role names
            vulnerable_roles (dict): Dictionary mapping account IDs to roles without ExternalId conditions
    """
    console.print("[bold blue]Checking IAM role trust policies...[/bold blue]")

    iam_client = boto3.client("iam")
    known_vendors = {}
    unknown_accounts = {}
    trusted_entities = {}
    vulnerable_roles = {}

    try:
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                trust_policy = role.get("AssumeRolePolicyDocument", {})

                # Extract account IDs from the trust policy
                account_ids = extract_account_ids_from_policy(trust_policy)

                for account_id in account_ids:
                    # Skip checking service roles (AWS services)
                    if account_id == "":
                        continue

                    # Check if account is in trusted zone
                    if account_id in trusted_accounts:
                        trusted_name = trusted_accounts[account_id]["name"]
                        if trusted_name not in trusted_entities:
                            trusted_entities[trusted_name] = []
                        trusted_entities[trusted_name].append(role_name)
                    # Check if account is a known vendor
                    elif account_id in account_to_vendor:
                        vendor_name = account_to_vendor[account_id]["name"]
                        if vendor_name not in known_vendors:
                            known_vendors[vendor_name] = []
                        known_vendors[vendor_name].append(role_name)

                        # Check for missing ExternalId condition for vendors
                        has_external_id = check_external_id_condition(trust_policy)
                        if not has_external_id:
                            if vendor_name not in vulnerable_roles:
                                vulnerable_roles[vendor_name] = []
                            vulnerable_roles[vendor_name].append(role_name)
                    # Add to unknown accounts
                    else:
                        # Format account ID with alias if available
                        display_id = account_id
                        if account_id in account_aliases:
                            display_id = f"{account_id} ({account_aliases[account_id]})"

                        if display_id not in unknown_accounts:
                            unknown_accounts[display_id] = []
                        unknown_accounts[display_id].append(role_name)

                        # Check for missing ExternalId condition for unknown accounts
                        has_external_id = check_external_id_condition(trust_policy)
                        if not has_external_id:
                            if display_id not in vulnerable_roles:
                                vulnerable_roles[display_id] = []
                            vulnerable_roles[display_id].append(role_name)

        return known_vendors, unknown_accounts, trusted_entities, vulnerable_roles

    except Exception as e:
        console.print(
            f"[bold red]Error checking IAM role trust policies: {str(e)}[/bold red]"
        )
        return {}, {}, {}, {}


def check_s3_bucket_policies(account_to_vendor, trusted_accounts, account_aliases):
    """
    Check S3 bucket policies for known AWS accounts.

    Args:
        account_to_vendor (dict): Mapping of AWS account IDs to vendor names
        trusted_accounts (dict): Mapping of trusted AWS account IDs to internal names
        account_aliases (dict): Mapping of AWS account IDs to their aliases

    Returns:
        tuple: (known_vendors, unknown_accounts, trusted_entities)
            known_vendors (dict): Dictionary mapping vendor names to lists of bucket names
            unknown_accounts (dict): Dictionary mapping unknown account IDs to lists of bucket names
            trusted_entities (dict): Dictionary mapping trusted entity names to lists of bucket names
    """
    console.print("[bold blue]Checking S3 bucket policies...[/bold blue]")

    s3_client = boto3.client("s3")
    known_vendors = {}
    unknown_accounts = {}
    trusted_entities = {}

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
                    # Check if account is in trusted zone
                    if account_id in trusted_accounts:
                        trusted_name = trusted_accounts[account_id]["name"]
                        if trusted_name not in trusted_entities:
                            trusted_entities[trusted_name] = []
                        trusted_entities[trusted_name].append(bucket_name)
                    # Check if account is a known vendor
                    elif account_id in account_to_vendor:
                        vendor_name = account_to_vendor[account_id]["name"]
                        if vendor_name not in known_vendors:
                            known_vendors[vendor_name] = []
                        known_vendors[vendor_name].append(bucket_name)
                    # Add to unknown accounts
                    else:
                        # Format account ID with alias if available
                        display_id = account_id
                        if account_id in account_aliases:
                            display_id = f"{account_id} ({account_aliases[account_id]})"

                        if display_id not in unknown_accounts:
                            unknown_accounts[display_id] = []
                        unknown_accounts[display_id].append(bucket_name)

            except ClientError as e:
                # Skip buckets without policies
                if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    continue
                else:
                    console.print(
                        f"[yellow]Warning: Could not check policy for bucket {bucket_name}: {e.response['Error']['Message']}[/yellow]"
                    )

        return known_vendors, unknown_accounts, trusted_entities

    except Exception as e:
        console.print(
            f"[bold red]Error checking S3 bucket policies: {str(e)}[/bold red]"
        )
        return {}, {}, {}


def generate_report(
    iam_known_vendors,
    iam_unknown_accounts,
    iam_trusted_entities,
    iam_vulnerable_roles,
    s3_known_vendors,
    s3_unknown_accounts,
    s3_trusted_entities,
    account_aliases,
):
    """
    Generate a report with the findings.

    Args:
        iam_known_vendors (dict): Known vendors found in IAM role trust policies
        iam_unknown_accounts (dict): Unknown accounts found in IAM role trust policies
        iam_trusted_entities (dict): Trusted entities found in IAM role trust policies
        iam_vulnerable_roles (dict): Roles without ExternalId condition
        s3_known_vendors (dict): Known vendors found in S3 bucket policies
        s3_unknown_accounts (dict): Unknown accounts found in S3 bucket policies
        s3_trusted_entities (dict): Trusted entities found in S3 bucket policies
        account_aliases (dict): Mapping of AWS account IDs to their aliases

    Returns:
        str: The path to the generated report
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Get current account info
    current_account_id = (
        list(account_aliases.keys())[0] if account_aliases else "Unknown"
    )
    current_account_alias = account_aliases.get(current_account_id, current_account_id)

    report_file = f"aws_account_analysis_{current_account_id}_{timestamp}.md"

    with open(report_file, "w") as f:
        f.write("# AWS Account Access Analysis Report\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Account: {current_account_id} ({current_account_alias})\n\n")

        # Write IAM trusted entities section
        f.write("## Trusted Entities with IAM Role Access\n\n")
        if iam_trusted_entities:
            f.write("| Entity | IAM Roles |\n")
            f.write("|--------|----------|\n")
            for entity, roles in iam_trusted_entities.items():
                f.write(f"| {entity} | {', '.join(roles)} |\n")
        else:
            f.write("No trusted entities found in IAM role trust policies.\n")
        f.write("\n")

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

        # Write vulnerable roles section (missing ExternalId)
        f.write("## ⚠️ IAM Roles Missing ExternalId Condition\n\n")
        f.write(
            "These roles are vulnerable to the [confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).\n\n"
        )
        if iam_vulnerable_roles:
            f.write("| Entity | Vulnerable IAM Roles |\n")
            f.write("|--------|--------------------|\n")
            for entity, roles in iam_vulnerable_roles.items():
                f.write(f"| {entity} | {', '.join(roles)} |\n")
        else:
            f.write("No vulnerable IAM roles found (good job!).\n")
        f.write("\n")

        # Write S3 trusted entities section
        f.write("## Trusted Entities with S3 Bucket Access\n\n")
        if s3_trusted_entities:
            f.write("| Entity | S3 Buckets |\n")
            f.write("|--------|----------|\n")
            for entity, buckets in s3_trusted_entities.items():
                f.write(f"| {entity} | {', '.join(buckets)} |\n")
        else:
            f.write("No trusted entities found in S3 bucket policies.\n")
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
    iam_known_vendors,
    iam_unknown_accounts,
    iam_trusted_entities,
    iam_vulnerable_roles,
    s3_known_vendors,
    s3_unknown_accounts,
    s3_trusted_entities,
    account_aliases,
):
    """
    Display the results in a nice format with emojis.

    Args:
        iam_known_vendors (dict): Known vendors found in IAM role trust policies
        iam_unknown_accounts (dict): Unknown accounts found in IAM role trust policies
        iam_trusted_entities (dict): Trusted entities found in IAM role trust policies
        iam_vulnerable_roles (dict): Roles without ExternalId condition
        s3_known_vendors (dict): Known vendors found in S3 bucket policies
        s3_unknown_accounts (dict): Unknown accounts found in S3 bucket policies
        s3_trusted_entities (dict): Trusted entities found in S3 bucket policies
        account_aliases (dict): Mapping of AWS account IDs to their aliases
    """
    # Get current account info
    current_account_id = (
        list(account_aliases.keys())[0] if account_aliases else "Unknown"
    )
    current_account_alias = account_aliases.get(current_account_id, current_account_id)

    console.print(
        f"[cyan]Analyzing AWS Account:[/cyan] {current_account_id} ({current_account_alias})"
    )

    # Display IAM trusted entities table
    if iam_trusted_entities:
        table = Table(title="🔒 Trusted Entities with IAM Role Access", box=box.ROUNDED)
        table.add_column("Entity", style="green")
        table.add_column("IAM Roles", style="blue")

        for entity, roles in iam_trusted_entities.items():
            table.add_row(
                entity, "\n".join(roles[:5]) + ("\n..." if len(roles) > 5 else "")
            )

        console.print(table)

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

    # Display vulnerable roles table (missing ExternalId)
    if iam_vulnerable_roles:
        table = Table(
            title="⚠️ IAM Roles Missing ExternalId Condition (Vulnerable to Confused Deputy)",
            box=box.ROUNDED,
        )
        table.add_column("Entity", style="red")
        table.add_column("Vulnerable IAM Roles", style="red")

        for entity, roles in iam_vulnerable_roles.items():
            table.add_row(
                entity, "\n".join(roles[:5]) + ("\n..." if len(roles) > 5 else "")
            )

        console.print(table)

    # Display S3 trusted entities table
    if s3_trusted_entities:
        table = Table(
            title="🔒 Trusted Entities with S3 Bucket Access", box=box.ROUNDED
        )
        table.add_column("Entity", style="green")
        table.add_column("S3 Buckets", style="blue")

        for entity, buckets in s3_trusted_entities.items():
            table.add_row(
                entity, "\n".join(buckets[:5]) + ("\n..." if len(buckets) > 5 else "")
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
    total_trusted = len(iam_trusted_entities) + len(s3_trusted_entities)
    total_known = len(iam_known_vendors) + len(s3_known_vendors)
    total_unknown = len(iam_unknown_accounts) + len(s3_unknown_accounts)
    total_vulnerable = len(iam_vulnerable_roles)

    console.print(
        Panel(
            f"[bold]Summary:[/bold]\n"
            f"🔒 [green]Trusted entities found:[/green] {total_trusted}\n"
            f"🔍 [cyan]Known vendors found:[/cyan] {total_known}\n"
            f"❓ [yellow]Unknown AWS accounts found:[/yellow] {total_unknown}\n"
            f"⚠️ [red]Vulnerable IAM roles (missing ExternalId):[/red] {total_vulnerable}",
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

        # Fetch trusted accounts
        console.print("[bold]Loading trusted AWS accounts...[/bold]")
        trusted_accounts = fetch_trusted_accounts()

        # Get account aliases
        account_aliases = get_account_aliases()

        # Check IAM role trust policies
        (
            iam_known_vendors,
            iam_unknown_accounts,
            iam_trusted_entities,
            iam_vulnerable_roles,
        ) = check_iam_role_trust_policies(
            account_to_vendor, trusted_accounts, account_aliases
        )

        # Check S3 bucket policies
        s3_known_vendors, s3_unknown_accounts, s3_trusted_entities = (
            check_s3_bucket_policies(
                account_to_vendor, trusted_accounts, account_aliases
            )
        )

        # Display results
        display_results(
            iam_known_vendors,
            iam_unknown_accounts,
            iam_trusted_entities,
            iam_vulnerable_roles,
            s3_known_vendors,
            s3_unknown_accounts,
            s3_trusted_entities,
            account_aliases,
        )

        # Generate report
        report_file = generate_report(
            iam_known_vendors,
            iam_unknown_accounts,
            iam_trusted_entities,
            iam_vulnerable_roles,
            s3_known_vendors,
            s3_unknown_accounts,
            s3_trusted_entities,
            account_aliases,
        )
        console.print(f"[bold green]✅ Report generated: {report_file}[/bold green]")

    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
