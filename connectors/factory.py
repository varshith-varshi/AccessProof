from __future__ import annotations
from packages.connector_sdk.base import SourceAdapter

from typing import Any

from packages.test_engine.clock import Clock
from connectors.microsoft365.adapter import Microsoft365Adapter
from connectors.google_drive.adapter import GoogleDriveAdapter
from connectors.confluence.adapter import ConfluenceAdapter
from connectors.slack.adapter import SlackAdapter
from connectors.salesforce.adapter import SalesforceAdapter
from connectors.mock_source.adapter import MockSourceAdapter
from connectors.demo_ai.adapter import DemoAiSourceAdapter


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def create_source_adapter(
    provider: str, credentials: dict[str, Any], *, clock: Clock | None = None
) -> SourceAdapter:
    provider = provider.lower()
    if provider in {"mock", "mock-source"}:
        if clock is None:
            clock = Clock()
        return MockSourceAdapter(clock=clock)
    if provider in {"demo-ai", "external-ai-demo"}:
        return DemoAiSourceAdapter(
            base_url=credentials["base_url"], service_token=credentials.get("service_token")
        )
    if provider in {"sharepoint", "microsoft365", "onedrive"}:
        return Microsoft365Adapter(
            access_token=credentials["access_token"],
            drive_id=credentials["drive_id"],
            test_root_item_id=credentials["test_root_item_id"],
            tenant_hint=credentials.get("tenant_hint"),
            sharepoint_site_id=credentials.get("site_id") if provider in {"microsoft365", "sharepoint"} else None,
            sharepoint_list_id=credentials.get("list_id") if provider in {"microsoft365", "sharepoint"} else None,
            onedrive_owner_object_id=credentials.get("owner_object_id") if provider in {"microsoft365", "onedrive"} else None,
            test_group_id=credentials.get("test_group_id"),
            test_group_email=credentials.get("test_group_email"),
            advanced_directory_mode=_as_bool(credentials.get("advanced_directory_mode")),
            enable_share_link_tests=_as_bool(credentials.get("enable_share_link_tests")),
            move_target_parent_item_id=credentials.get("move_target_parent_item_id"),
            enable_parent_acl_tests=_as_bool(credentials.get("enable_parent_acl_tests")),
        )
    if provider == "google-drive":
        return GoogleDriveAdapter(
            access_token=credentials["access_token"],
            test_root_folder_id=credentials["test_root_folder_id"],
            enable_parent_acl_tests=bool(credentials.get("enable_parent_acl_tests", False)),
            move_target_folder_id=credentials.get("move_target_folder_id"),
        )
    if provider == "confluence":
        return ConfluenceAdapter(
            base_url=credentials["base_url"],
            access_token=credentials["access_token"],
            test_space_key=credentials["test_space_key"],
            enable_restriction_tests=bool(credentials.get("enable_restriction_tests", False)),
            restriction_guard_account_id=credentials.get("restriction_guard_account_id"),
        )
    if provider == "slack":
        return SlackAdapter(
            token=credentials["token"], test_channel_id=credentials["test_channel_id"]
        )
    if provider == "salesforce":
        return SalesforceAdapter(
            instance_url=credentials["instance_url"],
            access_token=credentials["access_token"],
            api_version=credentials.get("api_version", "v65.0"),
            test_object=credentials.get("test_object", "AccessProof_Test__c"),
            share_object=credentials.get("share_object"),
            share_parent_field=credentials.get("share_parent_field", "ParentId"),
            share_principal_field=credentials.get("share_principal_field", "UserOrGroupId"),
            share_access_field=credentials.get("share_access_field", "AccessLevel"),
            share_access_value=credentials.get("share_access_value", "Read"),
            share_row_cause_field=credentials.get("share_row_cause_field", "RowCause"),
            share_row_cause_value=credentials.get("share_row_cause_value", "Manual"),
        )
    raise ValueError(f"Unsupported provider: {provider}")
