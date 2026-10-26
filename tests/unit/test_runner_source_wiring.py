from packages.test_engine.clock import SimulatedClock
from apps.runner.accessproof_runner.main import build_source
from connectors.microsoft365.adapter import Microsoft365Adapter
from connectors.confluence.adapter import ConfluenceAdapter
from connectors.salesforce.adapter import SalesforceAdapter


def test_runner_uses_full_microsoft_factory_configuration():
    source = build_source(
        {
            "source": {
                "provider": "microsoft365",
                "credentials": {
                    "access_token": "token",
                    "drive_id": "drive",
                    "test_root_item_id": "root",
                    "test_group_id": "group",
                    "test_group_email": "group@example.com",
                    "advanced_directory_mode": True,
                    "enable_share_link_tests": True,
                    "move_target_parent_item_id": "move-parent",
                    "enable_parent_acl_tests": True,
                },
            }
        },
        SimulatedClock(),
    )
    assert isinstance(source, Microsoft365Adapter)
    assert source.advanced_directory_mode is True
    assert source.enable_share_link_tests is True
    assert source.enable_parent_acl_tests is True
    assert source.move_target_parent_item_id == "move-parent"


def test_runner_preserves_confluence_and_salesforce_advanced_configuration():
    confluence = build_source(
        {
            "source": {
                "provider": "confluence",
                "credentials": {
                    "base_url": "https://example.atlassian.net/wiki",
                    "access_token": "token",
                    "test_space_key": "AP",
                    "enable_restriction_tests": True,
                    "restriction_guard_account_id": "guard-1",
                },
            }
        },
        SimulatedClock(),
    )
    assert isinstance(confluence, ConfluenceAdapter)
    assert confluence.enable_restriction_tests is True
    assert confluence.restriction_guard_account_id == "guard-1"

    salesforce = build_source(
        {
            "source": {
                "provider": "salesforce",
                "credentials": {
                    "instance_url": "https://example.my.salesforce.com",
                    "access_token": "token",
                    "share_object": "AccessProof_Test__Share",
                    "share_parent_field": "ParentId",
                    "share_principal_field": "UserOrGroupId",
                    "share_access_field": "AccessLevel",
                    "share_access_value": "Read",
                    "share_row_cause_field": "RowCause",
                    "share_row_cause_value": "Manual",
                },
            }
        },
        SimulatedClock(),
    )
    assert isinstance(salesforce, SalesforceAdapter)
    assert salesforce.share_object == "AccessProof_Test__Share"
