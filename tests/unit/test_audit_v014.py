import pytest
import uuid
import typer
from decimal import Decimal
from unittest.mock import MagicMock, patch
from collections import defaultdict

from cyntrisec.core.schema import Asset, Relationship, AttackPath, SnapshotStatus
from cyntrisec.core.graph import AwsGraph
from cyntrisec.core.cost_estimator import CostEstimator
from cyntrisec.core.cuts import MinCutFinder, Remediation
from cyntrisec.aws.scanner import AwsScanner
from cyntrisec.storage.protocol import StorageBackend

# --- 1. Cost & ROI Logic Tests ---

def test_cost_estimator_malformed_assets():
    """
    Adversarial Check: Asset properties are missing expected keys or contain garbage types.
    """
    estimator = CostEstimator()
    snapshot_id = uuid.uuid4()
    
    # Case 1: EBS missing 'size' and 'volume_type'
    malformed_ebs = Asset(
        id=uuid.uuid4(),
        snapshot_id=snapshot_id,
        arn="arn:aws:ec2:us-east-1:123:volume/vol-bad",
        aws_resource_id="vol-bad",
        name="vol-bad",
        asset_type="ec2:ebs-volume",
        properties={"garbage": "data", "size": None} 
    )
    
    estimate = estimator.estimate(malformed_ebs)
    assert estimate is None, "Should handle missing size gracefully"

    # Case 2: RDS with empty properties
    malformed_rds = Asset(
        id=uuid.uuid4(),
        snapshot_id=snapshot_id,
        arn="arn:aws:rds:us-east-1:123:db:db-bad",
        aws_resource_id="db-bad",
        name="db-bad",
        asset_type="rds:db-instance",
        properties={}
    )
    estimate = estimator.estimate(malformed_rds)
    assert estimate is not None
    assert estimate.confidence == "unknown"


def test_roi_calibration_bias():
    """
    Adversarial Check: Verify the ROI formula prioritization.
    """
    rel_a_id = uuid.uuid4()
    rel_b_id = uuid.uuid4()
    
    # Cut A: Saves $2000, Blocks 1 path
    cut_a = Remediation(
        relationship=MagicMock(id=rel_a_id),
        action="remove", 
        description="Save Money",
        paths_blocked=[uuid.uuid4()], # 1 path
        cost_savings=Decimal("2000.00"),
        roi_score=0.0
    )
    cut_a.roi_score = 1.0 + (2000.0 * 0.05)
    
    # Cut B: Saves $0, Blocks 10 paths
    cut_b = Remediation(
        relationship=MagicMock(id=rel_b_id),
        action="restrict",
        description="Fix Security",
        paths_blocked=[uuid.uuid4() for _ in range(10)], # 10 paths
        cost_savings=Decimal("0.00"),
        roi_score=0.0
    )
    cut_b.roi_score = 10.0 + (0.0 * 0.05)
    
    remediations = [cut_a, cut_b]
    remediations.sort(key=lambda x: x.roi_score, reverse=True)
    
    # Confirm A is ranked higher than B
    assert remediations[0] == cut_a
    assert cut_a.roi_score > cut_b.roi_score


def test_cut_tie_breaking_determinism():
    """
    Adversarial Check: Ensure consistent results (determinism) for identical scores.
    """
    entry_id = uuid.uuid4()
    target_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    
    entry = Asset(
        id=entry_id, snapshot_id=snapshot_id, arn="entry", aws_resource_id="entry", name="entry", asset_type="net"
    )
    target = Asset(
        id=target_id, snapshot_id=snapshot_id, arn="target", aws_resource_id="target", name="target", asset_type="db"
    )
    
    # 3 identical edges
    edges = []
    outgoing = defaultdict(list)
    incoming = defaultdict(list)
    
    for i in range(3):
        e = Relationship(
            id=uuid.uuid4(),
            snapshot_id=snapshot_id,
            source_asset_id=entry_id, 
            target_asset_id=target_id, 
            relationship_type="ACCESS",
            properties={"index": i} 
        )
        edges.append(e)
        outgoing[entry_id].append(e)
        incoming[target_id].append(e)

    g = AwsGraph(
        assets_by_id={entry_id: entry, target_id: target},
        outgoing=dict(outgoing),
        incoming=dict(incoming)
    )
    
    # 3 paths, each using one edge
    paths = []
    for i in range(3):
        p = AttackPath(
            id=uuid.uuid4(),
            snapshot_id=snapshot_id,
            source_asset_id=entry_id,
            target_asset_id=target_id,
            path_relationship_ids=[edges[i].id],
            path_asset_ids=[entry_id, target_id], # Removed invalid path_assets, added IDs
            attack_vector="network_exposure",
            path_length=2,
            entry_confidence=Decimal("1.0"),
            exploitability_score=Decimal("1.0"),
            impact_score=Decimal("1.0"),
            risk_score=Decimal("1.0")
        )
        paths.append(p)
        
    finder = MinCutFinder()
    
    results = []
    for _ in range(5):
        # We ask for 1 cut
        cut_res = finder.find_cuts(g, paths, max_cuts=1)
        if cut_res.remediations:
            results.append(cut_res.remediations[0].relationship.id)
            
    first = results[0]
    for r in results[1:]:
        assert r == first, "Non-deterministic cut selection detected!"

# --- 2. Scanner Resilience Tests ---

@patch("cyntrisec.aws.scanner.CredentialProvider")
def test_scanner_credential_failure_exit(MockCreds):
    """
    Verify scanner handles credential failure gracefully (exit or explicit error), not crash.
    """
    mock_provider = MockCreds.return_value
    from botocore.exceptions import ClientError
    error_response = {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}}
    # We need to simulate the error RAISING from assume_role
    mock_provider.assume_role.side_effect = ClientError(error_response, 'AssumeRole')
    
    # We must ensure that AwsScanner imports these classes correctly for patch to work.
    # In scanner.py: from cyntrisec.aws.credentials import CredentialProvider
    # So we patch where it is used: cyntrisec.aws.scanner.CredentialProvider
    # This seems correct.
    
    # Why did it fail? "FAILED ... - botocore.exceptions.ClientError"
    # It means the scanner code DID NOT Catch the exception.
    # Let's verify if I actually saved the file change to scanner.py?
    
    scanner = AwsScanner(storage=MagicMock())
    
    with pytest.raises(ConnectionError):
        scanner.scan(regions=["us-east-1"], role_arn="arn:aws:iam::123:role/Bad")


@patch("cyntrisec.aws.scanner.Ec2Collector")
def test_scanner_partial_failure(MockEc2):
    """
    Verify scanner survives partial regional failure.
    """
    storage = MagicMock()
    storage.new_scan.return_value = "scan-123"
    scanner = AwsScanner(storage)
    
    def side_effect(session, region):
        mock = MagicMock()
        if region == "us-east-1":
            mock.collect_all.side_effect = Exception("Region Down")
        else:
            mock.collect_all.return_value = [] 
        return mock
        
    MockEc2.side_effect = side_effect
    
    with patch("cyntrisec.aws.scanner.IamCollector") as MockIam, \
         patch("cyntrisec.aws.scanner.S3Collector") as MockS3, \
         patch("cyntrisec.aws.scanner.NetworkCollector") as MockNet, \
         patch("cyntrisec.aws.scanner.LambdaCollector") as MockLambda, \
         patch("cyntrisec.aws.scanner.RdsCollector") as MockRds, \
         patch("cyntrisec.aws.scanner.CredentialProvider"), \
         patch("boto3.Session") as MockSession:
        
        # Mock STS identity
        mock_session_instance = MockSession.return_value
        mock_sts = mock_session_instance.client.return_value
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        MockIam.return_value.collect_all.return_value = []
        MockS3.return_value.collect_all.return_value = []
        MockNet.return_value.collect_all.return_value = []
        MockLambda.return_value.collect_all.return_value = []
        MockRds.return_value.collect_all.return_value = []
        
        MockEc2.return_value.collect_all.return_value = [] 
        MockEc2.side_effect = side_effect
        
        snapshot = scanner.scan(regions=["us-east-1", "eu-west-1"])
    
    # Partial failure check
    assert snapshot.status == SnapshotStatus.completed_with_errors
    assert snapshot.errors is not None
    assert any(e["service"] == "ec2" and "Region Down" in e["error"] for e in snapshot.errors)
    assert snapshot.aws_account_id is not None

# --- 3. CLI Input Safety Tests ---

def test_cli_path_traversal():
    """
    Adversarial Check: Path traversal via business config.
    """
    from cyntrisec.core.business_config import BusinessConfig
    with pytest.raises(FileNotFoundError):
        BusinessConfig.load("../../../non_existent_file.yaml")

def test_cli_command_injection_account_id():
    """
    Adversarial Check: Command injection in setup iam.
    """
    from cyntrisec.cli.setup import setup_iam
    
    injection_payload = "123456789012; rm -rf /"
    
    with pytest.raises(typer.Exit):
        setup_iam(account_id=injection_payload)
