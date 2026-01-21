import uuid
from unittest.mock import MagicMock, patch
from typer.testing import CliRunner
from cyntrisec.cli.analyze import analyze_app
from cyntrisec.core.schema import AttackPath
from cyntrisec.core.simulator import CanAccessResult

runner = CliRunner()

def test_analyze_paths_verification():
    """Test analyze paths command with verification flag."""
    
    # Mock data
    mock_snapshot = MagicMock()
    mock_snapshot.id = uuid.uuid4()
    
    # Create mock path
    mock_path = MagicMock(spec=AttackPath)
    mock_path.risk_score = 0.8
    mock_path.path_length = 3
    mock_path.attack_vector = "network"
    mock_path.entry_confidence = 1.0
    mock_path.impact_score = 1.0
    mock_path.confidence_level = "MED"
    mock_path.confidence_reason = "Test"
    mock_path.path_asset_ids = [uuid.uuid4(), uuid.uuid4()]
    
    # Mock model_dump for JSON serialization
    mock_path.model_dump.return_value = {
        "id": str(uuid.uuid4()),
        "source_asset_id": str(mock_path.path_asset_ids[0]),
        "target_asset_id": str(mock_path.path_asset_ids[1]),
        "path_asset_ids": [str(uid) for uid in mock_path.path_asset_ids],
        "path_relationship_ids": [str(uuid.uuid4())],
        "attack_vector": mock_path.attack_vector,
        "path_length": mock_path.path_length,
        "entry_confidence": mock_path.entry_confidence,
        "exploitability_score": 1.0,
        "impact_score": mock_path.impact_score,
        "risk_score": mock_path.risk_score,
        "confidence_level": mock_path.confidence_level,
        "confidence_reason": mock_path.confidence_reason,
        "attack_chain_relationship_ids": [],
        "context_relationship_ids": [],
    }

    with patch("cyntrisec.storage.FileSystemStorage") as MockStorage, \
         patch("cyntrisec.aws.credentials.CredentialProvider") as MockCreds, \
         patch("cyntrisec.core.simulator.PolicySimulator") as MockSim:
        
        storage = MockStorage.return_value
        storage.get_snapshot.return_value = mock_snapshot
        storage.get_attack_paths.return_value = [mock_path]

        # Mock assets
        asset1 = MagicMock()
        asset1.id = mock_path.path_asset_ids[0]
        asset1.asset_type = "iam:role"
        asset1.arn = "arn:aws:iam::123:role/Test"
        asset1.aws_resource_id = "arn:aws:iam::123:role/Test"
        asset1.name = "TestRole"
        
        asset2 = MagicMock()
        asset2.id = mock_path.path_asset_ids[1]
        asset2.asset_type = "s3:bucket"
        asset2.arn = "arn:aws:s3:::bucket"
        asset2.aws_resource_id = "arn:aws:s3:::bucket"
        asset2.name = "TestBucket"
        
        storage.get_assets.return_value = [asset1, asset2]
        
        # Mock simulation result
        sim_instance = MockSim.return_value
        sim_instance.can_access.return_value = CanAccessResult(
            principal_arn="arn:aws:iam::123:role/Test", 
            target_resource="arn:aws:s3:::bucket", 
            action="s3:GetObject", 
            can_access=True
        )
        
        # Run command with --verify
        result = runner.invoke(analyze_app, ["paths", "--scan", "latest", "--verify"])
        
        # Verify success
        assert result.exit_code == 0
        
        # Verify simulator was called
        sim_instance.can_access.assert_called_once()
        
        # Since we can't easily inspect the modified object inside the function,
        # we check if output reflects success if we could.
        # But here we mostly verify it runs without crashing and calls simulator.
        # To truly verify mutation, we'd need to inspect the object list passed to storage?
        # No, storage.get_attack_paths returns the list we created.
        
        # Check if confidence level was updated on the mock object
        assert mock_path.confidence_level == "HIGH"
        assert "Verified via AWS Policy Simulator" in mock_path.confidence_reason

def test_analyze_paths_table_output():
    """Test analyze paths basic table output."""
    mock_snapshot = MagicMock()
    mock_snapshot.id = uuid.uuid4()
    
    mock_path = MagicMock(spec=AttackPath)
    mock_path.risk_score = 0.8
    mock_path.path_length = 3
    mock_path.attack_vector = "network"
    mock_path.entry_confidence = 1.0
    mock_path.impact_score = 1.0
    mock_path.confidence_level = "MED"
    
    with patch("cyntrisec.storage.FileSystemStorage") as MockStorage:
        storage = MockStorage.return_value
        storage.get_snapshot.return_value = mock_snapshot
        storage.get_attack_paths.return_value = [mock_path]
        
        result = runner.invoke(analyze_app, ["paths", "--scan", "latest", "--format", "table"])
        
        assert result.exit_code == 0
        assert "Risk" in result.stdout
        assert "Conf" in result.stdout
        assert "0.800" in result.stdout
        assert "MED" in result.stdout
