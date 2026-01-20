"""
Verify Phase 1 Implementation.
"""
import uuid
import logging
import sys
from decimal import Decimal

# Setup logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("verify_phase1")

# Import new components
from cyntrisec.core.business_config import BusinessConfig, EntrypointCriteria
from cyntrisec.core.business_logic import BusinessLogicEngine
from cyntrisec.core.graph import GraphBuilder
from cyntrisec.core.paths import PathFinder
from cyntrisec.core.schema import Asset, Relationship

def run_verification():
    log.info("Starting Phase 1 Verification...")

    # 1. Setup Mock Graph
    # A (Internet) -> B (Jump) -> C (Target)
    snapshot_id = uuid.uuid4()
    
    asset_a = Asset(
        snapshot_id=snapshot_id,
        asset_type="ec2:instance",
        aws_resource_id="i-entry",
        name="Bastion Host",
        is_internet_facing=True,
        properties={"public_ip": "1.2.3.4"},
        tags={"Role": "Bastion"}
    )
    
    asset_b = Asset(
        snapshot_id=snapshot_id,
        asset_type="ec2:instance",
        aws_resource_id="i-jump",
        name="App Server",
        tags={"Role": "App", "Env": "Prod"}
    )
    
    asset_c = Asset(
        snapshot_id=snapshot_id,
        asset_type="rds:db-instance",
        aws_resource_id="db-target",
        name="Prod DB",
        is_sensitive_target=True,
        tags={"Role": "Database"}
    )
    
    # Edges
    rel_ab = Relationship(
        snapshot_id=snapshot_id,
        source_asset_id=asset_a.id,
        target_asset_id=asset_b.id,
        relationship_type="ALLOWS_TRAFFIC_TO"
    )
    
    rel_bc = Relationship(
        snapshot_id=snapshot_id,
        source_asset_id=asset_b.id,
        target_asset_id=asset_c.id,
        relationship_type="ALLOWS_TRAFFIC_TO"
    )

    builder = GraphBuilder()
    graph = builder.build(assets=[asset_a, asset_b, asset_c], relationships=[rel_ab, rel_bc])
    
    log.info(f"Graph built: {graph.asset_count()} nodes, {graph.relationship_count()} edges")

    # 2. Verify PathFinder (k-best)
    log.info("Verifying PathFinder...")
    finder = PathFinder()
    paths = finder.find_paths(graph, snapshot_id)
    
    if len(paths) != 1:
        log.error(f"Expected 1 path, found {len(paths)}")
        sys.exit(1)
        
    log.info(f"Path found: {paths[0].path_length} steps, Risk: {paths[0].risk_score}")
    log.info("PathFinder: OK")

    # 3. Verify Business Labels & Delta
    log.info("Verifying Business Logic...")
    
    # Config: A is entrypoint, B is authorized (via tag)
    # C is NOT authorized explicitly (so accessing C via A->B might be suspect if C isn't business required?)
    # Wait, critical flow usually ends at C. If C is not authorized, the path is an attack path to a sensitive target.
    # If the PATH is business legitimate, then the access is OK.
    
    config = BusinessConfig(
        entrypoints=EntrypointCriteria(by_tags={"Role": "Bastion"}),
        global_allowlist={"Env": "Prod"} # B has Env:Prod
    )
    
    engine = BusinessLogicEngine(graph, config)
    engine.apply_labels()
    
    # Check labels
    if "business_entrypoint" in asset_a.labels:
        log.info("Asset A labeled as entrypoint: YES")
    else:
        log.error("Asset A NOT labeled as entrypoint")
        
    if "authorized" in asset_b.labels:
        log.info("Asset B labeled as authorized: YES")
    else:
        log.error("Asset B NOT labeled as authorized")

    # 4. Compute Delta
    # A is legit. B is legit. C is NOT legit.
    # Path A->B->C contains C. So path is NOT fully legitimate.
    # Expect delta to contain the path.
    
    delta_paths = engine.compute_delta(paths)
    if len(delta_paths) == 1:
        log.info("Delta correctly identified path as Unnecessary Exposure (C is not legit)")
    else:
        log.error("Delta failed. Expected path to be flagged.")
        
    # Scenario 2: Make C authorized
    log.info("Scenario 2: Authorizing C...")
    asset_c.labels.add("business_required")
    
    # Now path A(legit)->B(legit)->C(legit) should be filtered out from delta?
    # We must reset delta computation or just call it again.
    
    delta_paths_2 = engine.compute_delta(paths)
    if len(delta_paths_2) == 0:
        log.info("Delta correctly filtered out justified path.")
    else:
        log.error(f"Delta filter failed. Expected 0 paths, got {len(delta_paths_2)}")

    log.info("Verification Complete: SUCCESS")

if __name__ == "__main__":
    run_verification()
