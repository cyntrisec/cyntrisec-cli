from __future__ import annotations

from cyntrisec.cli.ask import _classify_query, _extract_entities


def test_classify_attack_paths():
    assert _classify_query("what attack paths reach prod")["intent"] == "attack_paths"


def test_classify_public_s3():
    result = _classify_query("show public s3 buckets")
    assert result["intent"] == "public_s3"
    assert result["scores"]["public_s3"] > 0


def test_classify_admin_roles():
    assert _classify_query("which roles are admin")["intent"] == "admin_roles"


def test_classify_compliance():
    assert _classify_query("check cis compliance")["intent"] == "compliance"


def test_classify_default():
    assert _classify_query("hello world")["intent"] == "general"


def test_extract_entities_buckets_roles_and_arns():
    query = "can AdminRole access s3://prod-bucket or arn:aws:s3:::another"
    entities = _extract_entities(query)
    assert "AdminRole" in entities["roles"]
    assert "s3://prod-bucket" in entities["buckets"]
    assert any(a.startswith("arn:aws:s3:::another") for a in entities["arns"])
