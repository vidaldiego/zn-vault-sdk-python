from znvault.models.audit import AuditVerifyResult
import pytest
GOOD = {'status': 'verified', 'valid': True, 'reasons': [], 'errors': [], 'checkedEntries': 3, 'readEntries': 3, 'authenticatedEntries': 3, 'unverifiedEntries': 0, 'unsignedDetailsEntries': 0, 'scope': 'retained', 'interval': {'firstId': 5, 'lastId': 7}, 'completed': True, 'startedAt': '2026-11-01T00:00:00Z', 'finishedAt': '2026-11-01T00:00:01Z', 'consistency': 'repeatable_read', 'historicalCompleteness': 'not_proven'}
def test_preserves_evidence():
    result = AuditVerifyResult.from_dict(GOOD)
    assert result.valid is True
    assert result.entries_verified == 3
    assert result.evidence == GOOD
    assert result.first_entry_id == 5

@pytest.mark.parametrize("patch", [{"status": status} for status in ["invalid", "unverifiable", "error", "empty", "unknown", None]] + [{"scope": "tail"}, {"completed": False}, {"unverifiedEntries": 1}, {"unsignedDetailsEntries": 1}, {"readEntries": 0}])
def test_partial_or_unknown_never_succeeds(patch):
    assert AuditVerifyResult.from_dict({**GOOD, **patch}).valid is False

def test_legacy_without_evidence_is_not_verified():
    assert AuditVerifyResult.from_dict({"valid": True, "count": 9}).valid is False
