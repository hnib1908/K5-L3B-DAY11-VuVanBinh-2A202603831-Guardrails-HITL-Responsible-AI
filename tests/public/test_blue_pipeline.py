"""Exercise Checkpoint 3 through the Blue runner with a local model stub."""
import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from assignment.pipeline import build_observability, build_production_plugins, run_assignment_suite
from core.config import BLUE_MODEL
from core.openai_runtime import OpenAIRunner


def test_blue_pipeline_keeps_sensitive_model_output_out_of_artifacts(tmp_path, monkeypatch):
    private_reply = "Please use test@example.com or call 0901234567."
    model_calls = []

    def create_completion(**kwargs):
        model_calls.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(
            message=SimpleNamespace(content=private_reply),
        )])

    fake_client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=create_completion),
    ))
    monkeypatch.setattr(OpenAIRunner, "_client", lambda self: fake_client)
    plugins = build_production_plugins()
    audit, monitor = build_observability()
    monitor.rate_limit_hit_threshold = 4
    pipeline = {"plugins": plugins, "audit": audit, "monitor": monitor}

    result = asyncio.run(run_assignment_suite(pipeline, output_dir=tmp_path))

    schema = json.loads((ROOT / "schemas" / "results.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(result, schema)
    assert len(model_calls) == 6
    assert all(call["model"] == BLUE_MODEL for call in model_calls)
    assert all(
        not row["blocked"]
        and row["layer"] == "output_guardrail"
        and row["response_preview"].count("[REDACTED]") == 2
        for row in result["safe_queries"]
    )
    assert all(row["blocked"] and row["layer"] == "input_guardrail"
               for row in result["attack_queries"])
    assert result["rate_limit"] == {
        "max_requests": 10, "window_seconds": 60, "sent": 15, "passed": 10, "blocked": 5,
    }

    audit_text = (tmp_path / "audit_log.json").read_text(encoding="utf-8")
    result_text = (tmp_path / "results.json").read_text(encoding="utf-8")
    metrics = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    audit_rows = json.loads(audit_text)
    assert json.loads(result_text) == result
    assert len(audit_rows) == metrics["total_requests"] == 30
    assert len({row["request_id"] for row in audit_rows}) == 30
    assert all(row["latency_ms"] >= 0 for row in audit_rows)
    assert metrics["blocked_requests"] == 14
    assert metrics["rate_limit_hits"] == 5
    assert metrics["alerts"][0]["metric"] == "rate_limit_hits"
    for sensitive in ("test@example.com", "0901234567"):
        assert sensitive not in audit_text
        assert sensitive not in result_text
