from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[1]


def _read_json(relative_path: str) -> dict:
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def test_actor_references_input_output_and_dataset_schemas() -> None:
    actor = _read_json(".actor/actor.json")
    assert actor["input"] == "./input_schema.json"
    assert actor["output"] == "./output_schema.json"
    assert actor["storages"]["dataset"] == "./dataset_schema.json"


def test_output_and_dataset_metadata_cover_agent_outputs() -> None:
    output = _read_json(".actor/output_schema.json")
    assert set(output["properties"]) == {"results", "outputJson", "reportMarkdown"}
    assert output["properties"]["results"]["template"].endswith("/items")
    assert output["properties"]["outputJson"]["template"].endswith("/records/OUTPUT")
    assert output["properties"]["reportMarkdown"]["template"].endswith(
        "/records/REPORT.md"
    )

    dataset = _read_json(".actor/dataset_schema.json")
    required_fields = {
        "scanned_at",
        "server_url",
        "server_name",
        "protocol_version",
        "reachable",
        "tool_count",
        "score",
        "grade",
        "summary",
        "findings",
    }
    assert required_fields <= set(dataset["fields"]["properties"])
    assert required_fields <= set(dataset["fields"]["required"])


def test_dynamic_inputs_are_safe_by_default() -> None:
    schema = _read_json(".actor/input_schema.json")
    properties = schema["properties"]
    assert properties["runDynamicChecks"]["default"] is False
    assert properties["authorizedToTest"]["default"] is False
    assert properties["dynamicToolAllowlist"]["default"] == []
    assert "probeUrl" in properties
    assert "unauthenticated comparison" in properties["authHeader"]["description"]
