from tools.attack_coverage import LAYER, REPORT, by_technique, collect, render_layer, render_report, validate


def test_every_technique_id_exists_in_attack():
    assert validate(collect()) == []


def test_every_engine_contributes():
    assert {d.engine for d in collect()} == {"Wazuh", "Sigma", "Suricata", "YARA"}


def test_generated_coverage_files_are_up_to_date():
    """Regenerate with `python -m tools.attack_coverage` after changing rules."""
    detections = collect()
    assert REPORT.read_text(encoding="utf-8") == render_report(detections)
    assert LAYER.read_text(encoding="utf-8") == render_layer(by_technique(detections))
