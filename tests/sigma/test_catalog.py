from tools.convert_sigma import CATALOG, render


def test_detection_catalog_is_up_to_date():
    """docs/detection-catalog.md is generated from the rules; regenerate it with
    `python -m tools.convert_sigma` after changing a rule or its test cases."""
    assert CATALOG.read_text(encoding="utf-8") == render()
