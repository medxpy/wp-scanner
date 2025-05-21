import pytest
from src.utils import helpers

def test_ensure_https():
    assert helpers.ensure_https("example.com") == "http://example.com"
    assert helpers.ensure_https("http://example.com") == "http://example.com"
    assert helpers.ensure_https("https://example.com") == "https://example.com"

def test_get_timestamp():
    ts = helpers.get_timestamp()
    assert isinstance(ts, str)
    assert "T" in ts or "-" in ts  # ISO format

def test_ensure_reports_dir(tmp_path, monkeypatch):
    # Patch Path to use a temp directory
    monkeypatch.setattr(helpers, "Path", lambda x="reports": tmp_path / "reports")
    reports_dir = helpers.ensure_reports_dir()
    assert reports_dir.exists()
    assert reports_dir.name == "reports"