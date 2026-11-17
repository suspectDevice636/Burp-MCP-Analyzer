"""Guards for publishing the repository."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_gitignore_keeps_secrets_and_client_data_out():
    lines = {l.strip() for l in (ROOT / ".gitignore").read_text().splitlines()}
    for must in (".env", "data/", "*.db", ".venv"):
        assert must in lines, f".gitignore must list {must}"


def test_readme_opens_with_the_authorized_use_notice():
    text = (ROOT / "README.md").read_text()
    first_screen = text[:2500]
    assert "Authorized use only" in first_screen and "written permission" in first_screen
    assert "No warranty" in text


def test_ui_shows_the_notice():
    html = (ROOT / "ui" / "index.html").read_text()
    assert "Authorized use only" in html and "legal-footer" in html


def test_env_example_has_no_real_secrets():
    env = (ROOT / ".env.example").read_text()
    assert "API_TOKEN=\n" in env or env.rstrip().endswith("API_TOKEN=")
