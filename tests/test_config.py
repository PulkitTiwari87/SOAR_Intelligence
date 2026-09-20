"""Configuration safety: .env.example must be safe to copy, production must refuse weak secrets."""
import re

import pytest

from soar.config import ROOT, Settings

EXAMPLE = ROOT / ".env.example"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """conftest sets test values in os.environ; these tests need Settings to see only what they pass."""
    for name in ("SOAR_ENV", "JWT_SECRET", "INGEST_API_KEY", "LLM_PROVIDER", "DATABASE_URL", "SOAR_ADMIN_PASSWORD",
                 "AUTO_EXECUTE_MAX_RISK"):
        monkeypatch.delenv(name, raising=False)


def test_env_example_has_no_inline_comments_that_dotenv_would_read_as_values():
    for n, line in enumerate(EXAMPLE.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        assert not re.search(r"=\s*.*\s#", line) and "= #" not in line, f".env.example:{n} has an inline comment: {line}"


def test_env_example_loads_and_every_secret_is_empty():
    s = Settings(_env_file=str(EXAMPLE))
    for secret in ("llm_api_key", "gemini_api_key", "openai_api_key", "anthropic_api_key", "wazuh_api_pass",
                   "thehive_api_key", "misp_api_key", "ingest_api_key", "admin_password"):
        assert getattr(s, secret) == "", f"{secret} must be empty in .env.example"
    assert s.env == "development" and s.auto_execute_max_risk == "low" and s.wazuh_verify_tls is True
    assert not s.protected_ips.startswith("#")


def test_production_refuses_missing_or_short_jwt_secret():
    with pytest.raises(ValueError, match="JWT_SECRET"):
        Settings(_env_file=None, SOAR_ENV="production")
    with pytest.raises(ValueError, match="32"):
        Settings(_env_file=None, SOAR_ENV="production", JWT_SECRET="short")
    assert Settings(_env_file=None, SOAR_ENV="production", JWT_SECRET="x" * 40).env == "production"


def test_development_generates_an_ephemeral_secret():
    a, b = Settings(_env_file=None), Settings(_env_file=None)
    assert len(a.jwt_secret) >= 32 and a.jwt_secret != b.jwt_secret


def test_invalid_auto_execute_ceiling_is_rejected():
    with pytest.raises(ValueError):
        Settings(_env_file=None, AUTO_EXECUTE_MAX_RISK="everything")


def test_no_known_leaked_secrets_remain_in_the_working_tree():
    """Guard: literals that shipped in the original repository must not reappear in source or config."""
    banned = ["MyS3cr37P450r", "soar-api-key-2026", "cortex-api-key-2026", "soar-dashboard-secret-key",
              "mZMfJp3OWSvn3", "th1s1s4v3rys3cr3t"]
    skip_dirs = {"node_modules", ".git", "__pycache__", "models", "data", ".claude", "dist"}
    for path in ROOT.rglob("*"):
        if path.is_dir() or skip_dirs & set(path.relative_to(ROOT).parts) or path.suffix in {".png", ".pdf", ".ico", ".svg"}:
            continue
        if path.name == "test_config.py" or path.stat().st_size > 2_000_000:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for b in banned:
            assert b not in text, f"{b!r} found in {path.relative_to(ROOT)}"
