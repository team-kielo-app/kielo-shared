"""No code in kielo-shared names an OpenAI model retired in January 2027.

OpenAI retires tts-1, tts-1-hd and gpt-4o-mini-tts on 2027-01-06, and gpt-4o,
gpt-4o-mini, gpt-4.1 and gpt-4.1-mini on 2027-01-14. The model a call uses comes
from llm routes / tts_routes rows, never from a default here. Comments and
tests may mention the names; code may not.
"""

from __future__ import annotations

import datetime
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

PATTERN = re.compile(r"gpt-?4o|gpt-?4\.1|\btts-1\b", re.IGNORECASE)
SUFFIXES = {".py", ".go", ".ts", ".yaml", ".yml", ".toml", ".json", ".env"}
SKIP_DIRS = {
    "tests",
    "testdata",
    "build",
    "dist",
    "node_modules",
    ".git",
    ".venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
COMMENT_PREFIXES = ("#", "//", "*")

# The compiled price fallback still prices the models prod routes name until
# OpenAI retires them; the test fails on the shutdown day until they go.
GPT4O_SHUTDOWN = datetime.date(2027, 1, 14)
PRICE_TABLES = {
    Path("kielo_shared/llm/pricing.py"),
    Path("llmroute/spend.go"),
}

EXPECTED = (
    REPO_ROOT / "kielo_shared",
    REPO_ROOT / "seam" / "tts" / "openai.go",
    REPO_ROOT / "llmroute" / "spend.go",
)


def _is_code_file(path: Path) -> bool:
    if path.name.endswith("_test.go") or path.name.endswith(".test.ts"):
        return False
    return path.suffix in SUFFIXES or path.name.startswith(".env")


def _scan(root: Path, today: datetime.date | None = None) -> list[str]:
    today = today or datetime.date.today()
    hits: list[str] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if not path.is_file() or not _is_code_file(path):
            continue
        if any(part in SKIP_DIRS for part in rel.parts[:-1]):
            continue
        for number, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            stripped = line.strip()
            if not PATTERN.search(line) or stripped.startswith(COMMENT_PREFIXES):
                continue
            if rel in PRICE_TABLES and today < GPT4O_SHUTDOWN:
                continue
            hits.append(f"{rel}:{number}: {stripped}")
    return hits


def test_the_scan_has_everything_it_expects_to_scan():
    missing = [str(p) for p in EXPECTED if not p.exists()]
    assert not missing, "missing:\n" + "\n".join(missing)


def test_kielo_shared_code_names_no_retired_openai_model():
    hits = _scan(REPO_ROOT)
    assert not hits, (
        "OpenAI model names come from llm routes / tts_routes rows, not code "
        "defaults:\n" + "\n".join(hits)
    )


def test_the_price_table_exception_expires_with_the_models():
    after = _scan(REPO_ROOT, today=GPT4O_SHUTDOWN)
    stale = [h for h in after if Path(h.split(":")[0]) in PRICE_TABLES]
    if datetime.date.today() >= GPT4O_SHUTDOWN:
        assert not stale, (
            "drop the retired models from the price tables:\n" + "\n".join(stale)
        )
    else:
        assert (
            stale
        ), "the price tables no longer list a retired model: drop PRICE_TABLES"


def test_the_scan_catches_planted_names_and_skips_comments_and_tests(tmp_path):
    planted = {
        "a.py": 'MODEL = "gpt-4o"',
        "b.go": 'const m = "gpt-4o-mini-tts"',
        "c.yaml": "model: tts-1",
        "d.ts": 'const m = "gpt-4.1-mini";',
        "e.json": '{"model": "tts-1-hd"}',
        "f.py": 'PROVIDER = "openai:gpt4o_mini"',
    }
    for name, text in planted.items():
        (tmp_path / name).write_text(text + "\n")
    (tmp_path / "ok.py").write_text('# gpt-4o retires\nMODEL = "gpt-6-luna"\n')
    (tmp_path / "ok.go").write_text('// tts-1 rejects instructions\nconst m = ""\n')
    (tmp_path / "x_test.go").write_text('const m = "gpt-4o"\n')
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text('MODEL = "gpt-4o"\n')
    found = {h.split(":")[0] for h in _scan(tmp_path)}
    assert found == set(planted)
