"""Tests that kielo_shared.locale.* remains importable when optional
HTTP framework dependencies (starlette, fastapi) are absent.

Background: 2026-05-24 starlette-lazy-import fix
(kielo-shared cfac2b0) addressed a regression where importing
``kielo_shared.locale.capability`` in a non-HTTP consumer (the
kielo-convo livekit agent runs without starlette installed)
triggered the package ``__init__.py`` which eagerly pulled
``support_language.py`` → ``starlette.requests.Request``.

These tests pin the contract: the registry-lookup path
(``lookup_capability``, ``supported_capabilities``) must not require
starlette/fastapi at import time. HTTP-specific modules
(``kielo_shared.locale.fastapi``, ``kielo_shared.middleware.*``)
remain free to import starlette eagerly — they're FastAPI-specific
helpers and consumers that use them MUST have starlette installed
anyway.

Implementation note: each test spawns a fresh Python subprocess
with a sys.path that lacks starlette/fastapi. This is much cleaner
than mutating ``sys.modules`` in-process — that approach leaked
state into subsequent tests in the same pytest session.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import unittest
from pathlib import Path


_KIELO_SHARED_ROOT = Path(__file__).resolve().parents[1]


def _run_in_clean_subprocess(
    script: str,
    *,
    hide_modules: tuple[str, ...] = (),
) -> tuple[int, str, str]:
    """Run ``script`` in a fresh Python subprocess that has ``hide_modules``
    blocked at the import system level.

    Returns (returncode, stdout, stderr) for the test to assert on.
    """
    # Prepend a sys.meta_path finder that raises ModuleNotFoundError
    # for any module name in hide_modules (or any of its submodules).
    # This is the cleanest way to simulate "starlette isn't installed"
    # without uninstalling it from the venv.
    preamble = textwrap.dedent(f"""
        import sys
        _BLOCKED = {hide_modules!r}

        class _BlockingFinder:
            def find_spec(self, name, path, target=None):
                for blocked in _BLOCKED:
                    if name == blocked or name.startswith(blocked + "."):
                        raise ModuleNotFoundError(
                            f"No module named {{name!r}} (blocked by test)"
                        )
                return None

        sys.meta_path.insert(0, _BlockingFinder())
    """).strip()
    full_script = preamble + "\n" + script
    result = subprocess.run(
        [sys.executable, "-c", full_script],
        capture_output=True,
        text=True,
        cwd=str(_KIELO_SHARED_ROOT),
        timeout=30,
    )
    return result.returncode, result.stdout, result.stderr


class TestNonHttpImportSafety(unittest.TestCase):
    """Each non-HTTP-safe module must import cleanly without starlette."""

    def test_capability_imports_without_starlette(self):
        """The regression that bit 2026-05-24: importing
        kielo_shared.locale.capability from a non-HTTP service
        must not require starlette."""
        rc, out, err = _run_in_clean_subprocess(
            textwrap.dedent("""
                from kielo_shared.locale.capability import lookup_capability
                cap = lookup_capability("fi")
                assert cap is not None
                assert cap.code == "fi"
                print("OK")
            """),
            hide_modules=("starlette",),
        )
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        self.assertIn("OK", out)

    def test_locale_init_imports_without_starlette(self):
        """The package ``__init__.py`` must not eagerly import
        starlette-dependent submodules."""
        rc, out, err = _run_in_clean_subprocess(
            textwrap.dedent("""
                import kielo_shared.locale
                # __init__.py re-exports support_language.* helpers.
                assert hasattr(kielo_shared.locale, "resolve_support_language_stateless")
                assert hasattr(kielo_shared.locale, "is_supported_support_language")
                print("OK")
            """),
            hide_modules=("starlette",),
        )
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        self.assertIn("OK", out)

    def test_support_language_imports_without_starlette(self):
        rc, out, err = _run_in_clean_subprocess(
            textwrap.dedent("""
                from kielo_shared.locale.support_language import (
                    resolve_support_language_stateless,
                    is_supported_support_language,
                )
                assert callable(resolve_support_language_stateless)
                assert callable(is_supported_support_language)
                print("OK")
            """),
            hide_modules=("starlette",),
        )
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        self.assertIn("OK", out)

    def test_locale_constants_imports_without_starlette(self):
        rc, out, err = _run_in_clean_subprocess(
            textwrap.dedent("""
                from kielo_shared.locale_constants import SUPPORTED_LEARNING_LANGUAGES
                assert "fi" in SUPPORTED_LEARNING_LANGUAGES
                assert "sv" in SUPPORTED_LEARNING_LANGUAGES
                print("OK")
            """),
            hide_modules=("starlette",),
        )
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        self.assertIn("OK", out)


class TestNonHttpFastApiImportSafety(unittest.TestCase):
    """Same as above but with both starlette AND fastapi hidden — even
    stricter simulation of a non-HTTP environment."""

    def test_capability_imports_without_starlette_or_fastapi(self):
        rc, out, err = _run_in_clean_subprocess(
            textwrap.dedent("""
                from kielo_shared.locale.capability import lookup_capability
                cap = lookup_capability("sv")
                assert cap is not None
                assert cap.code == "sv"
                print("OK")
            """),
            hide_modules=("starlette", "fastapi"),
        )
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        self.assertIn("OK", out)


class TestHttpOnlyModulesGracefullyFail(unittest.TestCase):
    """HTTP-framework helpers ARE allowed to require starlette. They
    should raise ModuleNotFoundError cleanly when starlette is absent.
    We test this so a future change doesn't accidentally make these
    modules import-safe (e.g. by bringing in a starlette-stub that
    silently succeeds)."""

    def test_locale_fastapi_requires_starlette(self):
        rc, out, err = _run_in_clean_subprocess(
            textwrap.dedent("""
                try:
                    import kielo_shared.locale.fastapi
                except ModuleNotFoundError as exc:
                    if "starlette" in str(exc):
                        print("EXPECTED_FAIL")
                    else:
                        raise
            """),
            hide_modules=("starlette",),
        )
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        self.assertIn("EXPECTED_FAIL", out)

    def test_middleware_legacy_alias_requires_starlette(self):
        rc, out, err = _run_in_clean_subprocess(
            textwrap.dedent("""
                try:
                    import kielo_shared.middleware.legacy_alias
                except ModuleNotFoundError as exc:
                    if "starlette" in str(exc):
                        print("EXPECTED_FAIL")
                    else:
                        raise
            """),
            hide_modules=("starlette",),
        )
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        self.assertIn("EXPECTED_FAIL", out)


if __name__ == "__main__":
    unittest.main()
