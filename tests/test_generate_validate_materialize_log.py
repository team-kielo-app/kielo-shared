"""A refused structured output says which fields failed, and for a
model-level check which check it was, without logging the output itself."""

from __future__ import annotations

import logging

import pytest
from pydantic import BaseModel, model_validator

from kielo_shared.llm.generate_validate import _try_materialize


class _Card(BaseModel):
    prompt: str
    distractors: list[str] = []

    @model_validator(mode="after")
    def require_distractors(self) -> "_Card":
        if len(self.distractors) < 2:
            raise ValueError("Provide at least 2 distinct distractors")
        return self


def test_a_model_level_check_names_itself(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="kielo_shared.llm.generate_validate"):
        assert (
            _try_materialize(_Card, {"prompt": "Mitä kuuluu?", "distractors": ["x"]})
            is None
        )
    line = caplog.records[-1].getMessage()
    assert "rejected keys=['distractors', 'prompt']" in line
    assert "Provide at least 2 distinct distractors" in line
    assert "Mitä kuuluu?" not in line


def test_a_field_error_logs_no_message(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="kielo_shared.llm.generate_validate"):
        assert _try_materialize(_Card, {"prompt": 123456789}) is None
    line = caplog.records[-1].getMessage()
    assert "prompt:string_type" in line
    assert "123456789" not in line
