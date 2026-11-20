import json
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from kielo_shared.cms_writers.client import CMSWritersClient


def _client_with_capture():
    client = CMSWritersClient("http://cms")
    response = MagicMock(status_code=200)
    response.raise_for_status = MagicMock()
    response.json = MagicMock(
        return_value={
            "data": {"meaning_action": "updated", "senses_upserted": 1},
        }
    )
    post = AsyncMock(return_value=response)
    client._client = MagicMock(post=post)
    return client, post


@pytest.mark.asyncio
async def test_translation_upsert_sends_cefr_level_when_given():
    client, post = _client_with_capture()
    await client.upsert_base_word_translation(
        uuid4(), "to say", source="lookup", cefr_level="B1"
    )
    payload = post.call_args.kwargs["json"]
    assert payload["cefr_level"] == "B1"
    assert json.dumps(payload)


@pytest.mark.asyncio
async def test_translation_upsert_omits_cefr_level_when_absent():
    client, post = _client_with_capture()
    await client.upsert_base_word_translation(uuid4(), "to say", source="lookup")
    assert "cefr_level" not in post.call_args.kwargs["json"]
