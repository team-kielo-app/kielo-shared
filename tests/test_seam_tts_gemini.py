"""Gemini TTS provider and language map. Mocks only: no network, no paid calls."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from kielo_shared.seam.tts import Error, ErrorClass, Request, class_of
from kielo_shared.seam.tts.gemini_provider import (
    GeminiTTSProvider,
    GenAISpeechClient,
    audio_as_wav,
    pcm16_to_wav,
    wav_to_pcm,
)
from kielo_shared.seam.tts.languages import LANGUAGE_CODES, language_tag

FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "seam"
    / "tts"
    / "gemini"
    / "testdata"
    / "language_tags.json"
)


def _wav(pcm: bytes = b"\x01\x00" * 8) -> bytes:
    return pcm16_to_wav(pcm)


class FakeClient:
    def __init__(self, mime="audio/wav", data=None, exc=None):
        self.mime = mime
        self.data = _wav() if data is None else data
        self.exc = exc
        self.calls: list[dict] = []

    async def generate_speech(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc is not None:
            raise self.exc
        return self.mime, self.data


def _req(**kw) -> Request:
    base = {
        "text": "Hei maailma",
        "task": "t",
        "voice_id": "Kore",
        "language_code": "fi",
    }
    base.update(kw)
    return Request(**base)


def test_language_map_matches_shared_fixture():
    assert json.loads(FIXTURE.read_text()) == LANGUAGE_CODES


@pytest.mark.parametrize(
    "given,want",
    [
        ("fi", "fi-FI"),
        ("FI", "fi-FI"),
        (" zh ", "cmn-CN"),
        ("fi_FI", "fi-FI"),
        ("pt-BR", "pt-BR"),
        ("xx", "xx"),
        ("", ""),
    ],
)
def test_language_tag(given, want):
    assert language_tag(given) == want


@pytest.mark.asyncio
async def test_request_shape_and_language_pinning():
    client = FakeClient()
    provider = GeminiTTSProvider(client, default_model="m-default", output="wav")
    result = await provider.synthesize(
        _req(instructions="speak slowly", language_code="sv")
    )
    assert client.calls == [
        {
            "model": "m-default",
            "text": "Hei maailma",
            "language_code": "sv-SE",
            "voice_name": "Kore",
        }
    ]
    assert result.provider == "gemini-tts:m-default"


@pytest.mark.asyncio
async def test_request_model_overrides_default():
    client = FakeClient()
    provider = GeminiTTSProvider(client, default_model="a", output="wav")
    result = await provider.synthesize(_req(model="b"))
    assert client.calls[0]["model"] == "b"
    assert result.provider == "gemini-tts:b"


@pytest.mark.asyncio
async def test_wav_passes_through_untouched():
    wav = _wav(b"\x05\x00" * 100)
    provider = GeminiTTSProvider(FakeClient(data=wav), default_model="m", output="wav")
    result = await provider.synthesize(_req())
    assert result.audio == wav
    assert result.audio.count(b"RIFF") == 1


@pytest.mark.asyncio
async def test_mp3_output_transcodes_the_unwrapped_wav_with_speed():
    wav = _wav()
    seen = {}

    async def transcoder(data: bytes, speed: float) -> bytes:
        seen["wav"], seen["speed"] = data, speed
        return b"mp3"

    provider = GeminiTTSProvider(
        FakeClient(data=wav), default_model="m", transcoder=transcoder
    )
    result = await provider.synthesize(_req(speed=1.25))
    assert (result.audio, seen["wav"], seen["speed"]) == (b"mp3", wav, 1.25)
    await provider.synthesize(_req())
    assert seen["speed"] == 1.0


@pytest.mark.asyncio
async def test_raw_pcm_is_wrapped_once_with_its_rate():
    pcm = b"\x02\x00" * 10
    client = FakeClient(mime="audio/L16;codec=pcm;rate=16000", data=pcm)
    result = await GeminiTTSProvider(
        client, default_model="m", output="wav"
    ).synthesize(_req())
    assert result.audio[:4] == b"RIFF" and result.audio[44:] == pcm
    assert struct.unpack("<I", result.audio[24:28])[0] == 16000
    assert wav_to_pcm(result.audio) == pcm


def test_audio_as_wav_rejects_bad_clips():
    with pytest.raises(Error) as no_riff:
        audio_as_wav("audio/wav", b"not a wav")
    assert no_riff.value.error_class == ErrorClass.READ_BODY
    with pytest.raises(Error) as mime:
        audio_as_wav("audio/mpeg", b"x")
    assert mime.value.error_class == ErrorClass.READ_BODY


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "request_kwargs",
    [{"text": "  "}, {"voice_id": ""}],
)
async def test_validation_is_client_error_without_a_call(request_kwargs):
    client = FakeClient()
    provider = GeminiTTSProvider(client, default_model="m", output="wav")
    with pytest.raises(Error) as err:
        await provider.synthesize(_req(**request_kwargs))
    assert err.value.error_class == ErrorClass.CLIENT_ERROR
    assert client.calls == []


@pytest.mark.asyncio
async def test_missing_model_is_client_error():
    with pytest.raises(Error) as err:
        await GeminiTTSProvider(FakeClient()).synthesize(_req())
    assert err.value.error_class == ErrorClass.CLIENT_ERROR


class _Coded(Exception):
    def __init__(self, code):
        super().__init__(f"code {code}")
        self.code = code


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc,want",
    [
        (_Coded(429), ErrorClass.CLIENT_ERROR),
        (_Coded(503), ErrorClass.SERVER_ERROR),
        (TimeoutError("t"), ErrorClass.TIMEOUT),
        (httpx.ReadTimeout("t"), ErrorClass.TIMEOUT),
        (httpx.ConnectError("c"), ErrorClass.CONNECTION),
        (RuntimeError("?"), ErrorClass.UNKNOWN),
        (Error(ErrorClass.EMPTY_RESPONSE), ErrorClass.EMPTY_RESPONSE),
    ],
)
async def test_error_mapping(exc, want):
    provider = GeminiTTSProvider(FakeClient(exc=exc), default_model="m", output="wav")
    with pytest.raises(Error) as err:
        await provider.synthesize(_req())
    assert err.value.error_class == want
    assert class_of(err.value) == want.value


@pytest.mark.asyncio
async def test_empty_transcode_result_is_empty_response():
    async def transcoder(data, speed):
        return b""

    provider = GeminiTTSProvider(FakeClient(), default_model="m", transcoder=transcoder)
    with pytest.raises(Error) as err:
        await provider.synthesize(_req())
    assert err.value.error_class == ErrorClass.EMPTY_RESPONSE


def test_unknown_output_rejected():
    with pytest.raises(ValueError):
        GeminiTTSProvider(FakeClient(), output="flac")


@pytest.mark.asyncio
async def test_genai_client_request_shape():
    pytest.importorskip("google.genai")

    captured = {}

    inline = SimpleNamespace(mime_type="audio/wav", data=_wav())
    response = SimpleNamespace(
        candidates=[
            SimpleNamespace(
                content=SimpleNamespace(parts=[SimpleNamespace(inline_data=inline)])
            )
        ]
    )

    async def generate_content(**kwargs):
        captured.update(kwargs)
        return response

    fake = SimpleNamespace(
        aio=SimpleNamespace(models=SimpleNamespace(generate_content=generate_content))
    )

    client = GenAISpeechClient("k")
    client._client = fake
    mime, data = await client.generate_speech(
        model="m", text="Hei", language_code="fi-FI", voice_name="Kore"
    )
    assert mime == "audio/wav" and data[:4] == b"RIFF"
    assert captured["contents"] == "Hei"
    config = captured["config"]
    assert list(config.response_modalities) == ["AUDIO"]
    assert config.speech_config.language_code == "fi-FI"
    voice = config.speech_config.voice_config.prebuilt_voice_config
    assert voice.voice_name == "Kore"


@pytest.mark.asyncio
async def test_wav_to_mp3_with_local_ffmpeg():
    from kielo_shared.seam.tts.gemini_provider import _ffmpeg_executable, wav_to_mp3

    if not _ffmpeg_executable():
        pytest.skip("ffmpeg not available")
    mp3 = await wav_to_mp3(pcm16_to_wav(b"\x00\x00" * 24000), 1.5)
    assert mp3[:3] == b"ID3" or mp3[0] == 0xFF
