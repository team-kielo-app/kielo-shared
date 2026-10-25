"""Gemini TTS as a kielo_shared.seam.tts provider.

generate_content returns the clip as `inline_data`: mime `audio/wav` with a
COMPLETE WAV file (24 kHz mono, RIFF header and a trailing chunk). It is never
wrapped in a second header (that put a buzz at the end of every clip); only raw
PCM (`audio/L16`) gets one.

`contents` is the plain text and nothing else. The model speaks any instruction
aloud, so `Request.instructions` is deliberately ignored and the language is
pinned only through speech_config.language_code.

Output: ``"mp3"`` (default) transcodes the WAV with ffmpeg (the imageio-ffmpeg
wheel, else ffmpeg on PATH); ``"wav"`` returns the WAV as received.
"""

from __future__ import annotations

import asyncio
import io
import re
import shutil
import struct
import subprocess
import time
import wave
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

import httpx

from kielo_shared.seam.tts.languages import LANGUAGE_CODES, language_tag
from kielo_shared.seam.tts.types import Error, ErrorClass, Request, Result

GEMINI_PROVIDER = "gemini"

OUTPUT_MP3 = "mp3"
OUTPUT_WAV = "wav"

WAV_MIMES = frozenset({"audio/wav", "audio/x-wav", "audio/wave", "audio/vnd.wave"})
PCM_MIMES = frozenset({"audio/l16", "audio/pcm"})
DEFAULT_PCM_RATE = 24000
MP3_RATE = 44100
TRANSCODE_TIMEOUT_SECONDS = 30.0
DEFAULT_TIMEOUT_SECONDS = 30.0
MIN_TEMPO, MAX_TEMPO = 0.5, 2.0

__all__ = [
    "GEMINI_PROVIDER",
    "LANGUAGE_CODES",
    "OUTPUT_MP3",
    "OUTPUT_WAV",
    "GeminiSpeechClient",
    "GeminiTTSProvider",
    "GenAISpeechClient",
    "audio_as_wav",
    "language_tag",
    "pcm16_to_wav",
    "wav_to_mp3",
    "wav_to_pcm",
]


class GeminiSpeechClient(Protocol):
    async def generate_speech(
        self, *, model: str, text: str, language_code: str, voice_name: str
    ) -> tuple[str, bytes]:
        """(mime_type, data) of the clip."""


def pcm16_to_wav(pcm: bytes, rate: int = DEFAULT_PCM_RATE) -> bytes:
    header = (
        b"RIFF"
        + struct.pack("<I", 36 + len(pcm))
        + b"WAVEfmt "
        + struct.pack("<IHHIIHH", 16, 1, 1, rate, rate * 2, 2, 16)
        + b"data"
        + struct.pack("<I", len(pcm))
    )
    return header + pcm


def audio_as_wav(mime_type: str, data: bytes) -> bytes:
    """The response part as one WAV file: a WAV passes through untouched."""
    kind = (mime_type or "").split(";")[0].strip().lower()
    if kind in WAV_MIMES:
        if data[:4] != b"RIFF":
            raise Error(
                ErrorClass.READ_BODY, RuntimeError("gemini tts: audio/wav without RIFF")
            )
        return data
    if kind in PCM_MIMES:
        match = re.search(r"rate=(\d+)", mime_type or "")
        rate = int(match.group(1)) if match else DEFAULT_PCM_RATE
        return pcm16_to_wav(data, rate)
    raise Error(
        ErrorClass.READ_BODY, RuntimeError(f"gemini tts: unexpected mime {mime_type!r}")
    )


def wav_to_pcm(wav: bytes) -> bytes:
    """The PCM frames of a WAV file (for sinks that take raw PCM)."""
    try:
        with wave.open(io.BytesIO(wav), "rb") as clip:
            return clip.readframes(clip.getnframes())
    except (wave.Error, EOFError) as exc:
        raise Error(ErrorClass.READ_BODY, exc) from exc


def _ffmpeg_executable() -> str | None:
    try:
        import imageio_ffmpeg

        return str(imageio_ffmpeg.get_ffmpeg_exe())
    except (ImportError, RuntimeError):
        return shutil.which("ffmpeg")


def _clamp_tempo(speed: float) -> float:
    return max(MIN_TEMPO, min(MAX_TEMPO, speed))


def _wav_to_mp3_blocking(wav: bytes, speed: float) -> bytes:
    ffmpeg = _ffmpeg_executable()
    if not ffmpeg:
        raise Error(ErrorClass.UNKNOWN, RuntimeError("gemini tts: ffmpeg not found"))
    command = [ffmpeg, "-v", "error", "-i", "pipe:0", "-vn", "-ac", "1"]
    tempo = _clamp_tempo(speed)
    if abs(tempo - 1.0) > 1e-6:
        command += ["-af", f"atempo={tempo:.3f}"]
    command += ["-ar", str(MP3_RATE), "-b:a", "128k", "-f", "mp3", "pipe:1"]
    try:
        proc = subprocess.run(
            command,
            input=wav,
            capture_output=True,
            timeout=TRANSCODE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise Error(ErrorClass.TIMEOUT, exc) from exc
    if proc.returncode != 0 or not proc.stdout:
        detail = (proc.stderr or b"").decode("utf-8", "replace")[-200:]
        raise Error(
            ErrorClass.READ_BODY,
            RuntimeError(f"gemini tts: transcode failed: {detail}"),
        )
    return proc.stdout


async def wav_to_mp3(wav: bytes, speed: float = 1.0) -> bytes:
    """WAV -> mono 44.1 kHz 128k MP3; speed != 1 applies ffmpeg atempo (0.5..2.0)."""
    # Starting ffmpeg forks the process; a worker thread absorbs the fork.
    return await asyncio.to_thread(_wav_to_mp3_blocking, wav, speed)


class GenAISpeechClient:
    """google.genai, imported when first used (the package is only needed here)."""

    def __init__(
        self, api_key: str, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    ) -> None:
        self.api_key = api_key
        self._timeout_ms = int(max(1.0, timeout_seconds) * 1000)
        self._client: Any = None

    def _genai(self) -> Any:
        if self._client is None:
            from google import genai
            from google.genai import types

            self._client = genai.Client(
                api_key=self.api_key,
                http_options=types.HttpOptions(timeout=self._timeout_ms),
            )
        return self._client

    async def generate_speech(
        self, *, model: str, text: str, language_code: str, voice_name: str
    ) -> tuple[str, bytes]:
        from google.genai import types

        speech = types.SpeechConfig(
            voice_config=types.VoiceConfig(
                prebuilt_voice_config=types.PrebuiltVoiceConfig(voice_name=voice_name)
            ),
        )
        if language_code:
            speech.language_code = language_code
        response = await self._genai().aio.models.generate_content(
            model=model,
            contents=text,
            config=types.GenerateContentConfig(
                response_modalities=["AUDIO"], speech_config=speech
            ),
        )
        for candidate in response.candidates or []:
            for part in getattr(candidate.content, "parts", None) or []:
                inline = getattr(part, "inline_data", None)
                if inline is not None and inline.data:
                    return str(inline.mime_type or ""), bytes(inline.data)
        raise Error(
            ErrorClass.EMPTY_RESPONSE, RuntimeError("gemini tts: no audio part")
        )


def _error_class(exc: BaseException) -> ErrorClass:
    if isinstance(exc, (TimeoutError, httpx.TimeoutException)):
        return ErrorClass.TIMEOUT
    if isinstance(exc, (ConnectionError, httpx.RequestError)):
        return ErrorClass.CONNECTION
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return ErrorClass.SERVER_ERROR if code >= 500 else ErrorClass.CLIENT_ERROR
    return ErrorClass.UNKNOWN


Transcoder = Callable[[bytes, float], Awaitable[bytes]]


class GeminiTTSProvider:
    """Safe for concurrent use. ``synthesize(Request)`` pins the language from
    ``Request.language_code`` (via ``language_tag``), uses ``Request.voice_id`` as
    the prebuilt voice name and ``Request.model`` (else ``default_model``).
    """

    def __init__(
        self,
        client: GeminiSpeechClient,
        *,
        default_model: str = "",
        output: str = OUTPUT_MP3,
        transcoder: Transcoder | None = None,
    ) -> None:
        if output not in (OUTPUT_MP3, OUTPUT_WAV):
            raise ValueError(f"unknown gemini tts output {output!r}")
        self._client = client
        self._default_model = default_model
        self._output = output
        self._transcoder = transcoder or wav_to_mp3

    def provider_id(self, request: Request) -> str:
        return f"gemini-tts:{request.model or self._default_model}"

    async def synthesize(self, request: Request) -> Result:
        model = request.model or self._default_model
        if not request.text.strip():
            raise Error(ErrorClass.CLIENT_ERROR, RuntimeError("empty text"))
        if not model or not request.voice_id:
            raise Error(
                ErrorClass.CLIENT_ERROR,
                RuntimeError("gemini tts needs a model and a voice"),
            )
        started = time.perf_counter()
        try:
            mime_type, data = await self._client.generate_speech(
                model=model,
                text=request.text,
                language_code=language_tag(request.language_code),
                voice_name=request.voice_id,
            )
        except Error:
            raise
        except Exception as exc:
            raise Error(_error_class(exc), exc) from exc
        wav = audio_as_wav(mime_type, data)
        audio = wav
        if self._output == OUTPUT_MP3:
            speed = request.speed if request.speed > 0 else 1.0
            audio = await self._transcoder(wav, speed)
        if not audio:
            raise Error(
                ErrorClass.EMPTY_RESPONSE, RuntimeError("gemini tts returned no audio")
            )
        return Result(
            audio=audio,
            provider=self.provider_id(request),
            latency_ms=int((time.perf_counter() - started) * 1000),
        )
