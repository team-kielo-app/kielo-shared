# kielo-shared

Shared Go (`github.com/team-kielo-app/kielo-shared`) and Python (`kielo_shared`) libraries for the Kielo services.

## TTS seam

`seam/tts` (Go) and `kielo_shared/seam/tts` (Python) turn `(text, voice, speed)` into audio bytes behind one `Provider` interface, one `Request`/`Result`, one `ErrorClass` vocabulary and one metrics decorator (`kielo_tts_calls_total`). Providers: OpenAI, ElevenLabs and Gemini.

### Gemini TTS

One implementation per language, used by the engine and both halves of kielo-convo:

| | Go | Python |
| --- | --- | --- |
| Provider | `seam/tts/gemini` (`gemini.New(apiKey, model, client)`) | `kielo_shared.seam.tts.GeminiTTSProvider(client, default_model=...)` |
| Language map | `gemini.LanguageTag`, `gemini.LanguageCodes` | `kielo_shared.seam.tts.language_tag`, `LANGUAGE_CODES` |
| WAV helpers | `AudioAsWAV`, `PCMToWAV`, `WAVToPCM`, `WAVToMP3` | `audio_as_wav`, `pcm16_to_wav`, `wav_to_pcm`, `wav_to_mp3` |

Rules the provider enforces:

- Gemini returns a complete WAV (`audio/wav`). It is passed through as received and never re-wrapped; only raw PCM (`audio/L16`) gets a header. Re-wrapping a WAV puts a buzz at the end of every clip.
- `contents` is the plain text only. The model speaks any instruction aloud, so `Request.instructions` is ignored; the language is pinned with `speech_config.language_code` from `Request.language_code` mapped through the shared tag map (`fi` -> `fi-FI`, `zh` -> `cmn-CN`, a region tag passes through).
- Output is `mp3` by default (ffmpeg transcode, mono 44.1 kHz 128k, `Request.speed` applied as `atempo` clamped to 0.5..2.0) or `wav` for sinks that want the WAV or its PCM frames.
- Failures are `ttsseam.Error` / `Error` with a bounded `ErrorClass` (timeout, connection, `http_4xx`, `http_5xx`, `read_body`, `empty_response`).
- Spend-guard admission stays with the caller (the provider makes the paid call).

The language map lives in `kielo_shared/seam/tts/languages.py` and `seam/tts/gemini/languages.go`. Both are tested against `seam/tts/gemini/testdata/language_tags.json`; change all three together.

Tests use mocks only (no network, no paid calls): `go test ./seam/tts/...` and `pytest tests/test_seam_tts_gemini.py`.
