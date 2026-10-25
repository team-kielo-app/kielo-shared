package gemini

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	ttsseam "github.com/team-kielo-app/kielo-shared/seam/tts"
)

const (
	defaultPCMRate   = 24000
	mp3Rate          = 44100
	transcodeTimeout = 30 * time.Second
	minTempo         = 0.5
	maxTempo         = 2.0
)

var pcmRate = regexp.MustCompile(`rate=(\d+)`)

func mimeKind(mime string) string {
	return strings.ToLower(strings.TrimSpace(strings.SplitN(mime, ";", 2)[0]))
}

// AudioAsWAV returns the response part as one WAV file. A WAV passes through
// untouched (never re-wrapped); raw PCM (audio/L16) gets a header.
func AudioAsWAV(mime string, data []byte) ([]byte, error) {
	switch mimeKind(mime) {
	case "audio/wav", "audio/x-wav", "audio/wave", "audio/vnd.wave":
		if !bytes.HasPrefix(data, []byte("RIFF")) {
			return nil, &ttsseam.Error{Class: ttsseam.ErrorClassReadBody, Err: errors.New("gemini tts: audio/wav without RIFF")}
		}
		return data, nil
	case "audio/l16", "audio/pcm":
		return PCMToWAV(data, pcmSampleRate(mime)), nil
	}
	return nil, &ttsseam.Error{Class: ttsseam.ErrorClassReadBody, Err: fmt.Errorf("gemini tts: unexpected mime %q", mime)}
}

func pcmSampleRate(mime string) int {
	if m := pcmRate.FindStringSubmatch(mime); m != nil {
		if rate, err := strconv.Atoi(m[1]); err == nil && rate > 0 {
			return rate
		}
	}
	return defaultPCMRate
}

// PCMToWAV wraps raw 16-bit mono PCM in a WAV header.
func PCMToWAV(pcm []byte, rate int) []byte {
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(36+len(pcm)))
	buf.WriteString("WAVEfmt ")
	for _, field := range []any{uint32(16), uint16(1), uint16(1), uint32(rate), uint32(rate * 2), uint16(2), uint16(16)} {
		_ = binary.Write(&buf, binary.LittleEndian, field)
	}
	buf.WriteString("data")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(pcm)))
	buf.Write(pcm)
	return buf.Bytes()
}

// WAVToPCM returns the data chunk of a WAV file (for sinks that take raw PCM).
func WAVToPCM(wav []byte) ([]byte, error) {
	if len(wav) < 12 || !bytes.HasPrefix(wav, []byte("RIFF")) || !bytes.Equal(wav[8:12], []byte("WAVE")) {
		return nil, &ttsseam.Error{Class: ttsseam.ErrorClassReadBody, Err: errors.New("gemini tts: not a WAV file")}
	}
	pos := 12
	for pos+8 <= len(wav) {
		id := string(wav[pos : pos+4])
		size := int(binary.LittleEndian.Uint32(wav[pos+4 : pos+8]))
		start := pos + 8
		if id == "data" {
			end := start + size
			if end > len(wav) || size < 0 {
				end = len(wav)
			}
			return wav[start:end], nil
		}
		pos = start + size + size%2
	}
	return nil, &ttsseam.Error{Class: ttsseam.ErrorClassReadBody, Err: errors.New("gemini tts: WAV has no data chunk")}
}

// WAVToMP3 transcodes a WAV to mono 44.1 kHz 128k MP3 with ffmpeg on PATH; a
// speed other than 1 applies atempo, clamped to 0.5..2.0.
func WAVToMP3(ctx context.Context, wav []byte, speed float64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, transcodeTimeout)
	defer cancel()
	args := []string{"-hide_banner", "-loglevel", "error", "-i", "pipe:0", "-vn", "-ac", "1"}
	if tempo := clampTempo(speed); tempo != 1 {
		args = append(args, "-filter:a", "atempo="+strconv.FormatFloat(tempo, 'f', 3, 64))
	}
	args = append(args, "-ar", strconv.Itoa(mp3Rate), "-codec:a", "libmp3lame", "-b:a", "128k", "-f", "mp3", "pipe:1")
	cmd := exec.CommandContext(ctx, "ffmpeg", args...)
	cmd.Stdin = bytes.NewReader(wav)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		class := ttsseam.ErrorClassUnknown
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			class = ttsseam.ErrorClassTimeout
		}
		return nil, &ttsseam.Error{Class: class, Err: fmt.Errorf("ffmpeg transcode failed: %w (%s)", err, strings.TrimSpace(stderr.String()))}
	}
	return out.Bytes(), nil
}

func clampTempo(speed float64) float64 {
	switch {
	case speed < minTempo:
		return minTempo
	case speed > maxTempo:
		return maxTempo
	}
	return speed
}
