package media

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseStorageURL(t *testing.T) {
	cases := map[string]StorageObject{
		"https://storage.googleapis.com/kielo-media-processor/tts/base-words/äiti/m1/main.mp3":               {"kielo-media-processor", "tts/base-words/äiti/m1/main.mp3"},
		"https://media.kielo.app/kielo-media-signed-p/support/u/m/main.webp?Expires=1&KeyName=k&Signature=s": {"kielo-media-signed-p", "support/u/m/main.webp"},
		"https://edge.kielo.app/cdn/kielo-media-processor-p/kielotv/e/m/hls/master.m3u8":                     {"kielo-media-processor-p", "kielotv/e/m/hls/master.m3u8"},
		"https://edge.kielo.app/gcs/kielo-media-processor-p/assets/roadmap/a.webp":                           {"kielo-media-processor-p", "assets/roadmap/a.webp"},
		"http://localhost:4443/storage/v1/b/kielo-media-processor/o/processed%2Fabc%2Fmain.webp?alt=media":   {"kielo-media-processor", "processed/abc/main.webp"},
		"http://10.0.0.2:4443/download/storage/v1/b/b1/o/a%2Fb.png":                                          {"b1", "a/b.png"},
		"http://localhost:8097/kielo-media-processor/curriculum/t/m/main.webp":                               {"kielo-media-processor", "curriculum/t/m/main.webp"},
		"https://storage.googleapis.com/kielo-media-processor/tts/base-words/%C3%A4iti/m1/main.mp3":          {"kielo-media-processor", "tts/base-words/äiti/m1/main.mp3"},
	}
	for raw, want := range cases {
		got, ok := ParseStorageURL(raw)
		assert.True(t, ok, raw)
		assert.Equal(t, want, got, raw)
	}
	for _, raw := range []string{"", "not a url", "/relative/path.webp", "https://media.kielo.app/", "ftp://x/y/z", "https://cdn.example.com/onlybucket"} {
		_, ok := ParseStorageURL(raw)
		assert.False(t, ok, raw)
	}
}
