package db

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestValidateLanguageIdent_AcceptsISOCodes(t *testing.T) {
	for _, lang := range []string{"fi", "sv", "vi", "en", "zh", "pt"} {
		if err := ValidateLanguageIdent(lang); err != nil {
			t.Errorf("ValidateLanguageIdent(%q) = %v, want nil", lang, err)
		}
	}
}

func TestValidateLanguageIdent_RejectsGarbage(t *testing.T) {
	for _, lang := range []string{"FI", "f", "english", "fi-en", "fi; DROP", "", "fi_cn", "zh_CN", "pt_BR"} {
		if err := ValidateLanguageIdent(lang); err == nil {
			t.Errorf("ValidateLanguageIdent(%q) = nil, want error", lang)
		}
	}
}

func TestWithLanguage_RoundTrip(t *testing.T) {
	ctx := context.Background()
	if _, ok := LanguageFromContext(ctx); ok {
		t.Fatal("empty ctx should not have a language")
	}

	ctx = WithLanguage(ctx, "sv")
	got, ok := LanguageFromContext(ctx)
	if !ok || got != "sv" {
		t.Errorf("LanguageFromContext = (%q, %v), want (\"sv\", true)", got, ok)
	}
}

func TestWithLanguage_RejectsInvalidLangSilently(t *testing.T) {
	// Bad input should not poison the context — it should fall through to
	// "no language", which downstream IssueSearchPathForContext treats as
	// a hard error. This way handlers that pass through user input don't
	// accidentally propagate "FI" or "english" to a schema name.
	ctx := WithLanguage(context.Background(), "english")
	if _, ok := LanguageFromContext(ctx); ok {
		t.Error("WithLanguage with bad input should not attach anything")
	}

	// And a parent good language should be preserved if a downstream
	// handler accidentally calls WithLanguage with bad input.
	ctx = WithLanguage(context.Background(), "fi")
	ctx = WithLanguage(ctx, "BAD")
	got, _ := LanguageFromContext(ctx)
	if got != "fi" {
		t.Errorf("good parent should be preserved when child is bad; got %q", got)
	}
}

func TestWithLanguage_RejectsUnsupportedLearningLanguageSilently(t *testing.T) {
	ctx := WithLanguage(context.Background(), "vi")
	if _, ok := LanguageFromContext(ctx); ok {
		t.Error("WithLanguage with localization-only language should not attach anything")
	}
}

func TestBuildSearchPath_DefaultTemplate(t *testing.T) {
	got, err := BuildSearchPath("sv", DefaultPerLanguageSearchPathTemplate)
	if err != nil {
		t.Fatalf("BuildSearchPath: %v", err)
	}
	want := "klearn_sv,cms_sv,klearn,cms,users,localization,communications,convo,media,public"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildSearchPath_CustomTemplate(t *testing.T) {
	got, err := BuildSearchPath("fi", "cms_{lang}, _shared")
	if err != nil {
		t.Fatalf("BuildSearchPath: %v", err)
	}
	if got != "cms_fi,_shared" {
		t.Errorf("got %q, want cms_fi,_shared", got)
	}
}

func TestBuildSearchPath_RejectsInvalidLanguage(t *testing.T) {
	if _, err := BuildSearchPath("english", DefaultPerLanguageSearchPathTemplate); err == nil {
		t.Error("expected error for bad language identifier")
	}
}

func TestBuildSearchPath_RejectsInjectionInTemplate(t *testing.T) {
	// Even though {lang} is validated, a malformed template literal must
	// still be rejected — defense in depth.
	if _, err := BuildSearchPath("sv", "klearn_{lang}, cms_{lang}; DROP TABLE users"); err == nil {
		t.Error("expected error for injection in template")
	}
}

type fakeExec struct {
	queries []string
	err     error
}

func (f *fakeExec) Exec(_ context.Context, query string) error {
	f.queries = append(f.queries, query)
	return f.err
}

func TestIssueStaticSearchPath_IssuesSetLocal(t *testing.T) {
	exec := &fakeExec{}
	err := IssueStaticSearchPath(context.Background(), "_shared, public", exec.Exec)
	if err != nil {
		t.Fatalf("IssueStaticSearchPath: %v", err)
	}
	if len(exec.queries) != 1 {
		t.Fatalf("got %d queries, want 1", len(exec.queries))
	}
	if exec.queries[0] != "SET LOCAL search_path TO _shared,public" {
		t.Errorf("got %q", exec.queries[0])
	}
}

func TestIssueSearchPathForContext_PerLanguage(t *testing.T) {
	exec := &fakeExec{}

	ctxFi := WithLanguage(context.Background(), "fi")
	if err := IssueSearchPathForContext(ctxFi, DefaultPerLanguageSearchPathTemplate, exec.Exec); err != nil {
		t.Fatalf("IssueSearchPathForContext (fi): %v", err)
	}
	ctxSv := WithLanguage(context.Background(), "sv")
	if err := IssueSearchPathForContext(ctxSv, DefaultPerLanguageSearchPathTemplate, exec.Exec); err != nil {
		t.Fatalf("IssueSearchPathForContext (sv): %v", err)
	}

	want := []string{
		"SET LOCAL search_path TO klearn_fi,cms_fi,klearn,cms,users,localization,communications,convo,media,public",
		"SET LOCAL search_path TO klearn_sv,cms_sv,klearn,cms,users,localization,communications,convo,media,public",
	}
	if len(exec.queries) != len(want) {
		t.Fatalf("got %d queries, want %d", len(exec.queries), len(want))
	}
	for i, q := range exec.queries {
		if q != want[i] {
			t.Errorf("query %d: got %q, want %q", i, q, want[i])
		}
	}
}

func TestIssueSearchPathForContext_NoLanguage(t *testing.T) {
	exec := &fakeExec{}
	err := IssueSearchPathForContext(context.Background(), DefaultPerLanguageSearchPathTemplate, exec.Exec)
	if !errors.Is(err, ErrNoActiveLanguage) {
		t.Errorf("got %v, want ErrNoActiveLanguage", err)
	}
	if len(exec.queries) != 0 {
		t.Errorf("expected no SQL to be issued; got %v", exec.queries)
	}
}

func TestApplySearchPathToTx_NoLanguageNoOp(t *testing.T) {
	exec := &fakeExec{}
	err := ApplySearchPathToTx(context.Background(), exec.Exec)
	if err != nil {
		t.Fatalf("ApplySearchPathToTx: %v", err)
	}
	if len(exec.queries) != 0 {
		t.Errorf("expected optional helper to issue no SQL without language; got %v", exec.queries)
	}
}

func TestApplySearchPathToTxRequired_NoLanguageErrors(t *testing.T) {
	exec := &fakeExec{}
	err := ApplySearchPathToTxRequired(context.Background(), exec.Exec)
	if !errors.Is(err, ErrNoActiveLanguage) {
		t.Errorf("got %v, want ErrNoActiveLanguage", err)
	}
	if len(exec.queries) != 0 {
		t.Errorf("expected strict helper to issue no SQL without language; got %v", exec.queries)
	}
}

func TestApplySearchPathToTxRequired_IssuesSetLocal(t *testing.T) {
	exec := &fakeExec{}
	ctx := WithLanguage(context.Background(), "sv")
	err := ApplySearchPathToTxRequired(ctx, exec.Exec)
	if err != nil {
		t.Fatalf("ApplySearchPathToTxRequired: %v", err)
	}
	if len(exec.queries) != 1 {
		t.Fatalf("got %d queries, want 1", len(exec.queries))
	}
	if exec.queries[0] != "SET LOCAL search_path TO klearn_sv,cms_sv,klearn,cms,users,localization,communications,convo,media,public" {
		t.Errorf("got %q", exec.queries[0])
	}
}

func TestIssueRaw_PropagatesExecErr(t *testing.T) {
	wantErr := errors.New("boom")
	exec := &fakeExec{err: wantErr}
	err := IssueRaw(context.Background(), "_shared, public", exec.Exec)
	if !errors.Is(err, wantErr) {
		t.Errorf("got %v, want wrapped %v", err, wantErr)
	}
}

func TestIssueRaw_ValidatesPath(t *testing.T) {
	exec := &fakeExec{}
	err := IssueRaw(context.Background(), "public; DROP TABLE users", exec.Exec)
	if err == nil || !strings.Contains(err.Error(), "invalid search_path identifier") {
		t.Errorf("got %v, want invalid search_path error", err)
	}
	if len(exec.queries) != 0 {
		t.Errorf("expected no SQL to be issued on invalid path; got %v", exec.queries)
	}
}
