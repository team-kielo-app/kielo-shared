"""Tests for kielo_shared.paragraph_markup using REAL article bodies
sampled from the production-shaped local DB.

Each fixture is the verbatim ``data->>'content'`` (or stitched paragraph
text) from cms.content_versions of articles that triggered the bugs
that motivated this module:

* Eurovision SVT article (id 33f95d41…) — kielo-web-ingest LLM emitted
  the H2 heading TWICE on adjacent lines (LLM-duplication bug).
* Niinisalo Panssariprikaati article (id 0dbebf36…) — kielo-ingest-
  processor's simplifier (s07) hallucinated [MEDIA_PLACEHOLDER_1] and
  [MEDIA_PLACEHOLDER_2] for an article whose original body has zero
  [MEDIA::...] tags.

If you change the parser, run these against a fresh DB sample first —
``docker exec kielo-backend-next-postgres-1 psql -U kielo -d kielo_test
-At -c "SELECT data->>'content' FROM cms.content_versions WHERE id=...``
— and update the fixtures below. The point of these tests is to keep
the parser pinned to what production actually emits, not to a synthetic
ideal.
"""
from __future__ import annotations

from kielo_shared.paragraph_markup import (
    ParagraphType,
    dedupe_consecutive_headings,
    drop_leaked_placeholders,
    parse_body,
    parse_paragraph,
)


# Verbatim body extracted 2026-05-07 from cms.content_versions where
# id = '33f95d41-3a98-4c18-abd9-eb1175dc3579' (kielo-web-ingest LLM
# extraction output, original Swedish version).
EUROVISION_RAW_BODY = (
    "[H2] Eurovision song contest 2026\n"
    "\n"
    "[H2] Eurovision song contest 2026\n"
    "\n"
    "Artisten Felicia vann Melodifestivalen 2026 med låten ”My System” "
    "och kommer att representera Sverige i ESC 2026. Tävlingen avgörs i "
    "Wien i Österrike. Här samlas SVT:s bevakning av Eurovision 2026 – "
    "med senaste nyheterna, analyser, resultat och allt om Sveriges "
    "bidrag i tävlingen."
)

# Verbatim simplified body for content_version 0dbebf36-d3cc-4475-b18c-
# bef40393c9d2 (article_type='simplified_b1', lang='fi'). The original
# version of this article has zero [MEDIA::...] tags — the simplifier
# LLM invented both placeholders. The fact that they appear on a line
# of their own is what allows downstream to drop them.
NIINISALO_SIMPLIFIED_BODY = (
    "Panssariprikaatin harjoituksessa Niinisalossa tapahtui "
    "onnettomuus torstaina. Harjoituskäsikranaatti laukesi varusmiehen "
    "käteen.\n"
    "\n"
    "[MEDIA_PLACEHOLDER_1]\n"
    "\n"
    "**Tärkeimmät tiedot:**\n"
    "\n"
    "*   Varusmies loukkaantui käteen.\n"
    "\n"
    "[MEDIA_PLACEHOLDER_2]\n"
    "\n"
    "*   Hämeenlinnassa syttyi keskiviikkona maastopalo "
    "ampumaharjoituksen takia."
)


# ---------------------------------------------------------------------------
# parse_paragraph — single-line classification
# ---------------------------------------------------------------------------

class TestParseParagraphHeading:
    def test_h2_with_text_returns_heading_with_level_and_stripped_text(self) -> None:
        result = parse_paragraph("[H2] Eurovision song contest 2026")
        assert result.paragraph_type is ParagraphType.HEADING
        assert result.heading_level == 2
        assert result.text == "Eurovision song contest 2026"
        # Marker must NOT survive in user-facing text.
        assert "[H2]" not in result.text

    def test_h1_through_h6_all_recognized(self) -> None:
        for level in range(1, 7):
            result = parse_paragraph(f"[H{level}] Section {level}")
            assert result.heading_level == level
            assert result.text == f"Section {level}"

    def test_h7_is_not_a_heading_marker(self) -> None:
        # Regex is intentionally pinned to 1-6 — anything outside is text.
        result = parse_paragraph("[H7] not actually a heading")
        assert result.paragraph_type is ParagraphType.PROSE


class TestParseParagraphMedia:
    # Media IDs in production are UUIDs. The regex restricts to hex
    # chars + dashes intentionally — non-UUID-shaped IDs indicate the
    # extraction prompt produced something off-spec.
    UUID = "abc12345-6789-4abc-9def-0123456789ab"

    def test_canonical_media_only_line(self) -> None:
        result = parse_paragraph(f"[MEDIA::{self.UUID}::image]")
        assert result.paragraph_type is ParagraphType.MEDIA_ONLY
        assert result.media_refs == [f"{self.UUID}::image"]
        assert result.text == ""

    def test_leaked_simplifier_placeholder_classified_as_leaked(self) -> None:
        # When the simplifier hallucinates / fails to restore, the
        # placeholder reaches segmentation as its own line. Caller
        # uses LEAKED_PLACEHOLDER as a signal to drop, not display.
        result = parse_paragraph("[MEDIA_PLACEHOLDER_1]")
        assert result.paragraph_type is ParagraphType.LEAKED_PLACEHOLDER
        assert result.text == ""

    def test_inline_media_inside_prose_keeps_paragraph_as_prose(self) -> None:
        line = f"Look here [MEDIA::{self.UUID}::video] for context."
        result = parse_paragraph(line)
        assert result.paragraph_type is ParagraphType.PROSE
        assert result.media_refs == [f"{self.UUID}::video"]
        # The media tag is stripped from the text body.
        assert "[MEDIA::" not in result.text
        assert "Look here" in result.text


class TestParseParagraphProseAndStructure:
    def test_quote_line_strips_pipe(self) -> None:
        result = parse_paragraph("| She said it was unfair.")
        assert result.paragraph_type is ParagraphType.QUOTE
        assert result.text == "She said it was unfair."

    def test_list_item_strips_dash(self) -> None:
        result = parse_paragraph("- First point")
        assert result.paragraph_type is ParagraphType.LIST_ITEM
        assert result.text == "First point"

    def test_empty_line_is_empty(self) -> None:
        assert parse_paragraph("").paragraph_type is ParagraphType.EMPTY
        assert parse_paragraph("   ").paragraph_type is ParagraphType.EMPTY

    def test_normal_prose_returns_prose(self) -> None:
        line = "Felicia vann Melodifestivalen 2026 med låten ”My System”."
        result = parse_paragraph(line)
        assert result.paragraph_type is ParagraphType.PROSE
        assert result.text == line


# ---------------------------------------------------------------------------
# Real-body integration: parse_body + dedupe + drop_leaked
# ---------------------------------------------------------------------------

class TestRealEurovisionBody:
    """Real LLM output had `[H2] Eurovision song contest 2026` twice
    in a row. The parser must surface both so dedupe can collapse
    them, and the heading text must come out clean (no `[H2]`)."""

    def test_parse_preserves_both_duplicate_headings_for_dedupe(self) -> None:
        parsed = parse_body(EUROVISION_RAW_BODY)
        headings = [p for p in parsed if p.paragraph_type is ParagraphType.HEADING]
        assert len(headings) == 2, f"expected the LLM-duplicated pair, got {len(headings)}"
        assert all(h.text == "Eurovision song contest 2026" for h in headings)
        assert all(h.heading_level == 2 for h in headings)

    def test_dedupe_collapses_the_real_duplication(self) -> None:
        parsed = parse_body(EUROVISION_RAW_BODY)
        deduped = dedupe_consecutive_headings(parsed)
        types = [p.paragraph_type for p in deduped]
        # Expected: heading, prose. The duplicate heading is gone.
        assert types == [ParagraphType.HEADING, ParagraphType.PROSE]
        assert deduped[0].text == "Eurovision song contest 2026"
        assert "Felicia vann" in deduped[1].text

    def test_no_marker_survives_in_user_facing_text_after_pipeline(self) -> None:
        parsed = parse_body(EUROVISION_RAW_BODY)
        deduped = dedupe_consecutive_headings(parsed)
        clean = drop_leaked_placeholders(deduped)
        for p in clean:
            assert "[H2]" not in p.text
            assert "[MEDIA" not in p.text


class TestRealNiinisaloSimplifiedBody:
    """The simplifier LLM hallucinated MEDIA_PLACEHOLDER markers for
    an article that has no media. The parser must classify those as
    LEAKED_PLACEHOLDER so drop_leaked_placeholders can remove them
    without affecting the surrounding prose."""

    def test_hallucinated_placeholders_are_classified_as_leaked(self) -> None:
        parsed = parse_body(NIINISALO_SIMPLIFIED_BODY)
        leaked = [p for p in parsed if p.paragraph_type is ParagraphType.LEAKED_PLACEHOLDER]
        assert len(leaked) == 2

    def test_drop_leaked_keeps_the_rest_of_the_article_intact(self) -> None:
        parsed = parse_body(NIINISALO_SIMPLIFIED_BODY)
        clean = drop_leaked_placeholders(parsed)
        # No leaked placeholders left.
        assert all(
            p.paragraph_type is not ParagraphType.LEAKED_PLACEHOLDER
            for p in clean
        )
        # The real Finnish prose paragraphs are still present.
        joined = "\n".join(p.text for p in clean)
        assert "Panssariprikaatin harjoituksessa" in joined
        assert "Hämeenlinnassa" in joined
        assert "[MEDIA_PLACEHOLDER_" not in joined


# ---------------------------------------------------------------------------
# Anti-tolerance guard: pinned strict format
# ---------------------------------------------------------------------------

class TestStrictMarkerFormat:
    """We deliberately do NOT match whitespace-mangled markers like
    `[ MEDIA _ PLACEHOLDER _ 1 ]`. Production data shows the simplifier
    always emits canonical `[MEDIA_PLACEHOLDER_N]` — the spaced
    appearance in the mobile screenshot is the renderer splitting on
    underscore, not the storage format. If a real mangled variant ever
    appears in production, the fix is to repair the prompt that
    produced it; loosening the regex here would mask the upstream
    regression and let other variants creep in unbounded."""

    def test_spaced_placeholder_is_NOT_classified_as_leaked(self) -> None:
        # If this ever flips, somebody added speculative tolerance.
        result = parse_paragraph("[ MEDIA _ PLACEHOLDER _ 1 ]")
        assert result.paragraph_type is not ParagraphType.LEAKED_PLACEHOLDER

    def test_no_brackets_placeholder_is_NOT_classified_as_leaked(self) -> None:
        result = parse_paragraph("MEDIA_PLACEHOLDER_1")
        assert result.paragraph_type is not ParagraphType.LEAKED_PLACEHOLDER
