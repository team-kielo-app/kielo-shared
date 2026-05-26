"""Unified parser for the structural markers kielo-web-ingest emits in
extracted article body text.

Why this lives in kielo-shared
------------------------------
Three services need to recognize the same marker grammar:

* **kielo-ingest-processor** — segments LLM-extracted body text into
  paragraphs; must lift heading markers into typed paragraph metadata
  and dedupe LLM-induced duplications.
* **kielo-content-service** / **kielo-mobile-bff** — when serializing
  paragraphs for clients, must verify that no marker has leaked into
  user-facing text (defense against any pipeline regression upstream).
* **future structured-paragraph migration** — when we add
  `paragraph_type` + `heading_level` columns and stop persisting markers
  in `text`, the same parser will run on the migration backfill.

Without a shared module, each service rolls its own regex and they
drift. The Eurovision article that surfaced this bug had `[H2]`
duplicated in the LLM extraction output and a `[MEDIA_PLACEHOLDER_1]`
hallucinated by the simplifier — both went straight into stored
paragraph text because no parser existed at the boundary.

Marker grammar (pinned by kielo-web-ingest's
`ARTICLE_EXTRACTION_PROMPT_TEMPLATE`):

* ``[H#] text`` — heading (level 1–6), text on the same line
* ``[MEDIA::<media_id>::<media_type>]`` — canonical media reference
* ``| text`` — blockquote line
* ``- text`` — list item

Markers MUST appear at the start of a line. The simplification step
internally rewrites ``[MEDIA::...]`` to ``[MEDIA_PLACEHOLDER_N]`` to
shield the canonical syntax from LLM mangling, then restores. A leaked
``[MEDIA_PLACEHOLDER_N]`` is *always* a bug — production data shows
the simplifier sometimes hallucinates these even when the input had no
media at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

# ---------------------------------------------------------------------------
# Regexes — pinned to the exact format kielo-web-ingest produces.
# Do NOT relax these to "tolerate" LLM mangling. If you observe a real
# variant in production, fix the prompt; tolerance regexes mask the
# upstream bug and grow without bound.
# ---------------------------------------------------------------------------

HEADING_MARKER_REGEX = re.compile(r"^\[H([1-6])\]\s*(.*)$")
"""Capture group 1 = level digit, group 2 = heading text (may be empty)."""

MEDIA_TAG_REGEX = re.compile(r"\[MEDIA::([0-9a-fA-F\-]+)::(\w+)[^\]]*\]")
"""Canonical persistent media reference. group(1)=media_id, group(2)=type."""

MEDIA_PLACEHOLDER_LEAK_REGEX = re.compile(r"\[MEDIA_PLACEHOLDER_(\d+)\]")
"""Simplifier-internal token. Must NEVER appear in stored text — its
presence indicates the simplifier failed to restore (or, in the cases
we have seen, the simplifier LLM hallucinated a placeholder for an
article with no media at all)."""


class ParagraphType(str, Enum):
    HEADING = "heading"
    PROSE = "prose"
    MEDIA_ONLY = "media_only"
    QUOTE = "quote"
    LIST_ITEM = "list_item"
    EMPTY = "empty"
    LEAKED_PLACEHOLDER = "leaked_placeholder"
    """The paragraph is nothing but a leaked simplifier internal token.
    Callers should drop or quarantine these."""


@dataclass(frozen=True)
class ParsedParagraph:
    """Typed representation of one paragraph extracted from LLM body text."""

    paragraph_type: ParagraphType
    text: str
    """The user-facing text with markers stripped. Empty for media-only."""
    raw: str
    """The original line as the parser received it (for diagnostics)."""
    heading_level: Optional[int] = None
    media_refs: List[str] = field(default_factory=list)
    """For MEDIA_ONLY: list of `<media_id>::<media_type>` tuples found
    on the line. For PROSE that contains inline media tags, the same."""


def parse_paragraph(line: str) -> ParsedParagraph:
    """Parse a single paragraph line into a typed ParsedParagraph.

    The input is a single LLM-extracted body line (segmenter has
    already split on ``\\n+``). The parser:

      * recognizes ``[H#] text`` as a heading,
      * recognizes a line that is ONLY ``[MEDIA::id::type]`` references
        (and whitespace) as media-only,
      * recognizes a line that is ONLY a leaked ``[MEDIA_PLACEHOLDER_N]``
        as ``LEAKED_PLACEHOLDER`` so the caller can drop it,
      * otherwise classifies as PROSE / QUOTE / LIST_ITEM / EMPTY.

    The parser does NOT attempt whitespace-tolerant matching of any
    marker — if production starts producing mangled markers, the fix
    belongs in the prompt that generated them, not here.
    """
    raw = line
    stripped = line.strip()

    if not stripped:
        return ParsedParagraph(ParagraphType.EMPTY, "", raw)

    # Heading marker takes precedence; preserve the heading text.
    heading_match = HEADING_MARKER_REGEX.match(stripped)
    if heading_match:
        level = int(heading_match.group(1))
        text = heading_match.group(2).strip()
        return ParsedParagraph(
            ParagraphType.HEADING,
            text,
            raw,
            heading_level=level,
        )

    # Strip canonical media tags and check whether anything else remains.
    media_refs = [
        f"{m.group(1)}::{m.group(2)}" for m in MEDIA_TAG_REGEX.finditer(stripped)
    ]
    text_without_media = MEDIA_TAG_REGEX.sub("", stripped).strip()

    if not text_without_media and media_refs:
        return ParsedParagraph(
            ParagraphType.MEDIA_ONLY,
            "",
            raw,
            media_refs=media_refs,
        )

    # Leaked simplifier placeholder (always a bug — see module docstring).
    if MEDIA_PLACEHOLDER_LEAK_REGEX.fullmatch(stripped):
        return ParsedParagraph(
            ParagraphType.LEAKED_PLACEHOLDER,
            "",
            raw,
        )

    # Quote / list prefix on the line (web-ingest prompt rule).
    if stripped.startswith("|"):
        return ParsedParagraph(
            ParagraphType.QUOTE,
            stripped.lstrip("|").strip(),
            raw,
            media_refs=media_refs,
        )
    if stripped.startswith("- "):
        return ParsedParagraph(
            ParagraphType.LIST_ITEM,
            stripped[2:].strip(),
            raw,
            media_refs=media_refs,
        )

    return ParsedParagraph(
        ParagraphType.PROSE,
        text_without_media or stripped,
        raw,
        media_refs=media_refs,
    )


def parse_body(content: str) -> List[ParsedParagraph]:
    """Parse a full LLM-extracted body string into typed paragraphs.

    Splits on ``\\n+`` (matching `text_utils.split_into_paragraphs`)
    and runs `parse_paragraph` on each line. Returns an empty list for
    empty/whitespace-only input.
    """
    if not content or not content.strip():
        return []
    lines = re.split(r"\n+", content.strip())
    return [parse_paragraph(line) for line in lines if line.strip()]


def dedupe_consecutive_headings(
    paragraphs: List[ParsedParagraph],
) -> List[ParsedParagraph]:
    """Drop consecutive identical headings (the LLM-duplication pattern).

    Real-data trigger: kielo-web-ingest's ARTICLE_EXTRACTION_PROMPT
    occasionally produces

        [H2] Eurovision song contest 2026
        [H2] Eurovision song contest 2026
        Felicia vann ...

    where the LLM emits the section heading twice. Dedupe collapses
    them so segmentation stores the heading once.

    Only consecutive identical (level, text) pairs are collapsed. Two
    different ``[H2]`` headings that happen to repeat across the
    article are preserved.
    """
    if not paragraphs:
        return paragraphs
    out: List[ParsedParagraph] = []
    for p in paragraphs:
        if (
            out
            and p.paragraph_type is ParagraphType.HEADING
            and out[-1].paragraph_type is ParagraphType.HEADING
            and out[-1].heading_level == p.heading_level
            and out[-1].text == p.text
        ):
            continue
        out.append(p)
    return out


def drop_leaked_placeholders(
    paragraphs: List[ParsedParagraph],
) -> List[ParsedParagraph]:
    """Drop paragraphs whose entire content is a leaked simplifier
    placeholder. Always safe — these never carry user-facing content.
    """
    return [
        p
        for p in paragraphs
        if p.paragraph_type is not ParagraphType.LEAKED_PLACEHOLDER
    ]


__all__ = [
    "HEADING_MARKER_REGEX",
    "MEDIA_TAG_REGEX",
    "MEDIA_PLACEHOLDER_LEAK_REGEX",
    "ParagraphType",
    "ParsedParagraph",
    "parse_paragraph",
    "parse_body",
    "dedupe_consecutive_headings",
    "drop_leaked_placeholders",
]
