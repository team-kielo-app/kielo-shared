"""Deterministic article-language check (stopword scoring, no model).

Shared by kielo-web-ingest (link boundary) and kielo-ingest-processor (processing gate)
so both reject the same articles.
"""

import re
from dataclasses import dataclass

MIN_TOKENS = 30
MIN_WINNER_HITS = 5
DOMINANCE_RATIO = 2.0

_RAW_STOPWORDS: dict[str, str] = {
    "fi": (
        "ja on ei että se oli kun mutta myös tai jos niin kuin vain ovat hän he joka jotka "
        "tämä nämä sekä mitä mukaan yli noin ole olla voi sen siitä koska kuitenkin vielä "
        "hyvin olisi ollut sitä tässä siellä täällä kaikki mikä miten kanssa jälkeen "
        "ennen aikana välillä vuonna viime ensi nyt sillä joten eli onko ovat olivat "
        "heidän hänen meidän teidän minä sinä mä sä me te nämä nuo tuo"
    ),
    "sv": (
        "och att det som en är på av för med den har inte till om ett han hon de jag vi "
        "men kan från eller också var sin sitt vid efter under mycket när nu så ska skulle "
        "blir bli upp ut över hur vad där här sedan samt även andra detta dessa hade "
        "vara varit sig mot genom enligt bara redan fler flera alla ingen något"
    ),
    "en": (
        "the and of to in is that for it with as was on are by this be at from or an have "
        "has had not but they their which were will would there been more one all can "
        "said about after also into than other its who what when"
    ),
    "de": (
        "der die das und ist nicht ein eine mit von zu den dem des auf für sich auch es "
        "im als aber wie bei oder wird nach hat sind noch nur wurde werden über"
    ),
    "et": (
        "ning oli kui aga ka või see mis et kes tema nad meie teie olema oma selle "
        "pole ei vaid veel siis kus nii kõik"
    ),
}

_TOKEN_RE = re.compile(r"[a-zA-ZåäöÅÄÖüÜõÕéÉß]+")
_MEDIA_RE = re.compile(r"\[MEDIA::.*?\]")
_URL_RE = re.compile(r"https?://\S+|www\.\S+")


def _build_stopwords() -> dict[str, frozenset[str]]:
    sets = {code: set(raw.split()) for code, raw in _RAW_STOPWORDS.items()}
    shared = {
        word
        for code, words in sets.items()
        for word in words
        if any(
            word in other for other_code, other in sets.items() if other_code != code
        )
    }
    return {code: frozenset(words - shared) for code, words in sets.items()}


STOPWORDS: dict[str, frozenset[str]] = _build_stopwords()


@dataclass(frozen=True)
class LanguageVerdict:
    language: str | None
    confident: bool
    tokens: int
    hits: dict[str, int]

    @property
    def abstained(self) -> bool:
        return self.language is None


def _tokens(text: str) -> list[str]:
    cleaned = _URL_RE.sub(" ", _MEDIA_RE.sub(" ", text or ""))
    return [token.lower() for token in _TOKEN_RE.findall(cleaned)]


def detect_language(text: str) -> LanguageVerdict:
    """Most likely language of text among fi/sv/en/de/et, or an abstention
    (language None) when the text is too short or has no clear stopword winner."""
    tokens = _tokens(text)
    hits = {
        code: sum(1 for t in tokens if t in words) for code, words in STOPWORDS.items()
    }
    if len(tokens) < MIN_TOKENS:
        return LanguageVerdict(None, False, len(tokens), hits)
    ranked = sorted(hits.items(), key=lambda item: (-item[1], item[0]))
    (best, best_hits), (_, second_hits) = ranked[0], ranked[1]
    if best_hits < MIN_WINNER_HITS:
        return LanguageVerdict(None, False, len(tokens), hits)
    confident = best_hits >= DOMINANCE_RATIO * max(second_hits, 1)
    return LanguageVerdict(best, confident, len(tokens), hits)


def language_mismatch(text: str, expected_language: str) -> LanguageVerdict | None:
    """The verdict when text is confidently in a language other than expected,
    else None. Short, unclear or unsupported-expected inputs never mismatch."""
    expected = (expected_language or "").strip().lower().split("-")[0]
    if expected not in STOPWORDS:
        return None
    verdict = detect_language(text)
    if (
        verdict.language is None
        or not verdict.confident
        or verdict.language == expected
    ):
        return None
    if verdict.hits[verdict.language] < DOMINANCE_RATIO * max(
        verdict.hits[expected], 1
    ):
        return None
    return verdict
