"""Language detector on real Finnish and Swedish samples (kielo-web-ingest)."""

from kielo_shared.language_detect import detect_language, language_mismatch

FI_SELKOUUTISET = (
    "Eläkekysely. Bensan hinta. Jalkapallo ja politiikka. Keskiviikon sää. Eläkekysely "
    "Aluksi aiheena on eläke. Suomalaiset eivät usko, että eläke riittää kaikkiin kuluihin "
    "tulevaisuudessa. Tämä selviää Työeläkevakuuttajien kyselystä. 60 prosenttia vastaajista "
    "arvioi, että vuonna 2050 eläke ei riitä elämisen kuluihin. Etenkin nuoret ovat "
    "pessimistisiä. Näin ajattelee Eino Köntti : En usko. Musta tuntuu, että siitä jää liian "
    "vähän sitten kuitenkin elämiseen. Kuitenkin ruoka, asumiset, kaikki tällaiset."
)

FI_SEISKA = (
    "[MEDIA::706509d5-fb7b-438b-8cd8-33a2cd5e2a08::image/jpeg] Toni avasi sanaisen arkkunsa "
    "väleistään Tuukkaan. Kaksikolla on takanaan mutkikas menneisyys. Toni Wirtasen ja Tuukka "
    "Temosen 90-luvulla alkanut ystävyys viileni pitkäksi aikaa, kun kaksikon välinen jännite "
    "Apulanta-yhtyeen bänditreeneissä yltyi. Kaksikko on kuvaillut välejään vuosien varrella "
    "veljellisiksi, mutta eritavoin problemaattisiksi. Tonin mukaan tilanne on nykyään parempi."
)

SV_LATT_SVENSKA = (
    "Yle Nyheter på lätt svenska. I Yle Nyheter på lätt svenska hör du de senaste nyheterna. "
    "Du kan läsa nyheterna om du öppnar avsnittet. Tryck på dagens rubrik för att öppna "
    "avsnittet. Nu dagens Yle Nyheter på lätt svenska, onsdagen den 30 september. I Frankrike "
    "har gymnasieelever demonstrerat på många skolor. Eleverna protesterar mot att deras "
    "klasser är för stora och för att det är brist på lärare."
)

SV_8_SIDOR = (
    "Rolig forskning fick pris. Ruttna kalsonger som har legat i jorden. I torsdags var det "
    "en gala i Schweiz. Forskare fick pris för rolig och smart forskning. Priset heter Ig "
    "Nobel. Ett av priserna gick till några forskare som hade grävt ner kalsonger i jorden. "
    "De hade grävt ner tusen kalsonger i jorden i 25 länder. Sedan tog de upp kalsongerna "
    "efter två månader."
)

EN_NEWS = (
    "The government said on Tuesday that it would raise the minimum wage next year, after "
    "months of talks with unions and employers. The decision, which was announced at a press "
    "conference in the capital, has been welcomed by many workers but criticised by some "
    "business groups who say that it will be difficult for small companies to cope with."
)

SHORT_SV = "Nu är det dags att gå hem och äta middag."


def test_finnish_text_is_finnish():
    verdict = detect_language(FI_SELKOUUTISET)
    assert verdict.language == "fi" and verdict.confident
    assert language_mismatch(FI_SELKOUUTISET, "fi") is None


def test_sparse_tabloid_finnish_is_never_rejected():
    assert language_mismatch(FI_SEISKA, "fi") is None


def test_swedish_text_is_swedish():
    for text in (SV_LATT_SVENSKA, SV_8_SIDOR):
        verdict = detect_language(text)
        assert verdict.language == "sv" and verdict.confident
        assert language_mismatch(text, "sv") is None


def test_english_text_is_english():
    assert detect_language(EN_NEWS).language == "en"


def test_swedish_article_rejected_for_finnish_target():
    mismatch = language_mismatch(SV_LATT_SVENSKA, "fi")
    assert mismatch is not None and mismatch.language == "sv"
    assert language_mismatch(SV_8_SIDOR, "fi") is not None


def test_finnish_article_rejected_for_swedish_target():
    mismatch = language_mismatch(FI_SELKOUUTISET, "sv")
    assert mismatch is not None and mismatch.language == "fi"


def test_english_article_rejected_for_either_target():
    assert language_mismatch(EN_NEWS, "fi") is not None
    assert language_mismatch(EN_NEWS, "sv") is not None


def test_short_text_abstains_and_never_rejects():
    verdict = detect_language(SHORT_SV)
    assert verdict.abstained
    assert language_mismatch(SHORT_SV, "fi") is None


def test_empty_and_media_only_text_abstain():
    assert language_mismatch("", "fi") is None
    assert language_mismatch("[MEDIA::abc::image/jpeg] https://example.com/x", "fi") is None


def test_unsupported_expected_language_never_rejects():
    assert language_mismatch(EN_NEWS, "xx") is None
    assert language_mismatch(EN_NEWS, "") is None


def test_regional_expected_code_is_normalised():
    assert language_mismatch(SV_8_SIDOR, "fi-FI") is not None
    assert language_mismatch(FI_SEISKA, "fi-FI") is None


def test_mixed_article_with_foreign_quote_is_kept():
    mixed = FI_SELKOUUTISET + " " + SHORT_SV
    assert language_mismatch(mixed, "fi") is None
