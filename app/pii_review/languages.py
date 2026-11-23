"""Find the language of each section of a text: English, German, or French.

Presidio analyses a text in one language, and its language-specific
recognizers (German and French street addresses, the spaCy name models) only
work in that language. A document that mixes languages, such as a bundle of
letters, is therefore split into paragraphs, each paragraph is classified by
the common words it contains, and neighbouring paragraphs in the same language
are joined into sections that are analysed separately.

The classifier is deterministic and cheap, so it runs on all of the text:
- A paragraph counts only with clear evidence: at least MIN_HITS common words
  of one language and at least twice as many as of any other.
- A paragraph without clear evidence (a phone number, an IBAN, a name) belongs
  to the section before it, or to the first clear section if it comes first.
- A text without any clear paragraph keeps the default language: the local
  model's answer or PII_REVIEW_LANGUAGE.
"""

from __future__ import annotations

import re
from collections import Counter

MIN_HITS = 2
# Only the start of a very long paragraph is read; that is plenty of evidence.
MAX_WORDS = 400

_WORDS = {
    "en": """
        the and of to is are were be been being have has had with for this that these those
        it its you your yours we our ours they their them he she his him from at by not
        would can could should shall may might must which who whom whose what when where
        there here if about into over after before because please dear mr mrs ms sincerely
        regards thank thanks yes my but any all than then do does did done
        just only very more most some such each other same own how why our us
        """,
    "de": """
        der die das und ist sind war waren wird werden wurde wurden mit von für fuer auf nicht
        ein eine einen einem einer den dem sie ihr ihre ihren ihrem ihres wir unser unsere ich
        mich mir bitte sehr geehrte geehrter geehrten frau herr herrn freundlichen grüßen
        gruessen grüsse liebe lieber auch noch oder aber bei zu zum zur nach aus über ueber
        unter wenn dass daß sich hier haben hat hatte hatten können koennen kann muss müssen
        soll sollte diese dieser dieses wie wo telefon straße strasse unterlagen im am um vom
        beim nur schon mehr wurde gibt ihnen uns euch keine kein nichts jetzt heute
        """,
    "fr": """
        le la les un une des du et est sont était étaient être avec pour dans sur par pas ne
        vous votre vos nous notre nos je il elle ils elles qui que quoi ce cette ces au aux
        mais ou où très bien bonjour monsieur madame mademoiselle cordialement salutations
        merci numéro rue sécurité sociale chez été avoir fait comme tout tous toute toutes
        leur leurs sa ses mon ma mes se si en lui à déjà depuis donc alors aussi peut
        entre sans sous selon veuillez agréer
        """,
}


def _vocabulary() -> dict[str, str]:
    """word -> language, without words that belong to more than one list.

    The lists also leave out words that are common in another of the three
    languages, such as "will" and "also" (German) or "or" (French).
    """
    owners: dict[str, set[str]] = {}
    for language, words in _WORDS.items():
        for word in words.split():
            owners.setdefault(word, set()).add(language)
    return {word: next(iter(languages)) for word, languages in owners.items() if len(languages) == 1}


VOCABULARY = _vocabulary()
LANGUAGES = tuple(_WORDS)

_WORD_RE = re.compile(r"[^\W\d_]+")
_PARAGRAPH_BREAK_RE = re.compile(r"\n[ \t\r\f\v]*\n")


def classify(paragraph: str) -> str | None:
    """The paragraph's language, or None without clear evidence."""
    counts: Counter[str] = Counter()
    for index, match in enumerate(_WORD_RE.finditer(paragraph)):
        if index >= MAX_WORDS:
            break
        language = VOCABULARY.get(match.group().lower())
        if language:
            counts[language] += 1
    if not counts:
        return None
    ranked = counts.most_common(2)
    best, hits = ranked[0]
    runner_up = ranked[1][1] if len(ranked) > 1 else 0
    if hits >= MIN_HITS and hits >= 2 * runner_up:
        return best
    return None


def paragraphs(text: str) -> list[tuple[int, int]]:
    """(start, end) of each paragraph; together they cover the whole text.

    A paragraph ends after a blank line, which stays with the paragraph before.
    """
    spans: list[tuple[int, int]] = []
    start = 0
    for match in _PARAGRAPH_BREAK_RE.finditer(text):
        spans.append((start, match.end()))
        start = match.end()
    if start < len(text) or not spans:
        spans.append((start, len(text)))
    return spans


def language_sections(text: str, default: str, supported: tuple[str, ...] = LANGUAGES) -> list[tuple[int, int, str]]:
    """Contiguous (start, end, language) sections covering the whole text."""
    spans = paragraphs(text)
    found = [classify(text[start:end]) for start, end in spans]
    found = [language if language in supported else None for language in found]
    first = next((language for language in found if language), None)
    if first is None:
        return [(0, len(text), default)]
    sections: list[tuple[int, int, str]] = []
    current = first
    for (start, end), language in zip(spans, found):
        current = language or current
        if sections and sections[-1][2] == current:
            sections[-1] = (sections[-1][0], end, current)
        else:
            sections.append((start, end, current))
    return sections


def language_shares(sections: list[tuple[int, int, str]]) -> dict[str, int]:
    """Characters per language, largest first."""
    shares: Counter[str] = Counter()
    for start, end, language in sections:
        shares[language] += end - start
    return dict(shares.most_common())
