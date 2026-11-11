"""
text_clean.py
-------------
Shared text-cleaning function for Module A (Spam vs. Ham).
Kept deliberately light-touch: spam signal often lives in punctuation,
capitalisation, and symbols ('$', '!', 'FREE'), so we don't strip everything.
"""

import re

URL_RE = re.compile(r"http\S+|www\.\S+")
EMAIL_RE = re.compile(r"\S+@\S+")
MULTI_SPACE_RE = re.compile(r"\s+")


def clean_text(text: str) -> str:
    if text is None:
        return ""
    text = str(text)
    text = URL_RE.sub(" URLTOKEN ", text)
    text = EMAIL_RE.sub(" EMAILTOKEN ", text)
    text = MULTI_SPACE_RE.sub(" ", text)
    return text.strip()
