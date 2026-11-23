"""PII review: check the personal data in a text or document and mask it.

A user signs in with their own LiteLLM virtual key, pastes text or uploads a
document, sees every item Presidio (and optionally a local model) finds,
chooses what to mask and how, and gets the masked text back. Nothing is
stored, and nothing is sent to a cloud model.
"""

__version__ = "0.4.0"
