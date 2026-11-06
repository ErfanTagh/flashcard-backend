"""Generating a flashcard deck from documents with Claude.

The user hands in one or more files -- a PDF, photographs of handwritten notes,
a screenshot, a page of plain text -- and optionally a sentence or two saying
what they want. This turns that into a deck of term/definition cards.

Claude reads images and PDFs directly, so a photo of a textbook page or a scan
of lecture notes needs no OCR step here: the bytes go to the model as-is, as an
image or a document block, and the model does the reading. That is the whole
reason this is worth doing in the model rather than with a parser.

Nothing here writes to the database. The caller gets a plain dict back and
decides what to do with it -- in practice it is shown to the user for review and
only then saved through the ordinary deck-import path, so a generation the user
does not like costs nothing.
"""

import base64
import json
import os
import re

import anthropic


# The best model, per the product decision: a flashcard is only as good as the
# understanding behind it, and this is the model that understands the material.
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5-5")

# What the model may send back. Generous because the model thinks before it
# answers and that thinking counts against this ceiling, so a hundred cards
# plus the reasoning behind them needs room; we only pay for what is generated.
# Streaming (below) is what keeps a ceiling this high from risking a timeout.
MAX_OUTPUT_TOKENS = 32000

# The model decides how many cards the material warrants; this is only a
# ceiling it is told to stay within, and a hard cap enforced on the result, so
# a large upload cannot turn into hundreds of cards (and the output tokens that
# would cost).
MAX_CARDS = 50

# What a file may be. Images and PDFs go to the model as-is; text is read and
# passed as text. Anything else is refused with a message naming what works.
IMAGE_TYPES = {
    "image/jpeg", "image/png", "image/gif", "image/webp",
}
# HEIC/HEIF are what an iPhone produces by default. The model does not accept
# them, so they are converted to JPEG before being sent -- see _image_block.
HEIC_TYPES = {"image/heic", "image/heif"}
PDF_TYPE = "application/pdf"
TEXT_TYPES = {
    "text/plain", "text/markdown", "text/csv", "application/json",
}

# Kept well under the model's own request ceiling once base64 expansion (~1.33x)
# is accounted for. The HTTP layer in front enforces its own limit too; these
# are the ones whose message mentions documents rather than card images.
MAX_FILE_BYTES = 12 * 1024 * 1024
MAX_TOTAL_BYTES = 18 * 1024 * 1024
MAX_FILES = 10

# A text file is read into the prompt, so a runaway one would blow the context
# window. Truncated with a note rather than silently cut.
MAX_TEXT_CHARS = 100_000


class GenerationError(Exception):
    """Something the caller should show the user, not a server fault."""


def _image_block(data, media_type):
    """An image content block, converting HEIC/HEIF to JPEG first.

    An iPhone photo is HEIC by default and the model does not read it, so a
    user photographing their notes would otherwise be told their own camera's
    format is unsupported. Pillow with pillow-heif handles the conversion; if
    that stack is not installed the file is refused with a clear message rather
    than sent in a format the model rejects.
    """
    if media_type in HEIC_TYPES:
        try:
            import io
            from PIL import Image
            import pillow_heif  # noqa: F401  (registers the HEIF opener)

            pillow_heif.register_heif_opener()
            buffer = io.BytesIO()
            Image.open(io.BytesIO(data)).convert("RGB").save(buffer, format="JPEG", quality=85)
            data = buffer.getvalue()
            media_type = "image/jpeg"
        except Exception:
            raise GenerationError(
                "That looks like a HEIC photo, which can't be read here yet. "
                "Export it as JPEG or PNG and try again."
            )

    return {
        "type": "image",
        "source": {
            "type": "base64",
            "media_type": media_type,
            "data": base64.standard_b64encode(data).decode("ascii"),
        },
    }


def _file_to_block(name, media_type, data):
    """Turn one uploaded file into a Claude content block, or raise."""
    media_type = (media_type or "").lower().split(";")[0].strip()

    if media_type in IMAGE_TYPES or media_type in HEIC_TYPES:
        return _image_block(data, media_type)

    if media_type == PDF_TYPE:
        return {
            "type": "document",
            "source": {
                "type": "base64",
                "media_type": PDF_TYPE,
                "data": base64.standard_b64encode(data).decode("ascii"),
            },
        }

    if media_type in TEXT_TYPES or media_type.startswith("text/"):
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            raise GenerationError(f'"{name}" could not be read as text.')
        if len(text) > MAX_TEXT_CHARS:
            text = text[:MAX_TEXT_CHARS] + "\n\n[... truncated ...]"
        return {"type": "text", "text": f"--- {name} ---\n{text}"}

    raise GenerationError(
        f'"{name}" is a {media_type or "unknown"} file, which can\'t be used. '
        "Use a PDF, an image (JPEG/PNG/WEBP/GIF), or a text file."
    )


def _instruction(user_prompt):
    """The text block that tells the model what deck to make of the material."""
    lines = [
        "Create a flashcard deck from the material above.",
        "Decide how many cards the material warrants: enough to cover the key "
        "points a learner should take away, with no padding and no trivia. A "
        "short note makes a handful of cards; a dense chapter makes many. Use "
        f"as many or as few as the content genuinely supports, up to {MAX_CARDS}.",
    ]
    if (user_prompt or "").strip():
        # The user's own words, fenced so the model treats them as instructions
        # about the deck and not as material to make cards out of.
        lines.append(f'The person asked, in their words: "{user_prompt.strip()}"')

    lines.append(
        "\nReply with JSON only -- no code fences, no commentary before or "
        "after -- in exactly this shape:\n"
        '{ "name": "a short deck name", "cards": '
        '[ { "term": "front of the card", "definition": "back of the card" } ] }'
    )
    lines.append(
        "\nRules:\n"
        "- \"term\" is what the learner is shown and must recall: a word, phrase "
        "or question. Under 80 characters.\n"
        "- \"definition\" is the answer: one or two sentences, under 300 "
        "characters, and it must not restate the term.\n"
        "- Every term must be unique.\n"
        "- Base every card on the material provided; do not invent facts that "
        "are not supported by it.\n"
        "- Plain text only: no markdown, no HTML, no bullet characters.\n"
        "- Write in the same language as the material unless the person asked "
        "for another."
    )
    return "\n".join(lines)


SYSTEM = (
    "You turn study material into flashcards. You are given documents, images "
    "or text, and you return a deck of term/definition cards as JSON. You "
    "output only the JSON object asked for, with no surrounding text."
)


def _extract_json(text):
    """Pull the JSON object out of the model's reply, tolerating stray wrapping.

    The model is asked for bare JSON and usually obliges, but a stray code
    fence or a line of preamble should not sink an otherwise good deck. So:
    strip fences, and if that still does not parse, take the outermost {...}.
    """
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(cleaned[start:end + 1])
        except json.JSONDecodeError:
            pass

    raise GenerationError(
        "The model did not return a deck this time. Try again, or add a short "
        "instruction about what to focus on."
    )


def _cards_from(payload):
    """A clean (name, cards) pair from whatever JSON came back.

    Lenient on shape -- a bare list, a `cards`/`flashcards` key, `front`/`back`
    aliases -- because the deck is only as useful as it is forgiving, and the
    import path it is handed to validates it properly afterwards anyway.
    """
    name = ""
    raw = None
    if isinstance(payload, dict):
        name = str(payload.get("name") or payload.get("deck_name") or "").strip()
        for key in ("cards", "flashcards", "items", "deck"):
            if isinstance(payload.get(key), list):
                raw = payload[key]
                break
    elif isinstance(payload, list):
        raw = payload

    if not isinstance(raw, list) or not raw:
        raise GenerationError("The model returned no cards. Try again.")

    term_keys = ("term", "front", "question", "word", "prompt")
    def_keys = ("definition", "back", "answer", "meaning", "response")

    cards = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        term = next((entry[k] for k in term_keys if entry.get(k) not in (None, "")), None)
        definition = next((entry[k] for k in def_keys if entry.get(k) not in (None, "")), None)
        if term is None or definition is None:
            continue
        if isinstance(term, (dict, list)) or isinstance(definition, (dict, list)):
            continue
        term, definition = str(term).strip(), str(definition).strip()
        if term and definition:
            cards.append({"term": term, "definition": definition})

    if not cards:
        raise GenerationError("The model returned no usable cards. Try again.")

    return name, cards


def generate_cards(files, user_prompt=""):
    """Generate a deck from uploaded files.

    `files` is a list of (filename, media_type, bytes). Returns
    {"name": str, "cards": [{"term", "definition"}, ...]}. Raises
    GenerationError with a message meant for the user on anything they can fix,
    and lets genuine server faults propagate.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        # A configuration fault, not the user's: say so without blaming them.
        raise GenerationError(
            "AI generation isn't configured on the server yet. "
            "An administrator needs to set an API key."
        )

    if not files:
        raise GenerationError("Add at least one document or image to generate from.")
    if len(files) > MAX_FILES:
        raise GenerationError(f"That's {len(files)} files; the limit is {MAX_FILES}.")

    total = 0
    content = []
    for name, media_type, data in files:
        if not data:
            continue
        if len(data) > MAX_FILE_BYTES:
            raise GenerationError(
                f'"{name}" is larger than {MAX_FILE_BYTES // (1024 * 1024)}MB.'
            )
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise GenerationError(
                f"The files add up to more than {MAX_TOTAL_BYTES // (1024 * 1024)}MB. "
                "Remove one, or generate in two passes."
            )
        content.append(_file_to_block(name, media_type, data))

    if not content:
        raise GenerationError("Those files were empty.")

    content.append({"type": "text", "text": _instruction(user_prompt)})

    client = anthropic.Anthropic()
    try:
        # Streaming so a big document and a full deck of output cannot hit the
        # request timeout; the final message is assembled by the SDK.
        with client.messages.stream(
            model=MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            system=SYSTEM,
            messages=[{"role": "user", "content": content}],
        ) as stream:
            message = stream.get_final_message()
    except anthropic.AuthenticationError:
        raise GenerationError(
            "AI generation isn't configured correctly on the server "
            "(the API key was rejected)."
        )
    except anthropic.APIStatusError as error:
        status = getattr(error, "status_code", None)
        if status == 429:
            raise GenerationError("The AI service is busy right now. Try again in a moment.")
        if status == 413:
            raise GenerationError("Those files are too large for the AI service. Try fewer or smaller ones.")
        raise GenerationError("The AI service couldn't complete that. Try again.")
    except anthropic.APIConnectionError:
        raise GenerationError("Couldn't reach the AI service. Try again in a moment.")

    text = "".join(
        block.text for block in message.content if getattr(block, "type", None) == "text"
    )
    if not text.strip():
        raise GenerationError("The model returned an empty reply. Try again.")

    payload = _extract_json(text)
    name, cards = _cards_from(payload)
    # The model is asked to stay within the ceiling; enforce it regardless.
    return {"name": name, "cards": cards[:MAX_CARDS]}
