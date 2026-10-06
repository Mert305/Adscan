"""Terminal cell widths, safe text, and small dependency-free tables."""

from __future__ import annotations

import re
import shutil
import unicodedata

SGR = re.compile(r"\x1b\[[0-9;]*m")
ESCAPES = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]")


def clean(text):
    text = ESCAPES.sub("", str(text))
    return ''.join(ch if ch in "\n\t" or unicodedata.category(ch) != "Cc" else "" for ch in text)


def cells(text):
    return sum(char_width(ch) for ch in clean(text))


def char_width(ch):
    if unicodedata.combining(ch) or unicodedata.category(ch) in {"Cf", "Cc"}:
        return 0
    return 2 if unicodedata.east_asian_width(ch) in {"W", "F"} else 1


def fit(text, width):
    """Clip to terminal cells while retaining program-generated SGR colors."""
    if width <= 0:
        return ""
    text = ESCAPES.sub(lambda m: m.group() if SGR.fullmatch(m.group()) else "", str(text))
    output, used, index = [], 0, 0
    while index < len(text):
        match = SGR.match(text, index)
        if match:
            output.append(match.group())
            index = match.end()
            continue
        ch = text[index]
        count = char_width(ch)
        if used + count > width:
            return ''.join(output) + ("\x1b[0m" if "\x1b[" in text else "")
        if unicodedata.category(ch) != "Cc":
            output.append(ch)
        used += count
        index += 1
    return ''.join(output)


def wrap(text, width):
    """Word wrap plain text by terminal cells, including long identifiers."""
    width = max(1, width)
    output = []
    for paragraph in clean(text).expandtabs(4).splitlines() or [""]:
        line = ""
        for word in paragraph.split():
            if line and cells(line + " " + word) <= width:
                line += " " + word
                continue
            if line:
                output.append(line)
                line = ""
            while cells(word) > width:
                chunk = fit(word, width)
                if not chunk:  # a double-width glyph in a one-cell terminal
                    word = word[1:]
                    continue
                output.append(chunk)
                word = word[len(chunk):]
            line = word
        output.append(line)
    return output


def width():
    return max(8, shutil.get_terminal_size((80, 24)).columns - 1)


def table(headers, rows, *, max_width=None):
    limit = max_width or width()
    rows = [[clean(value).replace("\n", " ") for value in row] for row in rows]
    headers = [clean(value) for value in headers]
    natural = [max(cells(headers[i]), *(cells(row[i]) for row in rows), 1) for i in range(len(headers))]
    minimum = sum(min(value, 7) for value in natural) + 3 * (len(headers) - 1)
    if minimum > limit:
        lines = []
        for row in rows:
            lines.extend(wrap(' · '.join(f"{h}: {v}" for h, v in zip(headers, row, strict=True)), limit))
        return '\n'.join(lines)
    sizes = natural[:]
    while sum(sizes) + 3 * (len(headers) - 1) > limit:
        index = max(range(len(sizes)), key=lambda i: sizes[i])
        sizes[index] -= 1
    def line(values):
        return ' | '.join(fit(v, size) + ' ' * (size - cells(fit(v, size)))
                          for v, size in zip(values, sizes, strict=True))
    output = [line(headers), '-+-'.join('-' * size for size in sizes)]
    for row in rows:
        parts = [wrap(value, size) for value, size in zip(row, sizes, strict=True)]
        for index in range(max(map(len, parts), default=1)):
            output.append(line([part[index] if index < len(part) else '' for part in parts]))
    return '\n'.join(output)
