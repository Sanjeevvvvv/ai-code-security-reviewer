from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class CodeChunk:
    start_line: int
    end_line: int
    content: str


def estimate_tokens(s: str) -> int:
    # Per requirement: 1 token ≈ 4 chars (very rough).
    return max(1, len(s) // 4)


def _python_function_ranges(code: str) -> List[Tuple[int, int]]:
    try:
        tree = ast.parse(code)
    except Exception:
        return []

    ranges: List[Tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", None)
            if isinstance(start, int) and isinstance(end, int) and end >= start:
                ranges.append((start, end))
    ranges.sort()

    # merge overlaps
    merged: List[Tuple[int, int]] = []
    for s, e in ranges:
        if not merged or s > merged[-1][1] + 1:
            merged.append((s, e))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
    return merged


def chunk_code(
    code: str,
    language: str,
    max_tokens: int = 3000,
    overlap_lines: int = 10,
) -> List[CodeChunk]:
    """
    Split code into overlapping chunks.

    - If estimated tokens <= max_tokens: returns one chunk.
    - Preserves Python function boundaries where possible using `ast` lineno/end_lineno.
    """
    language = language.lower()
    lines = code.splitlines()
    if estimate_tokens(code) <= max_tokens:
        return [CodeChunk(1, max(1, len(lines)), code)]

    max_chars = max_tokens * 4
    n = len(lines)

    # For Python, try to keep whole function blocks together when building chunks.
    protected: List[Tuple[int, int]] = _python_function_ranges(code) if language == "python" else []

    def line_span_chars(start: int, end: int) -> int:
        # start/end are 1-based inclusive
        segment = "\n".join(lines[start - 1 : end])
        return len(segment)

    chunks: List[CodeChunk] = []
    i = 1
    while i <= n:
        # If we are at a function start, consider taking the whole function if it fits.
        func = next((r for r in protected if r[0] == i), None)
        if func:
            s, e = func
            # If the function alone is bigger than max, we'll fall back to line-based splitting inside it.
            if line_span_chars(s, e) <= max_chars:
                # try to extend beyond end with additional lines while fitting
                end = e
                while end < n and line_span_chars(s, end + 1) <= max_chars:
                    end += 1
                content = "\n".join(lines[s - 1 : end])
                chunks.append(CodeChunk(s, end, content))
                i = max(end - overlap_lines + 1, i + 1)
                continue

        # generic line-based accumulation
        start = i
        end = i
        while end < n and line_span_chars(start, end + 1) <= max_chars:
            end += 1

        if end == start:
            # single line bigger than max_chars (rare). force include.
            end = min(n, start)

        content = "\n".join(lines[start - 1 : end])
        chunks.append(CodeChunk(start, end, content))
        if end >= n:
            break
        i = max(end - overlap_lines + 1, start + 1)

    # De-duplicate identical chunks if overlap created duplicates
    uniq: List[CodeChunk] = []
    seen = set()
    for c in chunks:
        key = (c.start_line, c.end_line, hash(c.content))
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    return uniq

