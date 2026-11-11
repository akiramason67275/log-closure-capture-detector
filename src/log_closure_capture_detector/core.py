"""Core detection logic for log-closure-capture-detector.

The problem this library solves: a log call such as ``logger.info("state=%r", obj)``
looks harmless, but ``obj`` may be a closure or an object whose ``__repr__`` embeds a
large mutable structure. Serialising that message (to JSON, to a queue, to disk) can be
surprisingly expensive or leak sensitive state.

We cannot inspect the *actual* runtime repr of an arbitrary object without calling it,
and calling ``repr`` is exactly the side effect we want to warn about. So the detector
works statically on the message *text* plus lightweight metadata: it looks for the
tokens that indicate a closure or a repr of a mutable container, and it measures the
size of the textual payload that is already present.

The trade-off: this is a heuristic. It will not catch every closure, and it can flag a
short repr that happens to look like a container. We chose recall over precision for the
warning case because a false positive costs a log line's worth of noise, while a false
negative can serialise a megabyte of state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Sequence, Tuple


# Tokens that strongly suggest a closure or a bound callable is being embedded.
# ``<function`` and ``<bound method`` are the CPython repr prefixes for those objects;
# ``lambda`` is the source-level spelling. We match on the literal substrings rather
# than parsing, because log messages are strings, not ASTs.
CLOSURE_MARKERS: Tuple[str, ...] = (
    "<function ",
    "<bound method ",
    "<lambda>",
    "lambda ",
    "def ",
)

# Tokens that suggest a repr of a mutable container. These are the repr prefixes
# CPython uses for the builtin mutable containers plus a few common third-party ones
# that follow the same convention (``<...`` / ``{...}`` / ``[...]``).
MUTABLE_MARKERS: Tuple[str, ...] = (
    "<dict ",
    "<list ",
    "<set ",
    "<bytearray ",
    "<collections.",
    "<__main__.",
    "<object object at ",
)

# Characters that open a literal container repr. We count nesting depth so that a
# message containing a single ``{`` inside prose is not treated as a container.
OPEN_BRACKETS = "{[(\"'"
CLOSE_BRACKETS = "}]) \"'"


@dataclass(frozen=True)
class DetectorConfig:
    """Tunable thresholds for :class:`Detector`.

    ``max_repr_chars`` is the length above which a repr-like payload is considered
    "large". The default of 512 is deliberately conservative: most log lines are far
    shorter, and anything longer is worth a second look before serialising.

    ``max_nesting_depth`` bounds how deeply we walk bracket nesting when estimating
    container size. Deeply nested structures are a strong signal of embedded state, but
    walking them unboundedly is a denial-of-service vector on adversarial input.
    """

    max_repr_chars: int = 512
    max_nesting_depth: int = 32
    closure_markers: Sequence[str] = field(default_factory=lambda: CLOSURE_MARKERS)
    mutable_markers: Sequence[str] = field(default_factory=lambda: MUTABLE_MARKERS)

    def __post_init__(self) -> None:
        if self.max_repr_chars < 0:
            raise ValueError("max_repr_chars must be non-negative")
        if self.max_nesting_depth < 1:
            raise ValueError("max_nesting_depth must be at least 1")


DEFAULT_CONFIG = DetectorConfig()


@dataclass(frozen=True)
class Finding:
    """A single reason a message was flagged.

    ``kind`` is one of ``"closure"``, ``"mutable_repr"``, or ``"large_payload"``.
    ``detail`` is a human-readable explanation. ``offset`` is the index in the message
    where the marker was found, or ``-1`` when the finding is about the whole message.
    """

    kind: str
    detail: str
    offset: int = -1

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.kind}: {self.detail}"


class Detector:
    """Inspect log message strings for embedded closures or large mutable state.

    The detector is stateless apart from its config, so a single instance can be
    shared across threads. All methods are pure with respect to the input string.
    """

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config if config is not None else DEFAULT_CONFIG

    def inspect(self, message: object) -> List[Finding]:
        """Return findings for ``message``.

        ``message`` is coerced with ``str()``. We do *not* call ``repr()`` on the
        input, because the whole point is to avoid triggering expensive reprs; if the
        caller already has a string, we analyse that string.
        """
        text = message if isinstance(message, str) else str(message)
        findings: List[Finding] = []

        findings.extend(self._find_closures(text))
        findings.extend(self._find_mutable_reprs(text))
        findings.extend(self._find_large_payload(text))

        return findings

    def is_suspicious(self, message: object) -> bool:
        """Convenience predicate: ``True`` if :meth:`inspect` returns any finding."""
        return bool(self.inspect(message))

    def _find_closures(self, text: str) -> List[Finding]:
        out: List[Finding] = []
        for marker in self.config.closure_markers:
            start = 0
            while True:
                idx = text.find(marker, start)
                if idx < 0:
                    break
                out.append(
                    Finding(
                        kind="closure",
                        detail=f"message contains closure marker {marker!r}",
                        offset=idx,
                    )
                )
                start = idx + len(marker)
        return out

    def _find_mutable_reprs(self, text: str) -> List[Finding]:
        out: List[Finding] = []
        for marker in self.config.mutable_markers:
            idx = text.find(marker)
            if idx >= 0:
                out.append(
                    Finding(
                        kind="mutable_repr",
                        detail=f"message contains mutable-state marker {marker!r}",
                        offset=idx,
                    )
                )
        # Literal container reprs: only flag when the brackets are balanced and the
        # content is non-trivial. A lone ``{`` in prose must not trip the detector.
        depth = 0
        first_open = -1
        for i, ch in enumerate(text):
            if ch in "{[(":
                if depth == 0:
                    first_open = i
                depth += 1
                if depth > self.config.max_nesting_depth:
                    out.append(
                        Finding(
                            kind="mutable_repr",
                            detail=(
                                "bracket nesting exceeds "
                                f"{self.config.max_nesting_depth}"
                            ),
                            offset=i,
                        )
                    )
                    depth = 0
                    first_open = -1
                    break
            elif ch in "}])":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and first_open >= 0:
                        inner = text[first_open + 1 : i]
                        if len(inner) >= 16:
                            out.append(
                                Finding(
                                    kind="mutable_repr",
                                    detail=(
                                        f"balanced container literal of length "
                                        f"{len(inner)}"
                                    ),
                                    offset=first_open,
                                )
                            )
                        first_open = -1
        return out

    def _find_large_payload(self, text: str) -> List[Finding]:
        if len(text) <= self.config.max_repr_chars:
            return []
        return [
            Finding(
                kind="large_payload",
                detail=(
                    f"message length {len(text)} exceeds "
                    f"max_repr_chars={self.config.max_repr_chars}"
                ),
                offset=-1,
            )
        ]


def inspect_message(message: object, config: DetectorConfig | None = None) -> List[Finding]:
    """Module-level convenience wrapper around :class:`Detector`.

    Constructing a detector per call is cheap, but callers processing many messages
    should build one :class:`Detector` and reuse it.
    """
    return Detector(config).inspect(message)
