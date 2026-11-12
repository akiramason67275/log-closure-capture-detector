# log-closure-capture-detector

Warn before serialising a log message that embeds a closure or a large mutable object
repr.

## Usage

```python
from log_closure_capture_detector import Detector, inspect_message

detector = Detector()

findings = detector.inspect("handler=<function handle at 0x7f00>")
for finding in findings:
    print(finding.kind, finding.detail)
# closure message contains closure marker '<function '

if detector.is_suspicious("payload=<dict object at 0x1>"):
    # re-render the message without the object before serialising it
    ...

# One-shot helper for callers that do not keep a detector around.
assert inspect_message("callback=lambda x: x")
```

## Why this exists

A log call like `logger.info("state=%r", obj)` is cheap to write and expensive to
serialise: `obj` may be a closure that captures a buffer, or an object whose `__repr__`
walks a large mutable structure. By the time the message reaches a JSON encoder or a
network queue, the cost is already paid and the state may already be leaking.

This library inspects the *text* of the message before it is serialised. It does not
call `repr()` on the input, because triggering an expensive repr is exactly the side
effect we want to avoid. That makes the detector a heuristic: it matches on the repr
prefixes CPython emits for functions, bound methods, and mutable containers, plus
balanced bracket literals and a length threshold. We chose recall over precision — a
false positive is a noisy log line, a false negative is a megabyte on the wire.

## The awkward edge

The detector is static, so it cannot tell a real closure from the literal string
`"<function f>"` in a message. It will flag both. If you need precision, gate the
warning behind a debug flag or route flagged messages through a sanitising renderer
rather than dropping them.

## API

- `Detector(config=None)` — construct with an optional `DetectorConfig`.
  - `Detector.inspect(message) -> list[Finding]` — coerce `message` with `str()` and
    return every finding.
  - `Detector.is_suspicious(message) -> bool` — `True` when `inspect` returns anything.
- `DetectorConfig(max_repr_chars=512, max_nesting_depth=32, closure_markers=..., mutable_markers=...)`
  — frozen dataclass; `max_repr_chars` must be non-negative and `max_nesting_depth`
  must be at least 1.
- `Finding(kind, detail, offset=-1)` — frozen dataclass. `kind` is one of `"closure"`,
  `"mutable_repr"`, or `"large_payload"`.
- `inspect_message(message, config=None) -> list[Finding]` — module-level convenience
  wrapper.
- `DEFAULT_CONFIG` — the shared default `DetectorConfig` instance.
