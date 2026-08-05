// Frozen streaming-response vectors. NEVER regenerate these from implementation output — they
// were authored from the contract BEFORE any implementation existed, and the implementation is
// written to satisfy them, never the reverse.
//
// ============================================================================================
// Part A — SSE framing (text/event-stream)
// ============================================================================================
//
// Expected values are the WHATWG HTML "server-sent events" stream-parsing algorithm's behavior,
// read off the specification text rather than summarized from memory. The load-bearing clauses,
// verbatim:
//
//   Line endings: "a U+000D CARRIAGE RETURN U+000A LINE FEED (CRLF) character pair, a single
//   U+000A LINE FEED (LF) character not preceded by a U+000D CARRIAGE RETURN (CR) character, and
//   a single U+000D CARRIAGE RETURN (CR) character not followed by a U+000A LINE FEED (LF)
//   character being the ways in which a line can end."
//
//   Decoding: "Streams must be decoded using the UTF-8 decode algorithm", which "strips one
//   leading UTF-8 Byte Order Mark (BOM), if any" — of the STREAM, not of each chunk.
//
//   Line shapes: an empty line dispatches the event; a line beginning with U+003A COLON is
//   ignored; a line containing a colon splits into field (before the first colon) and value
//   (after it), and "If value starts with a U+0020 SPACE character, remove it from value"
//   — one, not all; a non-empty line with no colon uses "the whole line as the field name, and
//   the empty string as the field value".
//
//   Fields: "data" — "Append the field value to the data buffer, then append a single U+000A
//   LINE FEED (LF) character to the data buffer." "event" — "Set the event type buffer to the
//   field value." "id" — "If the field value does not contain U+0000 NULL, then set the last
//   event ID buffer to the field value. Otherwise, ignore the field." "retry" — "If the field
//   value consists of only ASCII digits, then interpret the field value as an integer in base
//   ten ... Otherwise, ignore the field." Any other field name: "The field is ignored."
//
//   Dispatch, in this order:
//     1. "Set the last event ID string of the event source to the value of the last event ID
//        buffer."
//     2. "If the data buffer is an empty string, set the data buffer and the event type buffer to
//        the empty string and return."
//     3. "If the data buffer's last character is a U+000A LINE FEED (LF) character, then remove
//        the last character from the data buffer."
//     ...
//     6. "If the event type buffer has a value other than the empty string, change the type of the
//        newly created event to equal the value of the event type buffer."
//     7. "Set the data buffer and the event type buffer to the empty string."
//
// Three consequences of that step order drive vectors below and a naive reading gets each wrong:
//
//   (a) Step 1 runs BEFORE step 2's early return, and step 2 resets only the data buffer and the
//       event type buffer. So a block carrying only `id:` dispatches no event yet still COMMITS
//       the last event ID, and the last event ID buffer survives every dispatch — it is never
//       reset by the algorithm at all. Only the event type is reset.
//   (b) `data:` with an empty value is NOT an empty data buffer: the field appends value + LF, so
//       the buffer is "\n", step 2 does not fire, step 3 strips the LF, and an event with
//       `data: ""` IS dispatched. A block with no `data` field at all is the only way to reach
//       step 2's early return.
//   (c) Step 3 removes "the last character", singular — a data buffer ending in two LFs keeps one.
//
// This file pins FRAMING ONLY. `data` in an expected event is the accumulated string BEFORE JSON
// decoding; JSON decoding is a separate stage with its own vector array below.
//
// Two Oasts conventions sit on top of the standard, and are labeled as such wherever they appear:
//
//   * `id` on a raw event mirrors the standard's `lastEventId`: it is the last event ID string at
//     dispatch time. It is omitted from the expected object when that string is the empty string,
//     and present otherwise.
//   * `retry` is OASTS, NOT WHATWG. The standard has no per-event retry — `retry:` sets the event
//     stream's reconnection time, which never reaches a dispatched MessageEvent — so the standard
//     cannot arbitrate whether it persists. The contract states persistence for `id` and states
//     nothing for `retry`; that asymmetry is read as: `retry` is carried only on the event
//     dispatched from the block whose lines contained the field, and is cleared at every dispatch
//     attempt exactly as the event type buffer is (step 7, and step 2's early return).
//
// ============================================================================================
// Part B — progress-counter saturation
// ============================================================================================
//
// A mid-stream failure exposes `min(actual progress, Number.MAX_SAFE_INTEGER)`. Progress past the
// representable range pins the counter and never fails or alters the stream.

const encoder = new TextEncoder();

/** UTF-8 bytes of `text`. Chunk boundaries are exactly where an author splits these calls. */
const u8 = (text: string): readonly number[] => Array.from(encoder.encode(text));

/**
 * A dispatched event, before JSON decoding. `data` is the accumulated data buffer; `event`, `id`,
 * and `retry` are omitted (never `undefined`) when the algorithm leaves them absent.
 */
export type RawSseEvent = {
  readonly data: string;
  readonly event?: string;
  readonly id?: string;
  readonly retry?: number;
};

export type SseFramingVector = {
  readonly cite: string;
  readonly description: string;
  /** Bytes delivered to the parser, one inner array per upstream chunk. */
  readonly chunks: readonly (readonly number[])[];
  /** The full dispatched sequence, in order. An empty array means nothing is dispatched. */
  readonly expectedEvents: readonly RawSseEvent[];
  /**
   * The standard's "last event ID string" once the stream has ended. Set only on vectors that
   * exercise `id:`; absent elsewhere because those vectors pin nothing about it.
   */
  readonly expectedLastEventId?: string;
};

/**
 * A stream whose bytes are replayed twice: once whole, once one byte per chunk. Both spellings
 * must produce `CHUNK_SPLIT_EXPECTED`.
 */
const CHUNK_SPLIT_SOURCE = u8(
  "id: 7\nevent: greet\ndata: a\ndata: b\n\nretry: 100\ndata: c\r\n\r\n",
);

const CHUNK_SPLIT_EXPECTED: readonly RawSseEvent[] = [
  { data: "a\nb", event: "greet", id: "7" },
  { data: "c", id: "7", retry: 100 },
];

export const SSE_FRAMING_VECTORS: readonly SseFramingVector[] = [
  // --- line terminators -----------------------------------------------------------------------
  {
    cite: "WHATWG HTML SSE, line endings",
    description: "A lone LF terminates a line; a blank line dispatches.",
    chunks: [u8("data: hello\n\n")],
    expectedEvents: [{ data: "hello" }],
  },
  {
    cite: "WHATWG HTML SSE, line endings",
    description:
      "A lone CR not followed by LF terminates a line. Here both CRs are unambiguous without any " +
      "end-of-stream reasoning — the first is followed by a CR and the second by 'd' — so the " +
      "first ends 'data: a' and the second ends the empty line that dispatches. The block that " +
      "follows is CRLF-terminated, so one stream can mix both terminators.",
    chunks: [u8("data: a\r\rdata: b\r\n\r\n")],
    expectedEvents: [{ data: "a" }, { data: "b" }],
  },
  {
    cite: "WHATWG HTML SSE, line endings",
    description:
      "A CR that is still pending when the stream ends is a terminator, because it is then " +
      "definitively 'not followed by' an LF: the second CR here ends the empty line and dispatches. " +
      "A parser that holds a trailing CR forever, waiting for an LF that can never arrive, emits " +
      "nothing for this stream. Note the asymmetry with the discarded-trailing-frame vectors " +
      "below: a terminator at end of stream closes the line before it and does not synthesise a " +
      "further empty line after it.",
    chunks: [u8("data: hello\r\r")],
    expectedEvents: [{ data: "hello" }],
  },
  {
    cite: "WHATWG HTML SSE, line endings",
    description: "A CRLF pair is ONE terminator, not two.",
    chunks: [u8("data: hello\r\n\r\n")],
    expectedEvents: [{ data: "hello" }],
  },
  {
    cite: "WHATWG HTML SSE, line endings",
    description:
      "A CRLF split across a chunk boundary (CR ends chunk 1, LF starts chunk 2) is still one " +
      "terminator: the CR is only a line ending when it is 'not followed by' an LF, so the parser " +
      "must hold it until the next byte arrives. A parser that dispatches on the trailing CR and " +
      "again on the leading LF would emit two events here; the single joined event is the " +
      "discriminator.",
    chunks: [u8("data: hello\r"), u8("\ndata: world\r\n\r\n")],
    expectedEvents: [{ data: "hello\nworld" }],
  },
  {
    cite: "WHATWG HTML SSE, line endings",
    description: "A zero-length chunk is inert and does not terminate a line or dispatch.",
    chunks: [u8("data: a\n"), [], u8("\n")],
    expectedEvents: [{ data: "a" }],
  },

  // --- BOM ------------------------------------------------------------------------------------
  {
    cite: "WHATWG HTML SSE, UTF-8 decode",
    description: "One leading UTF-8 BOM is stripped at the very start of the stream.",
    chunks: [u8("\uFEFFdata: hello\n\n")],
    expectedEvents: [{ data: "hello" }],
  },
  {
    cite: "WHATWG HTML SSE, UTF-8 decode",
    description:
      "Only the FIRST BOM is stripped. The second block's U+FEFF is an ordinary character, so " +
      "its field name is '\\uFEFFdata' — an unknown field, ignored — leaving that block with an " +
      "empty data buffer, which dispatch step 2 returns from without dispatching.",
    chunks: [u8("\uFEFFdata: a\n\n"), u8("\uFEFFdata: b\n\n")],
    expectedEvents: [{ data: "a" }],
  },
  {
    cite: "WHATWG HTML SSE, UTF-8 decode",
    description:
      "The BOM is stripped from the decoded STREAM, so a BOM split across a chunk boundary " +
      "(0xEF alone, then 0xBB 0xBF) is still stripped and never surfaces as data.",
    chunks: [[0xef], [0xbb, 0xbf, ...u8("data: a\n\n")]],
    expectedEvents: [{ data: "a" }],
  },

  // --- field / value splitting ----------------------------------------------------------------
  {
    cite: "WHATWG HTML SSE, line shapes",
    description:
      "Exactly ONE leading U+0020 after the colon is removed; a second space is part of the value.",
    chunks: [u8("data:  two spaces\n\n")],
    expectedEvents: [{ data: " two spaces" }],
  },
  {
    cite: "WHATWG HTML SSE, line shapes",
    description: "No space after the colon: the value starts immediately.",
    chunks: [u8("data:nospace\n\n")],
    expectedEvents: [{ data: "nospace" }],
  },
  {
    cite: "WHATWG HTML SSE, line shapes",
    description:
      "A non-empty line with no colon is the whole line as field name and the EMPTY STRING as " +
      "value, so a bare 'data' line appends only the LF — which is not an empty data buffer, and " +
      "dispatches an event whose data is the empty string.",
    chunks: [u8("data\n\n")],
    expectedEvents: [{ data: "" }],
  },
  {
    cite: "WHATWG HTML SSE, line shapes",
    description: "A line beginning with U+003A COLON is a comment and is ignored.",
    chunks: [u8(": keep-alive\ndata: a\n:another comment\ndata: b\n\n")],
    expectedEvents: [{ data: "a\nb" }],
  },
  {
    cite: "WHATWG HTML SSE, unknown fields",
    description: "An unknown field name is ignored and contributes nothing.",
    chunks: [u8("foo: bar\ndata: a\n\n")],
    expectedEvents: [{ data: "a" }],
  },
  {
    cite: "WHATWG HTML SSE, field names",
    description:
      "Field names are matched exactly, so 'Data' is an unknown field rather than a spelling of " +
      "'data'.",
    chunks: [u8("Data: ignored\ndata: a\n\n")],
    expectedEvents: [{ data: "a" }],
  },

  // --- the data buffer ------------------------------------------------------------------------
  {
    cite: "WHATWG HTML SSE, data field + dispatch step 3",
    description:
      "Multiple data lines join with a single LF between them: each appends value + LF, and " +
      "dispatch removes only the trailing one.",
    chunks: [u8("data: a\ndata: b\ndata: c\n\n")],
    expectedEvents: [{ data: "a\nb\nc" }],
  },
  {
    cite: "WHATWG HTML SSE, dispatch step 3",
    description:
      "Step 3 removes 'the last character', singular. A buffer of 'a\\n\\n' (from 'data: a' then " +
      "an empty-valued 'data:') keeps one LF, so the data is 'a\\n'.",
    chunks: [u8("data: a\ndata:\n\n")],
    expectedEvents: [{ data: "a\n" }],
  },
  {
    cite: "WHATWG HTML SSE, dispatch step 2",
    description:
      "'data:' with an empty value DOES dispatch: the field appends '' + LF, so the buffer is " +
      "'\\n', step 2's empty-string test fails, and step 3 strips the LF down to ''.",
    chunks: [u8("data:\n\n")],
    expectedEvents: [{ data: "" }],
  },
  {
    cite: "WHATWG HTML SSE, dispatch step 2",
    description:
      "The contrast case: a block with NO data field at all has a genuinely empty data buffer, so " +
      "step 2 returns and nothing is dispatched despite a well-formed 'event:' line.",
    chunks: [u8("event: ping\n\n")],
    expectedEvents: [],
  },

  // --- event type -----------------------------------------------------------------------------
  {
    cite: "WHATWG HTML SSE, dispatch steps 6 and 7",
    description:
      "'event:' names the type for the next dispatch ONLY — step 7 clears the event type buffer, " +
      "so the following event has no type.",
    chunks: [u8("event: greet\ndata: a\n\ndata: b\n\n")],
    expectedEvents: [{ data: "a", event: "greet" }, { data: "b" }],
  },
  {
    cite: "WHATWG HTML SSE, dispatch step 6",
    description:
      "An empty-valued 'event:' sets the buffer to the empty string, and step 6 only overrides the " +
      "type when the buffer is non-empty, so no event type is carried.",
    chunks: [u8("event:\ndata: a\n\n")],
    expectedEvents: [{ data: "a" }],
  },
  {
    cite: "WHATWG HTML SSE, dispatch step 2",
    description:
      "Step 2's early return clears the event type buffer even though it dispatches nothing, so " +
      "the 'ping' type set in the first block does NOT leak onto the next event.",
    chunks: [u8("event: ping\n\ndata: x\n\n")],
    expectedEvents: [{ data: "x" }],
  },

  // --- last event ID ---------------------------------------------------------------------------
  {
    cite: "WHATWG HTML SSE, dispatch steps 1 and 7",
    description:
      "The last event ID buffer is NOT among the buffers step 7 resets, so an id set once is " +
      "carried by every later event until a new 'id:' replaces it.",
    chunks: [u8("id: 42\ndata: a\n\ndata: b\n\n")],
    expectedEvents: [
      { data: "a", id: "42" },
      { data: "b", id: "42" },
    ],
    expectedLastEventId: "42",
  },
  {
    cite: "WHATWG HTML SSE, dispatch step 1 before step 2",
    description:
      "Step 1 commits the last event ID buffer BEFORE step 2's empty-data early return, and step 2 " +
      "resets only the data and event type buffers. So an id-only block dispatches no event yet " +
      "still establishes the last event ID, which the next event carries.",
    chunks: [u8("id: 42\n\ndata: x\n\n")],
    expectedEvents: [{ data: "x", id: "42" }],
    expectedLastEventId: "42",
  },
  {
    cite: "WHATWG HTML SSE, id field",
    description:
      "An empty-valued 'id:' sets the buffer to the empty string, resetting it: the event before " +
      "the reset carries the id and the event after it carries none.",
    chunks: [u8("id: 7\ndata: a\n\nid:\ndata: b\n\n")],
    expectedEvents: [{ data: "a", id: "7" }, { data: "b" }],
    expectedLastEventId: "",
  },
  {
    cite: "WHATWG HTML SSE, id field",
    description:
      "An id value containing U+0000 NULL is ignored ENTIRELY — the buffer keeps its prior value " +
      "rather than being cleared, which is why this vector sets a real id first.",
    chunks: [u8("id: 7\ndata: a\n\nid: a\u0000b\ndata: b\n\n")],
    expectedEvents: [
      { data: "a", id: "7" },
      { data: "b", id: "7" },
    ],
    expectedLastEventId: "7",
  },

  // --- retry (Oasts convention on top of the standard) ------------------------------------------
  {
    cite: "WHATWG HTML SSE, retry field + Oasts per-event retry convention",
    description: "An all-ASCII-digits retry value is parsed base ten onto the event.",
    chunks: [u8("retry: 3000\ndata: a\n\n")],
    expectedEvents: [{ data: "a", retry: 3000 }],
  },
  {
    cite: "Oasts per-event retry convention",
    description:
      "OASTS, NOT WHATWG: retry does not persist. It rides only the event dispatched from the " +
      "block whose lines carried the field; the next event has none.",
    chunks: [u8("retry: 5000\ndata: a\n\ndata: b\n\n")],
    expectedEvents: [{ data: "a", retry: 5000 }, { data: "b" }],
  },
  {
    cite: "Oasts per-event retry convention + WHATWG dispatch step 2",
    description:
      "OASTS, NOT WHATWG: a retry in a block with no data field has no event to ride. Step 2 " +
      "returns without dispatching and the pending retry is cleared with the rest of the " +
      "per-block state, so the next event does not inherit it.",
    chunks: [u8("retry: 3000\n\ndata: a\n\n")],
    expectedEvents: [{ data: "a" }],
  },
  {
    cite: "WHATWG HTML SSE, retry field",
    description:
      "A retry value with a trailing unit is not all ASCII digits, so the field is ignored.",
    chunks: [u8("retry: 3000ms\ndata: a\n\n")],
    expectedEvents: [{ data: "a" }],
  },
  {
    cite: "WHATWG HTML SSE, retry field",
    description:
      "A leading sign is not an ASCII digit, so a negative retry is ignored rather than clamped.",
    chunks: [u8("retry: -1\ndata: a\n\n")],
    expectedEvents: [{ data: "a" }],
  },
  {
    cite: "WHATWG HTML SSE, retry field",
    description:
      "The rule is ASCII digits specifically: Arabic-Indic digits U+0661 U+0662 U+0663 are ignored, " +
      "not parsed as 123.",
    chunks: [u8("retry: ١٢٣\ndata: a\n\n")],
    expectedEvents: [{ data: "a" }],
  },
  {
    cite: "Oasts reading of WHATWG HTML SSE, retry field",
    description:
      "An empty retry value is ignored. The standard's 'consists of only ASCII digits' is " +
      "vacuously true of the empty string but 'interpret the field value as an integer in base " +
      "ten' has no defined result for it, so Oasts pins the ignore branch rather than leaving the " +
      "hole open.",
    chunks: [u8("retry:\ndata: a\n\n")],
    expectedEvents: [{ data: "a" }],
  },

  // --- end of stream -----------------------------------------------------------------------------
  {
    cite: "WHATWG HTML SSE, dispatch is triggered only by a blank line",
    description:
      "A trailing frame whose lines are terminated but which never reaches a blank line is " +
      "discarded, not dispatched at end of stream.",
    chunks: [u8("data: a\n\ndata: b\n")],
    expectedEvents: [{ data: "a" }],
  },
  {
    cite: "WHATWG HTML SSE, line endings",
    description:
      "A trailing line with no terminator at all is never even processed as a line, so it too is " +
      "discarded.",
    chunks: [u8("data: a\n\ndata: b")],
    expectedEvents: [{ data: "a" }],
  },

  // --- multibyte across chunk boundaries -----------------------------------------------------
  {
    cite: "WHATWG HTML SSE, UTF-8 decode",
    description:
      "A two-byte sequence (U+00E9, 0xC3 0xA9) split across a chunk boundary decodes to one " +
      "character, not to replacement characters.",
    chunks: [
      [...u8("data: caf"), 0xc3],
      [0xa9, ...u8("\n\n")],
    ],
    expectedEvents: [{ data: "café" }],
  },
  {
    cite: "WHATWG HTML SSE, UTF-8 decode",
    description:
      "A four-byte sequence (U+1F600, 0xF0 0x9F 0x98 0x80) split two bytes to a chunk decodes to " +
      "one astral character.",
    chunks: [
      [...u8("data: "), 0xf0, 0x9f],
      [0x98, 0x80, ...u8("\n\n")],
    ],
    expectedEvents: [{ data: "\u{1F600}" }],
  },

  // --- chunking invariance ----------------------------------------------------------------------
  {
    cite: "WHATWG HTML SSE, stream parsing",
    description:
      "Baseline for the chunking-invariance pair: the whole stream delivered as one chunk.",
    chunks: [CHUNK_SPLIT_SOURCE],
    expectedEvents: CHUNK_SPLIT_EXPECTED,
    expectedLastEventId: "7",
  },
  {
    cite: "WHATWG HTML SSE, stream parsing",
    description:
      "The identical bytes delivered one byte per chunk — splitting every field name, every CRLF " +
      "pair, every blank line, and the 'retry: 100' value mid-digits — produce the identical event " +
      "sequence. The mid-value splits are the discriminator for a parser that inspects a partial " +
      "line before its terminator arrives.",
    chunks: CHUNK_SPLIT_SOURCE.map((byte) => [byte]),
    expectedEvents: CHUNK_SPLIT_EXPECTED,
    expectedLastEventId: "7",
  },
];

// ============================================================================================
// JSON decoding of the accumulated data string
// ============================================================================================
//
// A separate stage from framing: the accumulated `data` of a dispatched event is JSON-decoded, and
// the declared response schema describes that decoded value. A data payload that is not valid JSON
// is a per-event decode failure.

export type JsonDecodeVector = {
  readonly description: string;
  readonly data: string;
  readonly outcome:
    | { readonly kind: "decoded"; readonly value: unknown }
    | { readonly kind: "decode-failure" };
};

export const SSE_JSON_DECODE_VECTORS: readonly JsonDecodeVector[] = [
  {
    description: "An object payload decodes to an object.",
    data: '{"id":1,"name":"ada"}',
    outcome: { kind: "decoded", value: { id: 1, name: "ada" } },
  },
  {
    description: "An array payload decodes to an array.",
    data: "[1,2,3]",
    outcome: { kind: "decoded", value: [1, 2, 3] },
  },
  {
    description: "A top-level JSON string decodes to a string, quotes consumed.",
    data: '"hello"',
    outcome: { kind: "decoded", value: "hello" },
  },
  {
    description: "A top-level number decodes to a number.",
    data: "42",
    outcome: { kind: "decoded", value: 42 },
  },
  {
    description: "A top-level null decodes to null — a successful decode, not a failure.",
    data: "null",
    outcome: { kind: "decoded", value: null },
  },
  {
    description:
      "The empty data string — which framing really does produce, from 'data:' with an empty " +
      "value — is not valid JSON and is a decode failure.",
    data: "",
    outcome: { kind: "decode-failure" },
  },
  {
    description: "A truncated object is a decode failure.",
    data: '{"id":',
    outcome: { kind: "decode-failure" },
  },
  {
    description: "A bare unquoted word is a decode failure, not a string.",
    data: "hello",
    outcome: { kind: "decode-failure" },
  },
];

// ============================================================================================
// Progress-counter saturation
// ============================================================================================
//
// Both counters are non-negative safe integers exposing `min(actual progress, MAX_SAFE_INTEGER)`.
// `eventsYielded` (kind 'sse') increments only after framing, decoding, validation and transforms
// succeed and the event is yielded; `bytesRead` (kind 'raw') is the cumulative length of upstream
// chunks successfully read before the failing read.
//
// How a test drives these: start a counter at 0 and fold `increments` left with the saturating-add
// the implementation exposes — `increments.reduce(add, 0)` — then assert the result equals
// `expected`. Each element is one successful step's contribution: 1 per yielded event for 'sse',
// one chunk's byte length for 'raw'. The huge elements are seeds that walk the counter to the
// boundary without a quadrillion iterations; they are not claims that a single event or chunk is
// that large.

export type SaturationVector = {
  readonly description: string;
  readonly kind: "sse" | "raw";
  readonly increments: readonly number[];
  readonly expected: number;
};

export const PROGRESS_SATURATION_VECTORS: readonly SaturationVector[] = [
  // --- kind: 'sse' (eventsYielded) --------------------------------------------------------------
  {
    description: "sse: a failure before any event is yielded reports zero, not a missing counter.",
    kind: "sse",
    increments: [],
    expected: 0,
  },
  {
    description: "sse: exactly one event yielded before the failure.",
    kind: "sse",
    increments: [1],
    expected: 1,
  },
  {
    description: "sse: a small count is the plain sum of the yields.",
    kind: "sse",
    increments: [1, 1, 1, 1, 1],
    expected: 5,
  },
  {
    description: "sse: one below the ceiling is reported exactly, with no saturation yet.",
    kind: "sse",
    increments: [Number.MAX_SAFE_INTEGER - 1],
    expected: Number.MAX_SAFE_INTEGER - 1,
  },
  {
    description: "sse: landing exactly on MAX_SAFE_INTEGER reports it as a real count.",
    kind: "sse",
    increments: [Number.MAX_SAFE_INTEGER - 1, 1],
    expected: Number.MAX_SAFE_INTEGER,
  },
  {
    description: "sse: one step past the ceiling pins the counter at MAX_SAFE_INTEGER.",
    kind: "sse",
    increments: [Number.MAX_SAFE_INTEGER - 1, 1, 1],
    expected: Number.MAX_SAFE_INTEGER,
  },
  {
    description:
      "sse: a single step that jumps from below the ceiling to well past it still pins at " +
      "MAX_SAFE_INTEGER. The rule is min(actual, MAX_SAFE_INTEGER), so an implementation that only " +
      "special-cases equality with the ceiling passes the +1 vectors and fails this one.",
    kind: "sse",
    increments: [Number.MAX_SAFE_INTEGER - 1, 1000],
    expected: Number.MAX_SAFE_INTEGER,
  },

  // --- kind: 'raw' (bytesRead) ------------------------------------------------------------------
  {
    description:
      "raw: a failure on the very first read reports zero bytes — a real state, distinct from " +
      "'sse' zero.",
    kind: "raw",
    increments: [],
    expected: 0,
  },
  {
    description: "raw: a single one-byte chunk read before the failure.",
    kind: "raw",
    increments: [1],
    expected: 1,
  },
  {
    description: "raw: a few chunks of differing lengths sum to the cumulative byte count.",
    kind: "raw",
    increments: [16, 4096, 128],
    expected: 4240,
  },
  {
    description: "raw: one below the ceiling is reported exactly, with no saturation yet.",
    kind: "raw",
    increments: [Number.MAX_SAFE_INTEGER - 1],
    expected: Number.MAX_SAFE_INTEGER - 1,
  },
  {
    description: "raw: landing exactly on MAX_SAFE_INTEGER reports it as a real byte count.",
    kind: "raw",
    increments: [Number.MAX_SAFE_INTEGER - 1, 1],
    expected: Number.MAX_SAFE_INTEGER,
  },
  {
    description: "raw: one byte past the ceiling pins the counter at MAX_SAFE_INTEGER.",
    kind: "raw",
    increments: [Number.MAX_SAFE_INTEGER - 1, 1, 1],
    expected: Number.MAX_SAFE_INTEGER,
  },
  {
    description:
      "raw: a single chunk that carries the total from below the ceiling to well past it pins at " +
      "MAX_SAFE_INTEGER rather than overflowing into an imprecise float.",
    kind: "raw",
    increments: [Number.MAX_SAFE_INTEGER - 1, 65536],
    expected: Number.MAX_SAFE_INTEGER,
  },
];
