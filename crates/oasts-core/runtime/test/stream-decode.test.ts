import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type { SseEvent, StreamFailure } from "../result.ts";
import {
  createSseFramer,
  decodeMultipartResponse,
  decodeSseStream,
  readRawStream,
  saturatingAdd,
} from "../serialize.ts";
import {
  createTransport,
  discriminatedBody,
  execute,
  jsonBody,
  streamBody,
  type ExecutionResult,
  type OperationDescriptor,
  type ResponsePlan,
} from "../transport.ts";
import { isDocumented, responseFailure } from "./result-narrowing.ts";
import {
  PROGRESS_SATURATION_VECTORS,
  SSE_FRAMING_VECTORS,
  SSE_JSON_DECODE_VECTORS,
} from "./vectors-streaming.ts";

const ENCODER = new TextEncoder();

// The seam: the frozen framing vectors pin the accumulated data string BEFORE JSON decoding, and
// `decodeSseStream` only ever yields decoded events, so most vector payloads ("hello", "a\nb") would
// have to be rewritten as JSON to survive it. `createSseFramer` is that pre-JSON stage exported on
// its own — the very object `decodeSseStream` drives internally — so the vectors run against the
// real parser, chunk boundaries and all, and `expectedLastEventId` (observable nowhere else, since
// the standard's last event ID string is never a member of a dispatched event) is readable from it.
// One wired stream below drives `decodeSseStream` end to end so the seam exempts nothing.
describe("SSE framing vectors", () => {
  for (const vector of SSE_FRAMING_VECTORS) {
    test(`${vector.cite}: ${vector.description}`, () => {
      const framer = createSseFramer();
      const dispatched: SseEvent<string>[] = [];
      for (const chunk of vector.chunks) {
        dispatched.push(...framer.push(Uint8Array.from(chunk)));
      }

      assert.deepEqual(dispatched, vector.expectedEvents);
      if (vector.expectedLastEventId !== undefined) {
        assert.equal(framer.lastEventId, vector.expectedLastEventId);
      }
    });
  }
});

function bodyOf(chunks: readonly (string | Uint8Array)[]): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(typeof chunk === "string" ? ENCODER.encode(chunk) : chunk);
      }
      controller.close();
    },
  });
}

async function collect(events: AsyncIterable<SseEvent<unknown>>): Promise<SseEvent<unknown>[]> {
  const seen: SseEvent<unknown>[] = [];
  for await (const event of events) {
    seen.push(event);
  }
  return seen;
}

/** The value an iterable rejected with, or a sentinel when it completed instead. */
const COMPLETED = Symbol("completed");

async function rejectionOf(work: Promise<unknown>): Promise<unknown> {
  try {
    await work;
  } catch (error: unknown) {
    return error;
  }
  return COMPLETED;
}

function isStreamFailure(value: unknown): value is StreamFailure {
  return typeof value === "object" && value !== null && "kind" in value && "cause" in value;
}

function assertEventIterable(value: unknown): asserts value is AsyncIterable<SseEvent<unknown>> {
  assert.ok(typeof value === "object" && value !== null && Symbol.asyncIterator in value);
}

describe("SSE JSON decode vectors", () => {
  for (const vector of SSE_JSON_DECODE_VECTORS) {
    test(vector.description, async () => {
      const events = decodeSseStream(
        bodyOf([`data: ${vector.data}\n\n`]),
        new AbortController().signal,
        null,
      );

      if (vector.outcome.kind === "decoded") {
        assert.deepEqual(await collect(events), [{ data: vector.outcome.value }]);
        return;
      }
      const failure = await rejectionOf(collect(events));
      assert.ok(isStreamFailure(failure));
      assert.ok(failure.kind === "sse");
      assert.equal(failure.eventsYielded, 0);
      assert.ok(failure.cause instanceof SyntaxError);
    });
  }
});

describe("progress-counter saturation vectors", () => {
  for (const vector of PROGRESS_SATURATION_VECTORS) {
    test(vector.description, () => {
      assert.equal(vector.increments.reduce(saturatingAdd, 0), vector.expected);
    });
  }
});

// A source whose chunks, failure and end are all driven from the test, so a stream can be left
// mid-read while something else happens to it.
type ControlledSource = {
  readonly stream: ReadableStream<Uint8Array>;
  readonly push: (chunk: string | Uint8Array) => void;
  readonly fail: (cause: unknown) => void;
  readonly cancelledWith: () => unknown;
};

const NOT_CANCELLED = Symbol("not cancelled");

function controlledSource(): ControlledSource {
  let controller: ReadableStreamDefaultController<Uint8Array> | null = null;
  let cancelled: unknown = NOT_CANCELLED;
  const stream = new ReadableStream<Uint8Array>({
    start(source) {
      controller = source;
    },
    cancel(reason: unknown) {
      cancelled = reason;
    },
  });
  const opened = (): ReadableStreamDefaultController<Uint8Array> => {
    assert.ok(controller !== null, "the source controller is captured during start");
    return controller;
  };
  return {
    stream,
    push: (chunk) => {
      opened().enqueue(typeof chunk === "string" ? ENCODER.encode(chunk) : chunk);
    },
    fail: (cause) => {
      opened().error(cause);
    },
    cancelledWith: () => cancelled,
  };
}

/** Yields once the microtask queue has drained, so a pending read has really parked. */
async function settle(): Promise<void> {
  for (let turn = 0; turn < 4; turn += 1) {
    await Promise.resolve();
  }
}

describe("decodeSseStream", () => {
  test("frames, decodes and yields events across chunk boundaries", async () => {
    // The wiring test the framing seam does not cover: a real body, one frame split across three
    // enqueues, driven through the whole decoder.
    const events = decodeSseStream(
      bodyOf([
        'id: 7\nevent: greet\ndata: {"na',
        'me":"ada"}\n\nretry: 100\ndata: [1,2]\r',
        "\n\r\n",
      ]),
      new AbortController().signal,
      null,
    );

    assert.deepEqual(await collect(events), [
      { data: { name: "ada" }, event: "greet", id: "7" },
      { data: [1, 2], id: "7", retry: 100 },
    ]);
  });

  test("runs the per-event pipeline on the decoded data and yields what it returns", async () => {
    const seen: unknown[] = [];
    const events = decodeSseStream(
      bodyOf(["data: 1\n\ndata: 2\n\n"]),
      new AbortController().signal,
      (data: unknown) => {
        seen.push(data);
        return { wrapped: data };
      },
    );

    assert.deepEqual(await collect(events), [{ data: { wrapped: 1 } }, { data: { wrapped: 2 } }]);
    assert.deepEqual(seen, [1, 2]);
  });

  test("a per-event pipeline failure reports the events already yielded", async () => {
    const events = decodeSseStream(
      bodyOf(["data: 1\n\ndata: 2\n\ndata: 3\n\n"]),
      new AbortController().signal,
      (data: unknown) => {
        if (data === 3) {
          throw new TypeError("event 3 is not acceptable");
        }
        return data;
      },
    );

    const failure = await rejectionOf(collect(events));
    assert.ok(isStreamFailure(failure));
    assert.ok(failure.kind === "sse");
    assert.equal(failure.eventsYielded, 2);
    assert.ok(failure.cause instanceof TypeError);
  });

  test("a mid-stream JSON failure counts only the events the consumer received", async () => {
    const events = decodeSseStream(
      bodyOf(["data: 1\n\n", "data: nope\n\n"]),
      new AbortController().signal,
      null,
    );

    const failure = await rejectionOf(collect(events));
    assert.ok(isStreamFailure(failure));
    assert.ok(failure.kind === "sse");
    assert.equal(failure.eventsYielded, 1);
  });

  test("an upstream read failure is a stream failure and still cancels the body", async () => {
    const source = controlledSource();
    const events = decodeSseStream(source.stream, new AbortController().signal, null);
    const cause = new Error("upstream died");
    source.push("data: 1\n\n");
    const pending = rejectionOf(collect(events));
    await settle();
    source.fail(cause);

    const failure = await pending;
    assert.ok(isStreamFailure(failure));
    assert.ok(failure.kind === "sse");
    assert.equal(failure.eventsYielded, 1);
    assert.equal(failure.cause, cause);
  });

  test("caller cancellation rejects with the signal's own reason, not a stream failure", async () => {
    const source = controlledSource();
    const controller = new AbortController();
    const events = decodeSseStream(source.stream, controller.signal, null);
    const pending = rejectionOf(collect(events));
    await settle();
    const reason = new Error("caller went away");
    controller.abort(reason);

    assert.equal(await pending, reason);
    // Aborting cancels the upstream body straight away, rather than at the next read that may never
    // come.
    assert.equal(source.cancelledWith(), reason);
  });

  test("an already-aborted signal rejects before anything is read", async () => {
    const source = controlledSource();
    const reason = new Error("aborted before iteration");
    const events = decodeSseStream(source.stream, AbortSignal.abort(reason), null);

    assert.equal(await rejectionOf(collect(events)), reason);
  });

  test("the iterable is single-consumer", async () => {
    const events = decodeSseStream(bodyOf(["data: 1\n\n"]), new AbortController().signal, null);
    assert.deepEqual(await collect(events), [{ data: 1 }]);

    assert.throws(() => events[Symbol.asyncIterator](), /consumed once/u);
  });

  test("breaking out of a for-await cancels the underlying reader", async () => {
    const source = controlledSource();
    source.push("data: 1\n\ndata: 2\n\n");
    const events = decodeSseStream(source.stream, new AbortController().signal, null);

    for await (const event of events) {
      assert.deepEqual(event, { data: 1 });
      break;
    }

    assert.equal(source.cancelledWith(), undefined);
  });
});

describe("readRawStream", () => {
  test("passes chunks through untouched", async () => {
    const chunks: Uint8Array[] = [];
    const stream = readRawStream(bodyOf(["one", "two"]), new AbortController().signal);
    for await (const chunk of stream) {
      chunks.push(chunk);
    }

    assert.deepEqual(
      chunks.map((chunk) => new TextDecoder().decode(chunk)),
      ["one", "two"],
    );
  });

  test("an upstream failure errors the stream with the bytes read so far", async () => {
    const source = controlledSource();
    const stream = readRawStream(source.stream, new AbortController().signal);
    const reader = stream.getReader();
    source.push(Uint8Array.from([1, 2, 3]));
    source.push(Uint8Array.from([4]));
    assert.equal((await reader.read()).value?.byteLength, 3);
    assert.equal((await reader.read()).value?.byteLength, 1);
    const cause = new Error("upstream died");
    source.fail(cause);

    const failure = await rejectionOf(reader.read());
    assert.ok(isStreamFailure(failure));
    assert.ok(failure.kind === "raw");
    assert.equal(failure.bytesRead, 4);
    assert.equal(failure.cause, cause);
  });

  test("caller cancellation errors with the signal's own reason", async () => {
    const source = controlledSource();
    const controller = new AbortController();
    const reader = readRawStream(source.stream, controller.signal).getReader();
    const pending = rejectionOf(reader.read());
    await settle();
    const reason = new Error("caller went away");
    controller.abort(reason);

    assert.equal(await pending, reason);
    assert.equal(source.cancelledWith(), reason);
  });

  test("an already-aborted signal errors with its reason without reading", async () => {
    const source = controlledSource();
    const reason = new Error("aborted before reading");
    const reader = readRawStream(source.stream, AbortSignal.abort(reason)).getReader();

    assert.equal(await rejectionOf(reader.read()), reason);
  });

  test("cancelling the returned stream cancels the upstream body", async () => {
    const source = controlledSource();
    const reader = readRawStream(source.stream, new AbortController().signal).getReader();
    await reader.cancel("consumer is done");

    assert.equal(source.cancelledWith(), "consumer is done");
  });
});

function responsePlan(overrides: Partial<ResponsePlan> = {}): ResponsePlan {
  return {
    match: "200",
    kind: "exact",
    status: 200,
    bodyless: false,
    media: [["text/event-stream", { sse: decodeSseStream, onEvent: null }]],
    hasContentTypeDiscriminant: false,
    ...overrides,
  };
}

function operation(overrides: Partial<OperationDescriptor> = {}): OperationDescriptor {
  return {
    operationId: "streamOperation",
    method: "GET",
    path: [[{ kind: "literal", text: "/events" }]],
    params: [],
    body: null,
    accept: "text/event-stream",
    credentialHeaders: ["Authorization"],
    security: null,
    responses: [responsePlan()],
    baseUrl: { kind: "literal", value: "https://example.com/api" },
    fetchDefaults: {},
    ...overrides,
  };
}

async function callWith(response: Response, descriptor = operation()): Promise<ExecutionResult> {
  return execute(createTransport({ fetch: async () => response }), descriptor, {});
}

function sseResponse(body: string, init: ResponseInit = {}): Response {
  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "text/event-stream" },
    ...init,
  });
}

describe("streaming response branches", () => {
  test("a 2xx event-stream branch resolves with the event iterable in data", async () => {
    const result = await callWith(sseResponse('data: {"tick":1}\n\ndata: {"tick":2}\n\n'));

    assert.ok(isDocumented(result));
    assert.ok(result.ok);
    const events = result.data;
    assertEventIterable(events);
    assert.deepEqual(await collect(events), [{ data: { tick: 1 } }, { data: { tick: 2 } }]);
  });

  test("the descriptor's per-event pipeline runs on every event", async () => {
    const result = await callWith(
      sseResponse("data: 1\n\n"),
      operation({
        responses: [
          responsePlan({
            media: [
              [
                "text/event-stream",
                {
                  sse: decodeSseStream,
                  onEvent: (data: unknown) => ({ checked: data }),
                },
              ],
            ],
          }),
        ],
      }),
    );

    assert.ok(isDocumented(result));
    assert.ok(result.ok);
    const events = result.data;
    assertEventIterable(events);
    assert.deepEqual(await collect(events), [{ data: { checked: 1 } }]);
  });

  test("a documented non-2xx streaming branch carries the handle in error", async () => {
    const result = await callWith(
      new Response("boom", {
        status: 500,
        headers: { "Content-Type": "application/octet-stream" },
      }),
      operation({
        responses: [
          responsePlan({
            match: "5XX",
            kind: "range",
            status: null,
            media: [["application/octet-stream", { raw: readRawStream }]],
            hasContentTypeDiscriminant: true,
          }),
        ],
      }),
    );

    assert.ok(isDocumented(result));
    assert.equal(result.ok, false);
    assert.equal(result.outcome, "5XX");
    // The content-type discriminant behaves exactly as it does for a buffered arm.
    assert.equal(result.contentType, "application/octet-stream");
    const bytes = isDocumented(result) && !result.ok ? result.error : undefined;
    assert.ok(bytes instanceof ReadableStream);
    let text = "";
    for await (const chunk of bytes) {
      text += new TextDecoder().decode(chunk);
    }
    assert.equal(text, "boom");
  });

  test("a streaming branch is decided before the body is read, so nothing drains it", async () => {
    // A body that never ends: a decoder that read it before resolving would never return.
    const source = controlledSource();
    source.push("data: 1\n\n");
    const result = await callWith(
      new Response(source.stream, { headers: { "Content-Type": "text/event-stream" } }),
    );

    assert.ok(isDocumented(result));
    assert.ok(result.ok);
    const events = result.data;
    assertEventIterable(events);
    for await (const event of events) {
      assert.deepEqual(event, { data: 1 });
      break;
    }
  });

  test("a declared stream that carries no body at all is a decode failure", async () => {
    const result = await callWith(
      new Response(null, { status: 200, headers: { "Content-Type": "text/event-stream" } }),
    );

    const failure = responseFailure(result);
    assert.equal(failure.outcome, "response-decode");
    assert.ok(failure.outcome === "response-decode");
    assert.match(failure.message, /streaming response branch 200 received no body/u);
  });

  test("a Content-Type matching no declared entry still fails after the body is read", async () => {
    const result = await callWith(
      sseResponse("data: 1\n\n", { headers: { "Content-Type": "text/plain" } }),
    );

    const failure = responseFailure(result);
    assert.ok(failure.outcome === "response-decode");
    assert.match(failure.message, /does not match declared content/u);
  });

  test("a carried decoder that is neither sse nor raw still takes the buffered path", async () => {
    const result = await callWith(
      new Response('--b\r\nContent-Disposition: form-data; name="note"\r\n\r\nhi\r\n--b--', {
        headers: { "Content-Type": "multipart/mixed; boundary=b" },
      }),
      operation({
        responses: [
          responsePlan({
            media: [
              [
                "multipart/mixed",
                {
                  decode: decodeMultipartResponse,
                  plan: {
                    parts: [{ name: "note", payload: "text", repeated: false }],
                    additional: { payload: "wire", repeated: false },
                  },
                },
              ],
            ],
          }),
        ],
      }),
    );

    assert.ok(isDocumented(result));
    assert.ok(result.ok);
    assert.deepEqual(result.data, { note: "hi" });
  });
});

describe("a read rejected while the signal is aborted is cancellation, not a failure", () => {
  // The host decides whether a cancel racing an in-flight read resolves it as done or rejects it.
  // Both spellings must surface the caller's own abort reason: a `StreamFailure` here would tell a
  // caller their stream broke when in fact they stopped it.
  function rejectingBody(): ReadableStream<Uint8Array> {
    return new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(ENCODER.encode('data: {"seq":1}\n\n'));
      },
      pull(controller) {
        controller.error(new Error("upstream broke"));
      },
    });
  }

  test("the event stream rejects with the abort reason", async () => {
    const controller = new AbortController();
    const events = decodeSseStream(rejectingBody(), controller.signal, null);
    const iterator = events[Symbol.asyncIterator]();
    await iterator.next();
    controller.abort("caller stopped");
    assert.equal(await rejectionOf(iterator.next()), "caller stopped");
  });

  test("the raw stream errors with the abort reason", async () => {
    const controller = new AbortController();
    const stream = readRawStream(rejectingBody(), controller.signal);
    const reader = stream.getReader();
    await reader.read();
    controller.abort("caller stopped");
    assert.equal(await rejectionOf(reader.read()), "caller stopped");
  });

  test("without an abort, the same rejection is a stream failure carrying the progress", async () => {
    const stream = readRawStream(rejectingBody(), new AbortController().signal);
    const reader = stream.getReader();
    const first = await reader.read();
    assert.equal(first.done, false);
    const failure = await rejectionOf(reader.read());
    assert.ok(isStreamFailure(failure));
    assert.equal(failure.kind, "raw");
    assert.equal(failure.kind === "raw" ? failure.bytesRead : -1, 17);
  });
});

describe("a streaming request body carries the duplex fetch requires", () => {
  // Fetch will not construct a Request with a stream body unless `duplex: "half"` is set, so the
  // encoder ships it alongside the body rather than leaving a caller to know that. These assert on
  // the constructed Request because that is the only place the pairing is observable.
  async function dispatch(
    body: NonNullable<OperationDescriptor["body"]>,
    input: Readonly<Record<string, unknown>>,
  ): Promise<Request> {
    let sent: Request | undefined;
    await execute(
      createTransport({
        fetch: async (request: Request) => {
          sent = request;
          return new Response(null, { status: 204 });
        },
      }),
      operation({
        method: "POST",
        body,
        accept: null,
        responses: [responsePlan({ match: "204", status: 204, bodyless: true, media: [] })],
      }),
      input,
    );
    assert.ok(sent !== undefined);
    return sent;
  }

  test("a top-level stream body reaches fetch as the caller's own stream", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(ENCODER.encode("chunk"));
        controller.close();
      },
    });
    const sent = await dispatch(streamBody("text/event-stream"), { body });
    assert.equal(sent.headers.get("Content-Type"), "text/event-stream");
    assert.equal(await sent.text(), "chunk");
  });

  test("a discriminated arm that streams keeps its duplex through the arm swap", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(ENCODER.encode("streamed"));
        controller.close();
      },
    });
    const sent = await dispatch(
      discriminatedBody([
        ["application/json", jsonBody("application/json")],
        ["text/event-stream", streamBody("text/event-stream")],
      ]),
      { body: { contentType: "text/event-stream", body } },
    );
    assert.equal(sent.headers.get("Content-Type"), "text/event-stream");
    assert.equal(await sent.text(), "streamed");
  });

  test("a buffered arm of the same body carries no duplex and still sends", async () => {
    const sent = await dispatch(
      discriminatedBody([
        ["application/json", jsonBody("application/json")],
        ["text/event-stream", streamBody("text/event-stream")],
      ]),
      { body: { contentType: "application/json", body: { seq: 1 } } },
    );
    assert.equal(sent.headers.get("Content-Type"), "application/json");
    assert.equal(await sent.text(), '{"seq":1}');
  });
});

describe("teardown after a failure does not replace the failure", () => {
  function brokenBody(): ReadableStream<Uint8Array> {
    return new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(ENCODER.encode('data: {"seq":1}\n\n'));
      },
      pull(controller) {
        controller.error(new Error("socket died"));
      },
    });
  }

  test("breaking out of a raw stream that already failed does not rethrow the bare cause", async () => {
    // Cancelling an errored stream rejects with its stored error; the ordinary `break` teardown
    // must not surface that instead of the envelope the reader was already given.
    const stream = readRawStream(brokenBody(), new AbortController().signal);
    const seen: number[] = [];
    const outcome = await rejectionOf(
      (async () => {
        for await (const chunk of stream) {
          seen.push(chunk.byteLength);
          break;
        }
      })(),
    );
    assert.deepEqual(seen, [17]);
    assert.equal(outcome, COMPLETED);
  });

  test("a caller that aborts mid-chunk stops receiving frames already parsed from it", async () => {
    // Three complete frames arrive in one read. Aborting while handling the first must not run the
    // consumer's body for the other two.
    const controller = new AbortController();
    const body = bodyOf(['data: {"seq":1}\n\ndata: {"seq":2}\n\ndata: {"seq":3}\n\n']);
    const seen: unknown[] = [];
    const outcome = await rejectionOf(
      (async () => {
        for await (const event of decodeSseStream(body, controller.signal, null)) {
          seen.push(event.data);
          controller.abort("caller stop");
        }
      })(),
    );
    assert.deepEqual(seen, [{ seq: 1 }]);
    assert.equal(outcome, "caller stop");
  });
});
