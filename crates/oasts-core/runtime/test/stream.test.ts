import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { encodeSseEvents } from "../serialize.ts";
import type { SseEvent } from "../result.ts";
import { streamBody } from "../transport.ts";

const decoder = new TextDecoder();
// Spelled as an escape so the source file itself stays free of control bytes.
const NUL = "\u0000";

async function* fromArray<T>(items: readonly T[]): AsyncGenerator<T> {
  for (const item of items) {
    yield item;
  }
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<string> {
  let text = "";
  for await (const chunk of stream) {
    text += decoder.decode(chunk, { stream: true });
  }
  return text + decoder.decode();
}

async function readAllRejecting(stream: ReadableStream<Uint8Array>): Promise<unknown> {
  try {
    await readAll(stream);
  } catch (error: unknown) {
    return error;
  }
  return undefined;
}

describe("encodeSseEvents", () => {
  test("frames one event as a data field and a blank line", async () => {
    const framed = await readAll(encodeSseEvents(fromArray([{ data: { id: 1 } }])));
    assert.equal(framed, 'data: {"id":1}\n\n');
  });

  test("an empty iterable produces an empty stream", async () => {
    assert.equal(await readAll(encodeSseEvents(fromArray([]))), "");
  });

  test("event, id and retry precede data, in that order", async () => {
    const event: SseEvent<string> = { data: "hi", event: "greet", id: "7", retry: 100 };
    const framed = await readAll(encodeSseEvents(fromArray([event])));
    assert.equal(framed, 'event: greet\nid: 7\nretry: 100\ndata: "hi"\n\n');
  });

  test("each event gets its own frame", async () => {
    const framed = await readAll(encodeSseEvents(fromArray([{ data: 1 }, { data: 2 }])));
    assert.equal(framed, "data: 1\n\ndata: 2\n\n");
  });

  test("a data value JSON.stringify cannot represent is refused", async () => {
    const failure = await readAllRejecting(encodeSseEvents(fromArray([{ data: undefined }])));
    assert.ok(failure instanceof TypeError);
    assert.match(failure.message, /not JSON-serializable/u);
  });

  for (const [label, event] of [
    ["an event type carrying LF", { data: 1, event: "a\nb" }],
    ["an event type carrying CR", { data: 1, event: "a\rb" }],
    ["an id carrying LF", { data: 1, id: "a\nb" }],
    ["an id carrying NUL", { data: 1, id: `a${NUL}b` }],
  ] as const) {
    test(`${label} cannot be framed`, async () => {
      const failure = await readAllRejecting(encodeSseEvents(fromArray([event])));
      assert.ok(failure instanceof TypeError);
      assert.match(failure.message, /cannot be framed/u);
    });
  }

  test("an event type carrying NUL is framed, because only id is sensitive to it", async () => {
    const framed = await readAll(encodeSseEvents(fromArray([{ data: 1, event: `a${NUL}b` }])));
    assert.equal(framed, `event: a${NUL}b\ndata: 1\n\n`);
  });

  for (const retry of [1.5, -1, Number.NaN, Number.MAX_SAFE_INTEGER + 2]) {
    test(`retry ${String(retry)} is refused`, async () => {
      const failure = await readAllRejecting(encodeSseEvents(fromArray([{ data: 1, retry }])));
      assert.ok(failure instanceof TypeError);
      assert.match(failure.message, /non-negative safe integer/u);
    });
  }

  test("retry 0 is a real value, not an absent one", async () => {
    const framed = await readAll(encodeSseEvents(fromArray([{ data: 1, retry: 0 }])));
    assert.equal(framed, "retry: 0\ndata: 1\n\n");
  });

  test("cancelling the stream returns the source iterator", async () => {
    let returned = false;
    const events: AsyncIterable<SseEvent<number>> = {
      [Symbol.asyncIterator]() {
        return {
          next: () => Promise.resolve({ done: false, value: { data: 1 } }),
          return: (value: unknown) => {
            returned = true;
            return Promise.resolve({ done: true, value });
          },
        };
      },
    };
    const stream = encodeSseEvents(events);
    const reader = stream.getReader();
    await reader.read();
    await reader.cancel("done reading");
    assert.equal(returned, true);
  });

  test("a frame that cannot be encoded still closes the source iterator", async () => {
    // Erroring a stream does not run its `cancel`, so this is the only thing that returns the
    // source — and a generator holding a handle would otherwise keep it for the caller's lifetime.
    let returned = false;
    const events: AsyncIterable<SseEvent<unknown>> = {
      [Symbol.asyncIterator]() {
        return {
          next: () => Promise.resolve({ done: false, value: { data: undefined } }),
          return: (value: unknown) => {
            returned = true;
            return Promise.resolve({ done: true, value });
          },
        };
      },
    };
    const failure = await readAllRejecting(encodeSseEvents(events));
    assert.ok(failure instanceof TypeError);
    assert.match(failure.message, /not JSON-serializable/u);
    assert.equal(returned, true);
  });

  test("a source that throws while closing does not replace the failure being reported", async () => {
    const events: AsyncIterable<SseEvent<unknown>> = {
      [Symbol.asyncIterator]() {
        return {
          next: () => Promise.resolve({ done: false, value: { data: undefined } }),
          return: () => Promise.reject(new Error("cleanup exploded")),
        };
      },
    };
    const failure = await readAllRejecting(encodeSseEvents(events));
    assert.ok(failure instanceof TypeError);
    assert.match(failure.message, /not JSON-serializable/u);
  });

  test("cancelling a source with no return method is not an error", async () => {
    const events: AsyncIterable<SseEvent<number>> = {
      [Symbol.asyncIterator]() {
        return { next: () => Promise.resolve({ done: false, value: { data: 1 } }) };
      },
    };
    const reader = encodeSseEvents(events).getReader();
    await reader.read();
    await reader.cancel("done reading");
  });
});

describe("streamBody", () => {
  test("passes the caller's stream through and pairs it with duplex", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.close();
      },
    });
    const serialized = await streamBody("text/event-stream")(stream);
    assert.equal(serialized.body, stream);
    assert.equal(serialized.contentType, "text/event-stream");
    assert.equal(serialized.duplex, "half");
  });

  test("a body that is not a stream is refused", async () => {
    await assert.rejects(
      async () => streamBody("application/octet-stream")("not a stream"),
      /streaming body must be a ReadableStream/u,
    );
  });
});
