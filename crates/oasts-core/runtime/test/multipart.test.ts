import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  EncodeError,
  encodeContentDispositionFilename,
  encodeMultipart,
  escapeContentDispositionName,
  type MultipartPart,
} from "../serialize.ts";
import { CTE_VECTORS, type CteVector } from "./vectors-multipart-cte.ts";
import {
  CONTENT_DISPOSITION_NAME_VECTORS,
  FILENAME_VECTORS,
  MULTIPART_BODY_VECTORS,
} from "./vectors-multipart.ts";

const UTF8_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder();

function multipartParts(parts: (typeof MULTIPART_BODY_VECTORS)[number]["parts"]): MultipartPart[] {
  return parts.map((part) => ({
    name: part.name,
    payload: UTF8_ENCODER.encode(part.payloadAscii),
    contentType: part.contentType,
    filename: part.filename,
  }));
}

function findCteVector(predicate: (vector: CteVector) => boolean): CteVector {
  const vector = CTE_VECTORS.find(predicate);
  assert.ok(vector);
  return vector;
}

describe("multipart body", () => {
  for (const [index, vector] of MULTIPART_BODY_VECTORS.entries()) {
    test(`vector ${index + 1}: ${vector.description}`, async () => {
      const encoded = await encodeMultipart(multipartParts(vector.parts));

      assert.equal(encoded.boundary, vector.expectedBoundary);
      assert.equal(encoded.contentTypeHeader, vector.expectedContentTypeHeader);
      assert.deepEqual(encoded.body, UTF8_ENCODER.encode(vector.expectedBody));
    });
  }

  test("emits optional headers in contractual order", async () => {
    const encoded = await encodeMultipart([
      {
        name: "upload",
        filename: "",
        payload: Uint8Array.of(0xff),
        extraHeaders: [
          ["X-First", "one"],
          ["X-Second", "two"],
        ],
        cte: "binary",
      },
    ]);

    assert.match(
      UTF8_DECODER.decode(encoded.body),
      /Content-Disposition: form-data; name="upload"; filename=""\r\nX-First: one\r\nX-Second: two\r\nContent-Transfer-Encoding: binary\r\n\r\n/u,
    );
  });

  test("encodes an empty part list as a closing delimiter", async () => {
    const encoded = await encodeMultipart([]);

    assert.equal(encoded.boundary, "oxb-e3b0c44298fc1c149afbf4c8");
    assert.deepEqual(encoded.body, UTF8_ENCODER.encode("--oxb-e3b0c44298fc1c149afbf4c8--"));
  });

  test("rejects a runtime field name that cannot be represented", async () => {
    await assert.rejects(
      encodeMultipart([{ name: "bad\nname", payload: new Uint8Array() }]),
      EncodeError,
    );
  });

  test("rejects control bytes in extra header names and values", async () => {
    for (const extraHeaders of [
      [["X-Bad\rName", "value"]] as const,
      [["X-Part", "safe\r\nX-Injected: evil"]] as const,
    ]) {
      await assert.rejects(
        encodeMultipart([{ name: "field", payload: new Uint8Array(), extraHeaders }]),
        EncodeError,
      );
    }
  });

  test("is deterministic across async digest calls", async () => {
    const parts = multipartParts(MULTIPART_BODY_VECTORS[0].parts);
    const first = await encodeMultipart(parts);
    const second = await encodeMultipart(parts);

    assert.equal(first.boundary, second.boundary);
    assert.equal(first.contentTypeHeader, second.contentTypeHeader);
    assert.deepEqual(first.body, second.body);
  });
});

describe("Content-Disposition name", () => {
  for (const [index, vector] of CONTENT_DISPOSITION_NAME_VECTORS.entries()) {
    test(`vector ${index + 1}: ${vector.description}`, () => {
      if (vector.expectGenerationDiagnostic) {
        assert.throws(() => escapeContentDispositionName(vector.fieldName), EncodeError);
        return;
      }

      assert.equal(
        `Content-Disposition: form-data; name="${escapeContentDispositionName(vector.fieldName)}"`,
        vector.expectedHeaderValue,
      );
    });
  }
});

describe("Content-Disposition filename", () => {
  for (const [index, vector] of FILENAME_VECTORS.entries()) {
    test(`vector ${index + 1}: ${vector.description}`, () => {
      assert.equal(
        `filename="${encodeContentDispositionFilename(vector.filename)}"`,
        vector.expectedFilenameParam,
      );
    });
  }

  test("percent encoding is injective across the vector set", () => {
    const inputs = new Set(FILENAME_VECTORS.map((vector) => vector.filename));
    const outputs = new Set(
      FILENAME_VECTORS.map((vector) => encodeContentDispositionFilename(vector.filename)),
    );

    assert.equal(outputs.size, inputs.size);
  });

  test("percent-encodes backslash", () => {
    assert.equal(encodeContentDispositionFilename("a\\b"), "a%5Cb");
  });
});

describe("multipart Content-Transfer-Encoding", () => {
  const rejected7bit = findCteVector(
    (vector) =>
      vector.encoding === "7bit" &&
      vector.verdict === "request-encode" &&
      vector.bytes.includes(0x80),
  );
  const accepted8bit = findCteVector(
    (vector) =>
      vector.encoding === "8bit" && vector.verdict === "ok" && vector.bytes.includes(0x80),
  );

  test("rejects a payload outside the declared 7bit domain", async () => {
    await assert.rejects(
      encodeMultipart([
        {
          name: "value",
          payload: Uint8Array.from(rejected7bit.bytes),
          cte: rejected7bit.encoding,
        },
      ]),
      EncodeError,
    );
  });

  test("accepts the same payload inside the 8bit domain", async () => {
    assert.deepEqual(accepted8bit.bytes, rejected7bit.bytes);

    const encoded = await encodeMultipart([
      {
        name: "value",
        payload: Uint8Array.from(accepted8bit.bytes),
        cte: accepted8bit.encoding,
      },
    ]);

    assert.match(UTF8_DECODER.decode(encoded.body), /Content-Transfer-Encoding: 8bit\r\n/u);
  });
});
