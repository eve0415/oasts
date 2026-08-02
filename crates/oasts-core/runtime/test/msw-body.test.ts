import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  projectParameter,
  projectRequestBody,
  type MultipartFieldDescriptor,
  type RequestBodyDescriptor,
  type UrlencodedFieldDescriptor,
} from "../msw-project.ts";
import { OastsHandlerError } from "../msw-runtime.ts";
import { encodeMultipart } from "../serialize.ts";
import { binaryBody, jsonBody, multipartBody, textBody, urlencodedBody } from "../transport.ts";

const BODY_SOURCE = {
  logicalSourceId: "$single",
  jsonPointer: "/paths/~1items/post/requestBody",
} as const;
const MEDIA_SOURCE = {
  logicalSourceId: "$single",
  jsonPointer: "/paths/~1items/post/requestBody/content/application~1json",
} as const;
const STRING_SHAPE = { kind: "string" } as const;
const STRING_ARRAY_SHAPE = { kind: "array", items: STRING_SHAPE } as const;
const OBJECT_SHAPE = {
  kind: "object",
  properties: { first: { required: true, shape: STRING_SHAPE } },
  additional: false,
} as const;

const JSON_DESCRIPTOR = {
  required: true,
  discriminated: false,
  sourcePointer: BODY_SOURCE,
  media: [{ media: "application/json", kind: "json", sourcePointer: MEDIA_SOURCE }],
} satisfies RequestBodyDescriptor & { readonly required: true };

const TEXT_DESCRIPTOR = {
  required: true,
  discriminated: false,
  sourcePointer: BODY_SOURCE,
  media: [{ media: "text/plain", kind: "text", sourcePointer: MEDIA_SOURCE }],
} satisfies RequestBodyDescriptor & { readonly required: true };

const BINARY_DESCRIPTOR = {
  required: true,
  discriminated: false,
  sourcePointer: BODY_SOURCE,
  media: [{ media: "application/octet-stream", kind: "binary", sourcePointer: MEDIA_SOURCE }],
} satisfies RequestBodyDescriptor & { readonly required: true };

const URLENCODED_DESCRIPTOR = {
  required: true,
  discriminated: false,
  sourcePointer: BODY_SOURCE,
  media: [
    {
      media: "application/x-www-form-urlencoded",
      kind: "urlencoded",
      sourcePointer: MEDIA_SOURCE,
      fields: [
        {
          name: "name",
          required: true,
          sourcePointer: MEDIA_SOURCE,
          decoder: "style",
          helper: "query-form-explode",
          shape: STRING_SHAPE,
        },
        {
          name: "tags",
          required: false,
          sourcePointer: MEDIA_SOURCE,
          decoder: "style",
          helper: "query-form-explode",
          shape: STRING_ARRAY_SHAPE,
        },
      ],
    },
  ],
} satisfies RequestBodyDescriptor & { readonly required: true };

const MULTIPART_DESCRIPTOR = {
  required: true,
  discriminated: false,
  sourcePointer: BODY_SOURCE,
  media: [
    {
      media: "multipart/form-data",
      kind: "multipart",
      sourcePointer: MEDIA_SOURCE,
      fields: [
        {
          name: "meta",
          required: true,
          sourcePointer: MEDIA_SOURCE,
          repeated: false,
          payload: "json",
          contentType: { kind: "fixed", value: "application/json" },
          filename: false,
        },
        {
          name: "file",
          required: true,
          sourcePointer: MEDIA_SOURCE,
          repeated: false,
          payload: "binary",
          contentType: { kind: "fixed", value: "application/octet-stream" },
          filename: true,
        },
      ],
    },
  ],
} satisfies RequestBodyDescriptor & { readonly required: true };

async function encodedRequest(
  encode: (
    input: unknown,
  ) => Promise<{ readonly body: BodyInit | null; readonly contentType: string | null }>,
  input: unknown,
): Promise<Request> {
  const encoded = await encode(input);
  if (encoded.body === null || encoded.contentType === null) {
    throw new TypeError("body encoder returned an empty body");
  }
  return new Request("https://api.test/items", {
    method: "POST",
    headers: { "Content-Type": encoded.contentType },
    body: encoded.body,
  });
}

function bodyRequest(contentType: string | null, body: BodyInit): Request {
  const headers = new Headers();
  if (contentType !== null) {
    headers.set("Content-Type", contentType);
  }
  return new Request("https://api.test/items", { method: "POST", headers, body });
}

function byteBody(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function multipartDescriptor(
  fields: readonly MultipartFieldDescriptor[],
): RequestBodyDescriptor & { readonly required: true } {
  return {
    required: true,
    discriminated: false,
    sourcePointer: BODY_SOURCE,
    media: [
      {
        media: "multipart/form-data",
        kind: "multipart",
        sourcePointer: MEDIA_SOURCE,
        fields,
      },
    ],
  };
}

function urlencodedDescriptor(
  fields: readonly UrlencodedFieldDescriptor[],
): RequestBodyDescriptor & { readonly required: true } {
  return {
    required: true,
    discriminated: false,
    sourcePointer: BODY_SOURCE,
    media: [
      {
        media: "application/x-www-form-urlencoded",
        kind: "urlencoded",
        sourcePointer: MEDIA_SOURCE,
        fields,
      },
    ],
  };
}

function multipartField(
  overrides: Partial<MultipartFieldDescriptor> = {},
): MultipartFieldDescriptor {
  return {
    name: "value",
    required: true,
    sourcePointer: MEDIA_SOURCE,
    repeated: false,
    payload: "text",
    contentType: { kind: "none" },
    filename: false,
    ...overrides,
  };
}

async function multipartRequest(
  fields: readonly MultipartFieldDescriptor[],
  parts: Parameters<typeof encodeMultipart>[0],
): Promise<{
  readonly request: Request;
  readonly descriptor: RequestBodyDescriptor & { readonly required: true };
}> {
  const encoded = await encodeMultipart(parts);
  return {
    request: bodyRequest(encoded.contentTypeHeader, byteBody(encoded.body)),
    descriptor: multipartDescriptor(fields),
  };
}

describe("MSW request body projection round trips", () => {
  test("JSON uses the real JSON body encoder", async () => {
    const value = { name: "Ada", active: true };
    const request = await encodedRequest(jsonBody("application/json"), value);
    assert.deepEqual(await projectRequestBody<typeof value>(request, JSON_DESCRIPTOR), value);
  });

  test("text uses the real text body encoder", async () => {
    const value = "hello, 世界";
    const request = await encodedRequest(textBody("text/plain"), value);
    assert.equal(await projectRequestBody<string>(request, TEXT_DESCRIPTOR), value);
  });

  test("binary uses the real binary body encoder", async () => {
    const value = Uint8Array.of(0, 127, 255);
    const request = await encodedRequest(binaryBody("application/octet-stream"), value);
    assert.deepEqual(await projectRequestBody<Uint8Array>(request, BINARY_DESCRIPTOR), value);
  });

  test("form-urlencoded correlates repeated fields and percent-decodes values", async () => {
    const value = { name: "Ada & Bob", tags: ["red blue", "green"] };
    const request = await encodedRequest(
      urlencodedBody("application/x-www-form-urlencoded", [
        { name: "name", required: true, style: "form", explode: true, allowReserved: false },
        { name: "tags", required: false, style: "form", explode: true, allowReserved: false },
      ]),
      value,
    );
    assert.deepEqual(await projectRequestBody<typeof value>(request, URLENCODED_DESCRIPTOR), value);
  });

  test("form-urlencoded inverts JSON, text and every admitted style", async () => {
    const value = {
      json: { active: true },
      text: ["red", "blue"],
      spaced: ["a", "b"],
      piped: ["c", "d"],
      deep: { first: "Ada" },
      exploded: { first: "Grace" },
    };
    const request = await encodedRequest(
      urlencodedBody("application/x-www-form-urlencoded", [
        { name: "json", required: true, payloads: ["json"] },
        { name: "text", required: true, payloads: ["text"] },
        { name: "spaced", required: true, style: "spaceDelimited", explode: false },
        { name: "piped", required: true, style: "pipeDelimited", explode: false },
        { name: "deep", required: true, style: "deepObject", explode: true },
        { name: "exploded", required: true, style: "form", explode: true },
      ]),
      value,
    );
    const descriptor = urlencodedDescriptor([
      { name: "json", required: true, sourcePointer: MEDIA_SOURCE, decoder: "json" },
      {
        name: "text",
        required: true,
        sourcePointer: MEDIA_SOURCE,
        decoder: "text",
        shape: STRING_ARRAY_SHAPE,
      },
      {
        name: "spaced",
        required: true,
        sourcePointer: MEDIA_SOURCE,
        decoder: "style",
        helper: "query-space-delimited",
        shape: STRING_ARRAY_SHAPE,
      },
      {
        name: "piped",
        required: true,
        sourcePointer: MEDIA_SOURCE,
        decoder: "style",
        helper: "query-pipe-delimited",
        shape: STRING_ARRAY_SHAPE,
      },
      {
        name: "deep",
        required: true,
        sourcePointer: MEDIA_SOURCE,
        decoder: "style",
        helper: "query-deep-object-extended",
        shape: OBJECT_SHAPE,
      },
      {
        name: "exploded",
        required: true,
        sourcePointer: MEDIA_SOURCE,
        decoder: "style",
        helper: "query-form-explode",
        shape: OBJECT_SHAPE,
      },
    ]);
    assert.deepEqual(await projectRequestBody<typeof value>(request, descriptor), value);
  });

  test("multipart validates and decodes JSON and binary parts", async () => {
    const value = { meta: { name: "Ada" }, file: Uint8Array.of(0, 10, 255) };
    const request = await encodedRequest(
      multipartBody([
        {
          name: "meta",
          required: true,
          repeated: false,
          wrapper: false,
          payload: "json",
          contentType: { kind: "fixed", value: "application/json" },
          filename: false,
        },
        {
          name: "file",
          required: true,
          repeated: false,
          wrapper: false,
          payload: "binary",
          contentType: { kind: "fixed", value: "application/octet-stream" },
          filename: true,
        },
      ]),
      value,
    );
    assert.deepEqual(await projectRequestBody<typeof value>(request, MULTIPART_DESCRIPTOR), value);
  });

  test("the sent media chooses a discriminated exact or range arm", async () => {
    const descriptor = {
      required: true,
      discriminated: true,
      sourcePointer: BODY_SOURCE,
      media: [
        { media: "*/*", kind: "binary", sourcePointer: MEDIA_SOURCE },
        { media: "application/*", kind: "text", sourcePointer: MEDIA_SOURCE },
        { media: "application/json;charset=utf-8", kind: "json", sourcePointer: MEDIA_SOURCE },
      ],
    } satisfies RequestBodyDescriptor & { readonly required: true };
    const value = { selected: true };
    const request = await encodedRequest(jsonBody("Application/JSON; Charset=UTF-8"), value);
    assert.deepEqual(
      await projectRequestBody<{ contentType: string; body: typeof value }>(request, descriptor),
      { contentType: "application/json;charset=utf-8", body: value },
    );

    const ranged = await encodedRequest(textBody("application/custom; version=2"), "range");
    assert.deepEqual(
      await projectRequestBody<{ contentType: string; body: string }>(ranged, descriptor),
      { contentType: "application/custom;version=2", body: "range" },
    );
  });

  test("media matching canonicalizes quoted parameters", async () => {
    const descriptor = {
      required: true,
      discriminated: true,
      sourcePointer: BODY_SOURCE,
      media: [
        { media: "application/*", kind: "text", sourcePointer: MEDIA_SOURCE },
        {
          media: 'application/json;charset=utf-8;profile="a;b\\\"c"',
          kind: "json",
          sourcePointer: MEDIA_SOURCE,
        },
      ],
    } satisfies RequestBodyDescriptor & { readonly required: true };
    const request = bodyRequest(
      'Application/JSON; profile="a;b\\\"c"; Charset="UTF-8"',
      '{"ok":true}',
    );
    assert.deepEqual(
      await projectRequestBody<{ contentType: string; body: { readonly ok: boolean } }>(
        request,
        descriptor,
      ),
      {
        contentType: 'application/json;charset=utf-8;profile="a;b\\\"c"',
        body: { ok: true },
      },
    );

    const ranged = bodyRequest("application/custom", "text");
    assert.deepEqual(
      await projectRequestBody<{ contentType: string; body: string }>(ranged, descriptor),
      { contentType: "application/custom", body: "text" },
    );
  });

  test("multipart selected media and repeated parts follow their field plan", async () => {
    const field = multipartField({
      name: "values",
      repeated: true,
      payload: "binary",
      payloads: ["binary", "text", "json"],
      contentType: {
        kind: "selected",
        admitted: ["*/*", "application/*", "application/json"],
      },
    });
    const encoded = await multipartRequest(
      [field],
      [
        { name: "values", contentType: "application/json", payload: new TextEncoder().encode("1") },
        {
          name: "values",
          contentType: "application/custom",
          payload: new TextEncoder().encode("two"),
        },
      ],
    );
    assert.deepEqual(await projectRequestBody(encoded.request, encoded.descriptor), {
      values: [1, "two"],
    });
  });

  test("an absent optional body projects to undefined without requiring Content-Type", async () => {
    const descriptor = {
      ...JSON_DESCRIPTOR,
      required: false,
    } satisfies RequestBodyDescriptor & { readonly required: false };
    assert.equal(
      await projectRequestBody<unknown>(new Request("https://api.test/items"), descriptor),
      undefined,
    );
  });
});

async function expectBlocked(
  code: OastsHandlerError["code"],
  project: () => unknown,
  applicationPath?: OastsHandlerError["applicationPath"],
): Promise<void> {
  let resolverCalled = false;
  await assert.rejects(
    async () => {
      await project();
      resolverCalled = true;
    },
    (error: unknown) => {
      assert.ok(error instanceof OastsHandlerError);
      assert.equal(error.code, code);
      if (applicationPath !== undefined) {
        assert.deepEqual(error.applicationPath, applicationPath);
      }
      return true;
    },
  );
  assert.equal(resolverCalled, false);
}

describe("MSW malformed request bodies", () => {
  test("every handler error code blocks the resolver", async () => {
    await expectBlocked("parameter-decode", () =>
      projectParameter(
        {
          request: new Request("https://api.test/items/not-an-integer"),
          baseUrl: "https://api.test",
          pathTemplate: [[{ literal: "items" }], [{ parameter: "id" }]],
        },
        {
          location: "path",
          name: "id",
          helper: "path-simple",
          required: true,
          shape: { kind: "integer" },
          sourcePointer: BODY_SOURCE,
          applicationPath: ["id"],
          queryParameterNames: [],
        },
      ),
    );

    await expectBlocked(
      "content-type-mismatch",
      () => projectRequestBody(bodyRequest("image/png", Uint8Array.of(1)), JSON_DESCRIPTOR),
      null,
    );

    await expectBlocked(
      "body-decode",
      () => projectRequestBody(bodyRequest("application/json", "{"), JSON_DESCRIPTOR),
      ["body"],
    );

    await expectBlocked(
      "multipart-decode",
      () =>
        projectRequestBody(
          bodyRequest("multipart/form-data; boundary=broken", "not multipart"),
          MULTIPART_DESCRIPTOR,
        ),
      ["body"],
    );

    await expectBlocked(
      "body-missing",
      () => projectRequestBody(new Request("https://api.test/items"), JSON_DESCRIPTOR),
      null,
    );
  });

  test("malformed UTF-8 and a consumed binary body are body-decode errors", async () => {
    await expectBlocked("body-decode", () =>
      projectRequestBody(
        new Request("https://api.test/items", {
          method: "POST",
          headers: { "Content-Type": "text/plain" },
          body: Uint8Array.of(0xff),
        }),
        TEXT_DESCRIPTOR,
      ),
    );

    const consumed = new Request("https://api.test/items", {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: Uint8Array.of(1),
    });
    await consumed.arrayBuffer();
    await expectBlocked("body-decode", () => projectRequestBody(consumed, BINARY_DESCRIPTOR));
  });

  test("missing, non-concrete and unmatched media are content-type mismatches", async () => {
    await expectBlocked("content-type-mismatch", () =>
      projectRequestBody(bodyRequest(null, byteBody(Uint8Array.of(1))), JSON_DESCRIPTOR),
    );
    for (const contentType of ["application", "application/", "application/*", "text/plain"]) {
      await expectBlocked("content-type-mismatch", () =>
        projectRequestBody(bodyRequest(contentType, "{}"), JSON_DESCRIPTOR),
      );
    }
    await expectBlocked("content-type-mismatch", () =>
      projectRequestBody(bodyRequest("application/json;profile=actual", "{}"), {
        ...JSON_DESCRIPTOR,
        media: [
          {
            ...JSON_DESCRIPTOR.media[0],
            media: "application/json;profile=declared",
          },
        ],
      }),
    );
  });

  test("malformed declared media are ignored when another declaration matches", async () => {
    const malformed = [
      "application",
      "application/",
      "application/json ",
      "application/json; =x",
      "application/json;p",
      "application/json;p=",
      'application/json;p="unterminated',
      'application/json;p="escape\\',
      "application/json;p=x;p=y",
      "application/json;p=\u007f",
      'application/json;p="bad\u0001value"',
    ];
    for (const media of malformed) {
      const descriptor = {
        ...JSON_DESCRIPTOR,
        media: [{ media, kind: "text", sourcePointer: MEDIA_SOURCE }, ...JSON_DESCRIPTOR.media],
      } satisfies RequestBodyDescriptor & { readonly required: true };
      assert.deepEqual(
        await projectRequestBody(bodyRequest("application/json", "{}"), descriptor),
        {},
      );
    }
  });

  test("a range discriminant preserves parameters that need quoting and stable sorting", async () => {
    const descriptor = {
      required: true,
      discriminated: true,
      sourcePointer: BODY_SOURCE,
      media: [{ media: "application/*", kind: "text", sourcePointer: MEDIA_SOURCE }],
    } satisfies RequestBodyDescriptor & { readonly required: true };
    const request = bodyRequest('application/custom; aa=z; profile="a b\\\"c"; a=z', "value");
    assert.deepEqual(await projectRequestBody(request, descriptor), {
      contentType: 'application/custom;a=z;aa=z;profile="a b\\\"c"',
      body: "value",
    });
  });

  test("form-urlencoded rejects missing, ambiguous and undeclared pairs", async () => {
    const required = {
      name: "value",
      required: true,
      sourcePointer: MEDIA_SOURCE,
      decoder: "style",
      helper: "query-form-explode",
      shape: STRING_SHAPE,
    } as const;
    for (const body of ["", "value", "other=x", "value=a&value=b"]) {
      await expectBlocked("body-decode", () =>
        projectRequestBody(
          bodyRequest("application/x-www-form-urlencoded", body),
          urlencodedDescriptor([required]),
        ),
      );
    }
    await expectBlocked("body-decode", () =>
      projectRequestBody(
        bodyRequest("application/x-www-form-urlencoded", "other=x"),
        urlencodedDescriptor([{ ...required, required: false }]),
      ),
    );

    const openObject = {
      kind: "object",
      properties: {},
      additional: true,
    } as const;
    const ambiguous = urlencodedDescriptor([
      {
        name: "left",
        required: true,
        sourcePointer: MEDIA_SOURCE,
        decoder: "style",
        helper: "query-form-explode",
        shape: openObject,
      },
      {
        name: "right",
        required: true,
        sourcePointer: MEDIA_SOURCE,
        decoder: "style",
        helper: "query-form-explode",
        shape: openObject,
      },
    ]);
    await expectBlocked("body-decode", () =>
      projectRequestBody(
        bodyRequest("application/x-www-form-urlencoded", "unknown=value"),
        ambiguous,
      ),
    );
  });

  test("form-urlencoded correlation follows nullable, union and intersection shapes", async () => {
    const variants = [
      { kind: "nullable", value: OBJECT_SHAPE },
      { kind: "union", variants: [OBJECT_SHAPE, OBJECT_SHAPE] },
      { kind: "intersection", variants: [OBJECT_SHAPE] },
    ] as const;
    for (const shape of variants) {
      const descriptor = urlencodedDescriptor([
        {
          name: "value",
          required: true,
          sourcePointer: MEDIA_SOURCE,
          decoder: "style",
          helper: "query-form-explode",
          shape,
        },
      ]);
      assert.deepEqual(
        await projectRequestBody(
          bodyRequest("application/x-www-form-urlencoded", "first=Ada"),
          descriptor,
        ),
        { value: { first: "Ada" } },
      );
    }
  });

  test("body descriptors reject fields from the other form encoding", async () => {
    await expectBlocked("body-decode", () =>
      projectRequestBody(bodyRequest("application/x-www-form-urlencoded", "value=x"), {
        ...URLENCODED_DESCRIPTOR,
        media: [{ ...URLENCODED_DESCRIPTOR.media[0], fields: [multipartField()] }],
      }),
    );
    const encoded = await encodeMultipart([
      { name: "value", payload: new TextEncoder().encode("x") },
    ]);
    await expectBlocked("multipart-decode", () =>
      projectRequestBody(bodyRequest(encoded.contentTypeHeader, byteBody(encoded.body)), {
        ...MULTIPART_DESCRIPTOR,
        media: [
          { ...MULTIPART_DESCRIPTOR.media[0], fields: URLENCODED_DESCRIPTOR.media[0].fields },
        ],
      }),
    );
  });

  test("form body descriptors default an omitted field table to empty", async () => {
    assert.deepEqual(
      await projectRequestBody(bodyRequest("application/x-www-form-urlencoded", ""), {
        ...URLENCODED_DESCRIPTOR,
        media: [
          {
            media: "application/x-www-form-urlencoded",
            kind: "urlencoded",
            sourcePointer: MEDIA_SOURCE,
          },
        ],
      }),
      {},
    );
    assert.deepEqual(
      await projectRequestBody(bodyRequest("multipart/form-data;boundary=b", "--b--"), {
        ...MULTIPART_DESCRIPTOR,
        media: [
          {
            media: "multipart/form-data",
            kind: "multipart",
            sourcePointer: MEDIA_SOURCE,
          },
        ],
      }),
      {},
    );
  });

  test("an optional JSON form field can be absent", async () => {
    assert.deepEqual(
      await projectRequestBody(
        bodyRequest("application/x-www-form-urlencoded", ""),
        urlencodedDescriptor([
          {
            name: "value",
            required: false,
            sourcePointer: MEDIA_SOURCE,
            decoder: "json",
          },
        ]),
      ),
      {},
    );
  });

  test("multipart accepts escaped names, optional fields and an empty body", async () => {
    const escapedName = 'a"b\\c';
    const escaped = await multipartRequest(
      [multipartField({ name: escapedName })],
      [{ name: escapedName, payload: new TextEncoder().encode("value") }],
    );
    assert.deepEqual(await projectRequestBody(escaped.request, escaped.descriptor), {
      [escapedName]: "value",
    });

    const optional = multipartDescriptor([multipartField({ required: false })]);
    assert.deepEqual(
      await projectRequestBody(bodyRequest("multipart/form-data;boundary=b", "--b--"), optional),
      {},
    );
  });

  test("multipart rejects invalid boundaries and framing", async () => {
    const descriptor = multipartDescriptor([]);
    const cases = [
      ["multipart/form-data", "--b--"],
      ['multipart/form-data;boundary=""', "----"],
      [`multipart/form-data;boundary=${"a".repeat(71)}`, "--a--"],
      ['multipart/form-data;boundary="bad["', "--bad[--"],
      ['multipart/form-data;boundary="bad "', "--bad --"],
      ["multipart/form-data;boundary=boundary", "-"],
      ["multipart/form-data;boundary=b", "--b--trailing"],
      ["multipart/form-data;boundary=b", "--b\n"],
      ["multipart/form-data;boundary=b", "--b\r\npart"],
      ["multipart/form-data;boundary=b", "--b\r\n\r\n\r\n--b--trailing"],
      ["multipart/form-data;boundary=b", "--b\r\n\r\n\r\n--bnext"],
    ] as const;
    for (const [contentType, body] of cases) {
      await expectBlocked("multipart-decode", () =>
        projectRequestBody(bodyRequest(contentType, body), descriptor),
      );
    }
  });

  test("multipart validates declared names and repetitions", async () => {
    const undeclared = await encodeMultipart([
      { name: "other", payload: new TextEncoder().encode("x") },
    ]);
    await expectBlocked("multipart-decode", () =>
      projectRequestBody(
        bodyRequest(undeclared.contentTypeHeader, byteBody(undeclared.body)),
        multipartDescriptor([multipartField()]),
      ),
    );

    const repeated = await encodeMultipart([
      { name: "value", payload: new TextEncoder().encode("x") },
      { name: "value", payload: new TextEncoder().encode("y") },
    ]);
    await expectBlocked("multipart-decode", () =>
      projectRequestBody(
        bodyRequest(repeated.contentTypeHeader, byteBody(repeated.body)),
        multipartDescriptor([multipartField()]),
      ),
    );

    await expectBlocked("multipart-decode", () =>
      projectRequestBody(
        bodyRequest(
          "multipart/form-data;boundary=b",
          "--b\r\nContent-Disposition: form-data; name=value\r\n\r\nx\r\n--b--trailing",
        ),
        multipartDescriptor([multipartField()]),
      ),
    );

    await expectBlocked("multipart-decode", () =>
      projectRequestBody(
        bodyRequest("multipart/form-data;boundary=b", "--b--"),
        multipartDescriptor([multipartField()]),
      ),
    );
  });

  test("multipart validates every part header", async () => {
    const malformedHeaders = [
      "Broken",
      ": value",
      "Content-Disposition: form-data; name=value\r\nContent-Disposition: form-data; name=value",
      "Content-Disposition: form-data; name=value\r\nX-Test: no",
      "Content-Type: text/plain",
      "Content-Disposition: attachment; name=value",
      "Content-Disposition: form-data; bad=value",
      "Content-Disposition: form-data; name=value; name=again",
      "Content-Disposition: form-data; filename=file",
      'Content-Disposition: form-data; name="unterminated',
      'Content-Disposition: form-data; name="value"junk',
      "Content-Disposition: form-data; name=bad value",
      'Content-Disposition: form-data; name="bad\u0001value"',
    ];
    for (const headers of malformedHeaders) {
      const body = `--b\r\n${headers}\r\n\r\nx\r\n--b--`;
      await expectBlocked("multipart-decode", () =>
        projectRequestBody(
          bodyRequest("multipart/form-data;boundary=b", body),
          multipartDescriptor([multipartField()]),
        ),
      );
    }
    await expectBlocked("multipart-decode", () =>
      projectRequestBody(
        bodyRequest(
          "multipart/form-data;boundary=b",
          "--b\r\nContent-Disposition: form-data; name=value\r\n--b--",
        ),
        multipartDescriptor([multipartField()]),
      ),
    );
  });

  test("multipart validates filename and fixed Content-Type policies", async () => {
    const cases: readonly {
      readonly field: MultipartFieldDescriptor;
      readonly part: Parameters<typeof encodeMultipart>[0][number];
    }[] = [
      {
        field: multipartField(),
        part: { name: "value", filename: "file.txt", payload: new TextEncoder().encode("x") },
      },
      {
        field: multipartField(),
        part: { name: "value", contentType: "text/plain", payload: new TextEncoder().encode("x") },
      },
      {
        field: multipartField({ contentType: { kind: "fixed", value: "text/plain" } }),
        part: { name: "value", payload: new TextEncoder().encode("x") },
      },
      {
        field: multipartField({ contentType: { kind: "fixed", value: "text/plain" } }),
        part: {
          name: "value",
          contentType: "application/json",
          payload: new TextEncoder().encode("x"),
        },
      },
      {
        field: multipartField({ contentType: { kind: "fixed", value: "bad" } }),
        part: { name: "value", contentType: "text/plain", payload: new TextEncoder().encode("x") },
      },
    ];
    for (const value of cases) {
      const encoded = await multipartRequest([value.field], [value.part]);
      await expectBlocked("multipart-decode", () =>
        projectRequestBody(encoded.request, encoded.descriptor),
      );
    }
  });

  test("multipart validates selected per-part media and payload plans", async () => {
    const selected = multipartField({
      contentType: { kind: "selected", admitted: ["text/plain"] },
      payloads: ["text"],
    });
    const cases = [
      { field: selected, contentType: undefined },
      { field: selected, contentType: "*/*" },
      { field: selected, contentType: "application/json" },
      {
        field: multipartField({
          contentType: { kind: "selected", admitted: ["bad", "text/plain"] },
          payloads: ["text"],
        }),
        contentType: "text/plain",
      },
    ] as const;
    for (const value of cases) {
      const part = {
        name: "value",
        payload: new TextEncoder().encode("x"),
        ...(value.contentType === undefined ? {} : { contentType: value.contentType }),
      };
      const encoded = await multipartRequest([value.field], [part]);
      await expectBlocked("multipart-decode", () =>
        projectRequestBody(encoded.request, encoded.descriptor),
      );
    }

    const ranged = multipartField({
      contentType: { kind: "selected", admitted: ["text/*"] },
      payloads: ["text"],
    });
    const encoded = await multipartRequest(
      [ranged],
      [{ name: "value", contentType: "text/plain", payload: new TextEncoder().encode("text") }],
    );
    assert.deepEqual(await projectRequestBody(encoded.request, encoded.descriptor), {
      value: "text",
    });
  });
});
