import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import {
  encodeFormUrlencodedBody,
  parseMediaType,
  serializeContentJsonHeader,
  serializeContentJsonPath,
  serializeContentJsonQuery,
  serializeHeaderSimple,
  serializeHeaderSimpleExplode,
  serializeMediaType,
  serializePathLabel,
  serializePathLabelExplode,
  serializePathMatrix,
  serializePathMatrixExplode,
  serializePathSimple,
  serializePathSimpleExplode,
  serializeQueryDeepObject,
  serializeQueryDeepObjectExtended,
  serializeQueryForm,
  serializeQueryFormExplode,
  serializeQueryPipeDelimited,
  serializeQueryPipeDelimitedObject,
  serializeQuerySpaceDelimited,
  serializeQuerySpaceDelimitedObject,
} from "../serialize.ts";
import { encodeInt64 } from "../transform-runtime.ts";
import { MEDIA_VECTORS } from "./vectors-media.ts";
import {
  STYLE_VECTORS,
  type JsonPrimitive,
  type StyleValue,
  type StyleVector,
} from "./vectors-styles.ts";

function isPrimitiveArray(value: StyleValue): value is readonly JsonPrimitive[] {
  return Array.isArray(value);
}

function isPrimitiveObject(value: StyleValue): value is Readonly<Record<string, JsonPrimitive>> {
  return typeof value === "object" && !Array.isArray(value);
}

function serializeStyleVector(vector: StyleVector): string {
  const { allowReserved, explode, paramName, style, value } = vector;

  if (vector.location === "path") {
    if (style === "simple") {
      return explode
        ? serializePathSimpleExplode(paramName, value, allowReserved)
        : serializePathSimple(paramName, value, allowReserved);
    }
    if (style === "label") {
      return explode
        ? serializePathLabelExplode(paramName, value, allowReserved)
        : serializePathLabel(paramName, value, allowReserved);
    }
    if (style === "matrix") {
      return explode
        ? serializePathMatrixExplode(paramName, value, allowReserved)
        : serializePathMatrix(paramName, value, allowReserved);
    }
  }

  if (vector.location === "query") {
    if (style === "form") {
      return explode
        ? serializeQueryFormExplode(paramName, value, allowReserved)
        : serializeQueryForm(paramName, value, allowReserved);
    }
    if (style === "spaceDelimited" && isPrimitiveArray(value)) {
      return serializeQuerySpaceDelimited(paramName, value, allowReserved);
    }
    if (style === "pipeDelimited" && isPrimitiveArray(value)) {
      return serializeQueryPipeDelimited(paramName, value, allowReserved);
    }
    if (style === "deepObject" && isPrimitiveObject(value)) {
      return serializeQueryDeepObject(paramName, value, allowReserved);
    }
  }

  if (vector.location === "header" && style === "simple") {
    return explode
      ? serializeHeaderSimpleExplode(paramName, value, allowReserved)
      : serializeHeaderSimple(paramName, value, allowReserved);
  }

  throw new Error(`unsupported style vector: ${vector.location}/${style}/${String(explode)}`);
}

function findStyleVector(predicate: (vector: StyleVector) => boolean): StyleVector {
  const vector = STYLE_VECTORS.find(predicate);
  assert.ok(vector);
  return vector;
}

describe("parameter styles", () => {
  for (const [index, vector] of STYLE_VECTORS.entries()) {
    test(`vector ${index + 1}: ${vector.location}/${vector.style}/explode=${String(vector.explode)}`, () => {
      assert.equal(serializeStyleVector(vector), vector.expected);
    });
  }
});

describe("content JSON serialization", () => {
  // A content-sourced JSON parameter (OpenAPI Parameter Object `content`) stringifies the raw typed
  // value — including nested shapes a flat ParamValue could never hold — then applies the location's
  // wire framing: component-encoded `name=value` for query/cookie, an encoded path segment, and the
  // raw simple-header value.
  test("query wraps the JSON text as a component-encoded name=value pair", () => {
    assert.equal(serializeContentJsonQuery("filter", { n: 1 }, false), "filter=%7B%22n%22%3A1%7D");
    assert.equal(
      serializeContentJsonQuery("filter", { tags: ["a", "b"] }, false),
      "filter=%7B%22tags%22%3A%5B%22a%22%2C%22b%22%5D%7D",
    );
  });

  test("carries a transformed int64 as exact JSON digits", () => {
    const pointer = { logicalSourceId: "openapi.yaml", jsonPointer: "/parameters/filter" };
    const id = encodeInt64(12345678901234567890n, pointer, ["query", "filter"]);
    assert.equal(
      serializeContentJsonQuery("filter", { id }, false),
      "filter=%7B%22id%22%3A12345678901234567890%7D",
    );
  });

  test("path percent-encodes the JSON text as one segment with no name", () => {
    assert.equal(serializeContentJsonPath("p", { n: 1 }, false), "%7B%22n%22%3A1%7D");
    assert.equal(serializeContentJsonPath("p", [1, 2], false), "%5B1%2C2%5D");
  });

  test("header emits the JSON text verbatim without component encoding", () => {
    assert.equal(serializeContentJsonHeader("h", { a: "b c/d" }, false), '{"a":"b c/d"}');
  });

  test("a value JSON cannot represent is rejected", () => {
    assert.throws(() => serializeContentJsonHeader("h", undefined, false), TypeError);
    assert.throws(() => serializeContentJsonQuery("q", () => 1, false), TypeError);
  });
});

describe("delimited query objects", () => {
  for (const [style, serialize, separator] of [
    ["spaceDelimited", serializeQuerySpaceDelimitedObject, "%20"],
    ["pipeDelimited", serializeQueryPipeDelimitedObject, "%7C"],
  ] as const) {
    test(`${style} encodes each component when reserved characters are disallowed`, () => {
      assert.equal(
        serialize("color", { "R?": "/100", G: 200, B: false }, false),
        `color=R%3F${separator}%2F100${separator}G${separator}200${separator}B${separator}false`,
      );
    });

    test(`${style} preserves reserved characters when allowed`, () => {
      assert.equal(
        serialize("color", { "R?": "/100", G: 200, B: false }, true),
        `color=R?${separator}/100${separator}G${separator}200${separator}B${separator}false`,
      );
    });

    test(`${style} serializes an empty object`, () => {
      assert.equal(serialize("color", {}, false), "color=");
    });
  }
});

describe("form-urlencoded body", () => {
  test("defaults each field to form with explode enabled", () => {
    assert.equal(
      encodeFormUrlencodedBody([
        { name: "a", value: 1 },
        { name: "b", value: "x y" },
      ]),
      "a=1&b=x%20y",
    );
  });

  test("composes the pinned spaceDelimited query fragment", () => {
    const vector = findStyleVector((candidate) => candidate.style === "spaceDelimited");
    assert.ok(isPrimitiveArray(vector.value));
    assert.equal(
      encodeFormUrlencodedBody([
        {
          name: vector.paramName,
          value: vector.value,
          style: "spaceDelimited",
          explode: vector.explode,
          allowReserved: vector.allowReserved,
        },
      ]),
      vector.expected,
    );
  });

  test("composes the pinned pipeDelimited query fragment", () => {
    const vector = findStyleVector((candidate) => candidate.style === "pipeDelimited");
    assert.ok(isPrimitiveArray(vector.value));
    assert.equal(
      encodeFormUrlencodedBody([
        {
          name: vector.paramName,
          value: vector.value,
          style: "pipeDelimited",
          explode: vector.explode,
          allowReserved: vector.allowReserved,
        },
      ]),
      vector.expected,
    );
  });

  test("composes the pinned deepObject query fragment", () => {
    const vector = findStyleVector((candidate) => candidate.style === "deepObject");
    assert.ok(isPrimitiveObject(vector.value));
    assert.equal(
      encodeFormUrlencodedBody([
        {
          name: vector.paramName,
          value: vector.value,
          style: "deepObject",
          explode: vector.explode,
          allowReserved: vector.allowReserved,
        },
      ]),
      vector.expected,
    );
  });

  test("extended deepObject applies the bracket-path rule at every depth", () => {
    // Only the object form is specified, so these encodings are pinned here rather than derived
    // from the conformance vectors. They match `qs.stringify` for the same values.
    assert.equal(
      serializeQueryDeepObjectExtended("tags", ["a", "b"], false),
      "tags[0]=a&tags[1]=b",
    );
    assert.equal(
      serializeQueryDeepObjectExtended("filter", { colour: "red" }, false),
      "filter[colour]=red",
    );
    // A scalar has no nesting to bracket, so it is the same rule at depth zero.
    assert.equal(serializeQueryDeepObjectExtended("q", "plain", false), "q=plain");
    // An untyped schema dispatches on the value it is handed, so every form reaches one helper.
    assert.equal(serializeQueryDeepObjectExtended("raw", [], false), "");
    assert.equal(serializeQueryDeepObjectExtended("raw", {}, false), "");
    assert.equal(serializeQueryDeepObjectExtended("q", ["a b"], true), "q[0]=a%20b");
  });

  test("composes the pinned allowReserved form fragment", () => {
    const vector = findStyleVector(
      (candidate) =>
        candidate.style === "form" && candidate.allowReserved && candidate.value === "/?#[]@&= ",
    );
    assert.equal(
      encodeFormUrlencodedBody([
        {
          name: vector.paramName,
          value: vector.value,
          style: "form",
          explode: vector.explode,
          allowReserved: vector.allowReserved,
        },
      ]),
      vector.expected,
    );
  });

  test("json fields serialize the JSON representation after percent-encoding", () => {
    // OAS 3.1.1: urlencoded bodies encode complex objects after serializing them to a string, so a
    // JSON object is JSON.stringify'd then RFC1866 percent-encoded — `{`→%7B, `"`→%22, `:`→%3A,
    // ` `→%20, `}`→%7D.
    assert.equal(
      encodeFormUrlencodedBody([{ name: "address", json: { streetAddress: "123 Main St" } }]),
      "address=%7B%22streetAddress%22%3A%22123%20Main%20St%22%7D",
    );
  });

  test("json string fields keep their JSON quotes on the wire", () => {
    // A JSON-serialized string keeps its quotes: JSON.stringify("u") === '"u"' → %22u%22.
    assert.equal(encodeFormUrlencodedBody([{ name: "id", json: "u" }]), "id=%22u%22");
  });

  test("json fields reject values JSON cannot represent", () => {
    assert.throws(() => encodeFormUrlencodedBody([{ name: "n", json: 10n }]), /BigInt/u);
    assert.throws(
      () => encodeFormUrlencodedBody([{ name: "n", json: () => 1 }]),
      /not serializable/u,
    );
  });

  test("rejects styles paired with the wrong value shape", () => {
    assert.throws(
      () => encodeFormUrlencodedBody([{ name: "value", value: "x", style: "spaceDelimited" }]),
      /spaceDelimited fields require an array value/u,
    );
    assert.throws(
      () => encodeFormUrlencodedBody([{ name: "value", value: "x", style: "pipeDelimited" }]),
      /pipeDelimited fields require an array value/u,
    );
    // A deepObject field brackets an array by index and an object by key, and leaves a scalar as a
    // plain pair — the same bracket-path rule at each depth.
    assert.equal(
      encodeFormUrlencodedBody([{ name: "value", value: ["x"], style: "deepObject" }]),
      "value[0]=x",
    );
    assert.equal(
      encodeFormUrlencodedBody([{ name: "value", value: "x", style: "deepObject" }]),
      "value=x",
    );
  });
});

describe("canonical media types", () => {
  for (const [index, vector] of MEDIA_VECTORS.entries()) {
    test(`vector ${index + 1}: ${vector.verdict}`, () => {
      const parsed = parseMediaType(vector.input);
      if (vector.verdict === "canonical") {
        assert.ok(parsed);
        assert.equal(serializeMediaType(parsed), vector.expectedCanonical);
      } else {
        assert.equal(parsed, null);
      }
    });
  }

  test("all canonical members in a group converge", () => {
    const canonicalByGroup = new Map<string, string>();
    for (const vector of MEDIA_VECTORS) {
      if (vector.verdict !== "canonical") {
        continue;
      }
      const parsed = parseMediaType(vector.input);
      assert.ok(parsed);
      const canonical = serializeMediaType(parsed);
      const previous = canonicalByGroup.get(vector.group);
      if (previous === undefined) {
        canonicalByGroup.set(vector.group, canonical);
      } else {
        assert.equal(canonical, previous);
      }
    }
  });

  test("parses wildcard components and quoted empty values", () => {
    const wildcard = parseMediaType("*/*");
    assert.deepEqual(wildcard, { type: "*", subtype: "*", parameters: [] });

    const emptyQuoted = parseMediaType('text/plain\t;\tname=""');
    assert.ok(emptyQuoted);
    assert.equal(serializeMediaType(emptyQuoted), 'text/plain; name=""');
  });

  test("orders parameter names by bytes when one name prefixes another", () => {
    const parsed = parseMediaType("text/plain; a-=dash; a=short; a!=bang");
    assert.ok(parsed);
    assert.equal(serializeMediaType(parsed), "text/plain; a=short; a!=bang; a-=dash");
  });

  test("rejects every strict grammar boundary", () => {
    const invalidInputs = [
      "",
      "application",
      "application/",
      "application/xml ",
      "application/xml trailing",
      "application/xml;",
      "application/xml; =x",
      "application/xml; name =x",
      "application/xml; name= utf-8",
      'application/xml; name="unterminated',
      'application/xml; name="bad\\',
      'application/xml; name="bad\\\u0001"',
      'application/xml; name="bad\u0100"',
      'application/xml; name="bad\tvalue"',
    ];

    for (const input of invalidInputs) {
      assert.equal(parseMediaType(input), null, input);
    }
  });
});

describe("serialize.ts region grammar", () => {
  test("keeps deterministic, non-nested, fully enclosed export regions", () => {
    const source = readFileSync(new URL("../serialize.ts", import.meta.url), "utf8");
    const lines = source.split("\n");
    const regionLine = /^\/\/#region (oxs:(?:core|helper:[a-z0-9-]+))$/;
    const regions: { readonly id: string; readonly source: string }[] = [];
    let openRegion: { readonly id: string; readonly start: number } | undefined;
    let startCount = 0;
    let endCount = 0;

    for (const [index, line] of lines.entries()) {
      if (line.startsWith("//#region")) {
        const match = regionLine.exec(line);
        assert.ok(match, `invalid region line: ${line}`);
        assert.equal(openRegion, undefined, "regions must not nest");
        const id = match[1];
        assert.ok(id);
        openRegion = { id, start: index };
        startCount += 1;
        continue;
      }

      if (line === "//#endregion") {
        assert.ok(openRegion, "endregion must close an open region");
        regions.push({
          id: openRegion.id,
          source: lines.slice(openRegion.start, index + 1).join("\n"),
        });
        openRegion = undefined;
        endCount += 1;
        continue;
      }

      if (/^export\s/u.test(line)) {
        assert.ok(openRegion, `top-level export outside a region: ${line}`);
      }
    }

    assert.equal(openRegion, undefined);
    assert.equal(startCount, endCount);
    assert.equal(regions[0]?.id, "oxs:core");
    assert.equal(new Set(regions.map((region) => region.id)).size, regions.length);

    const helperIds = regions
      .map((region) => region.id)
      .filter((id) => id.startsWith("oxs:helper:"));
    assert.deepEqual(helperIds, helperIds.toSorted());

    const expectedHelpers: readonly (readonly [string, string])[] = [
      ["oxs:helper:path-simple", "serializePathSimple"],
      ["oxs:helper:path-simple-explode", "serializePathSimpleExplode"],
      ["oxs:helper:path-label", "serializePathLabel"],
      ["oxs:helper:path-label-explode", "serializePathLabelExplode"],
      ["oxs:helper:path-matrix", "serializePathMatrix"],
      ["oxs:helper:path-matrix-explode", "serializePathMatrixExplode"],
      ["oxs:helper:query-form", "serializeQueryForm"],
      ["oxs:helper:query-form-explode", "serializeQueryFormExplode"],
      ["oxs:helper:query-space-delimited", "serializeQuerySpaceDelimited"],
      ["oxs:helper:query-space-delimited-object", "serializeQuerySpaceDelimitedObject"],
      ["oxs:helper:query-pipe-delimited", "serializeQueryPipeDelimited"],
      ["oxs:helper:query-pipe-delimited-object", "serializeQueryPipeDelimitedObject"],
      ["oxs:helper:query-deep-object", "serializeQueryDeepObject"],
      ["oxs:helper:query-deep-object-extended", "serializeQueryDeepObjectExtended"],
      ["oxs:helper:header-simple", "serializeHeaderSimple"],
      ["oxs:helper:header-simple-explode", "serializeHeaderSimpleExplode"],
      ["oxs:helper:form-urlencoded-body", "encodeFormUrlencodedBody"],
      ["oxs:helper:media-canonical", "parseMediaType"],
      ["oxs:helper:media-canonical", "serializeMediaType"],
      ["oxs:helper:multipart", "encodeMultipart"],
      ["oxs:helper:multipart-cd", "escapeContentDispositionName"],
      ["oxs:helper:multipart-cd", "encodeContentDispositionFilename"],
      ["oxs:helper:multipart-response", "decodeMultipartResponse"],
      ["oxs:helper:content-json-header", "serializeContentJsonHeader"],
      ["oxs:helper:content-json-path", "serializeContentJsonPath"],
      ["oxs:helper:content-json-query", "serializeContentJsonQuery"],
    ];

    for (const [regionId, helperName] of expectedHelpers) {
      const region = regions.find((candidate) => candidate.id === regionId);
      assert.ok(region, `missing region ${regionId}`);
      assert.match(region.source, new RegExp(`export (?:async )?function ${helperName}\\b`, "u"));
    }

    for (const region of regions) {
      for (const [helperRegionId, helperName] of expectedHelpers) {
        if (region.id !== helperRegionId) {
          assert.doesNotMatch(
            region.source,
            new RegExp(`\\b${helperName}\\b`, "u"),
            `${region.id} must not depend on ${helperRegionId}`,
          );
        }
      }
    }
  });
});
