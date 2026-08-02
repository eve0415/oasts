import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  projectParameter,
  type ParameterHelper,
  type ParameterShape,
  type ProjectedValue,
  type ProjectionContext,
} from "../msw-project.ts";
import { OastsHandlerError } from "../msw-runtime.ts";
import {
  serializeContentJsonHeader,
  serializeContentJsonPath,
  serializeContentJsonQuery,
  serializeHeaderSimple,
  serializeHeaderSimpleExplode,
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

const SOURCE_POINTER = {
  logicalSourceId: "$single",
  jsonPointer: "/paths/~1items~1{p}/get/parameters/0",
} as const;
const PATH_TEMPLATE = [[{ literal: "items" }], [{ parameter: "p" }]] as const;

const STRING_SHAPE = { kind: "string" } as const;
const NUMBER_SHAPE = { kind: "number" } as const;
const INTEGER_SHAPE = { kind: "integer" } as const;
const BOOLEAN_SHAPE = { kind: "boolean" } as const;
const STRING_ARRAY_SHAPE = { kind: "array", items: STRING_SHAPE } as const;
const NUMBER_OBJECT_SHAPE = {
  kind: "object",
  properties: {
    R: { required: true, shape: NUMBER_SHAPE },
    G: { required: true, shape: NUMBER_SHAPE },
  },
  additional: false,
} as const;
const STRING_OBJECT_SHAPE = {
  kind: "object",
  properties: {
    k: { required: true, shape: STRING_SHAPE },
  },
  additional: false,
} as const;
const JSON_SHAPE = {
  kind: "object",
  properties: {
    name: { required: true, shape: STRING_SHAPE },
    tags: { required: true, shape: STRING_ARRAY_SHAPE },
    active: { required: false, shape: BOOLEAN_SHAPE },
  },
  additional: false,
} as const;

function pathContext(serialized: string, baseUrl = "https://api.test/v1"): ProjectionContext {
  return {
    request: new Request(`${baseUrl}/items/${serialized}`),
    baseUrl,
    pathTemplate: PATH_TEMPLATE,
  };
}

function queryContext(serialized: string): ProjectionContext {
  return {
    request: new Request(`https://api.test/v1/items/value?${serialized}`),
    baseUrl: "https://api.test/v1",
    pathTemplate: PATH_TEMPLATE,
  };
}

function headerContext(name: string, serialized: string): ProjectionContext {
  return {
    request: new Request("https://api.test/v1/items/value", {
      headers: { [name]: serialized },
    }),
    baseUrl: "https://api.test/v1",
    pathTemplate: PATH_TEMPLATE,
  };
}

function cookieContext(serialized: string): ProjectionContext {
  const equals = serialized.indexOf("=");
  if (equals < 0) {
    throw new TypeError("serialized cookie parameter lacks an equals sign");
  }
  return {
    request: new Request("https://api.test/v1/items/value"),
    baseUrl: "https://api.test/v1",
    pathTemplate: PATH_TEMPLATE,
    cookies: { [serialized.slice(0, equals)]: serialized.slice(equals + 1) },
  };
}

function projectRequired<const S extends ParameterShape>(
  context: ProjectionContext,
  location: "path" | "query" | "header" | "cookie",
  helper: ParameterHelper,
  shape: S,
  name = "p",
  queryParameterNames: readonly string[] = [name],
): ProjectedValue<S> {
  return projectParameter(context, {
    location,
    name,
    helper,
    required: true,
    shape,
    sourcePointer: SOURCE_POINTER,
    applicationPath: [name],
    queryParameterNames,
  });
}

function projectOptional<const S extends ParameterShape>(
  context: ProjectionContext,
  location: "path" | "query" | "header" | "cookie",
  helper: ParameterHelper,
  shape: S,
  name = "p",
  queryParameterNames: readonly string[] = [name],
): ProjectedValue<S> | undefined {
  return projectParameter(context, {
    location,
    name,
    helper,
    required: false,
    shape,
    sourcePointer: SOURCE_POINTER,
    applicationPath: [name],
    queryParameterNames,
  });
}

function expectDecodeError(project: () => unknown): void {
  assert.throws(project, OastsHandlerError);
}

describe("MSW parameter projection round trips", () => {
  test("all path helpers invert the real serializers", () => {
    const object = { R: 100, G: 200 };
    const strings = ["blue", "black"];

    const simple = serializePathSimple("p", 42, false);
    assert.equal(projectRequired(pathContext(simple), "path", "path-simple", INTEGER_SHAPE), 42);

    const simpleExplode = serializePathSimpleExplode("p", object, false);
    assert.deepEqual(
      projectRequired(
        pathContext(simpleExplode),
        "path",
        "path-simple-explode",
        NUMBER_OBJECT_SHAPE,
      ),
      object,
    );

    const label = serializePathLabel("p", strings, false);
    assert.deepEqual(
      projectRequired(pathContext(label), "path", "path-label", STRING_ARRAY_SHAPE),
      strings,
    );

    const labelExplode = serializePathLabelExplode("p", "blue", false);
    assert.equal(
      projectRequired(pathContext(labelExplode), "path", "path-label-explode", STRING_SHAPE),
      "blue",
    );

    const matrix = serializePathMatrix("p", object, false);
    assert.deepEqual(
      projectRequired(pathContext(matrix), "path", "path-matrix", NUMBER_OBJECT_SHAPE),
      object,
    );

    const matrixExplode = serializePathMatrixExplode("p", object, false);
    assert.deepEqual(
      projectRequired(
        pathContext(matrixExplode),
        "path",
        "path-matrix-explode",
        NUMBER_OBJECT_SHAPE,
      ),
      object,
    );

    const json = { name: "blue", tags: ["a", "b"], active: true };
    const content = serializeContentJsonPath("p", json, false);
    assert.deepEqual(
      projectRequired(pathContext(content), "path", "content-json-path", JSON_SHAPE),
      json,
    );

    const dotted = ["a.b", "c"];
    const safeLabel = serializePathLabel("p", dotted, false);
    assert.equal(safeLabel, ".a.b,c");
    assert.deepEqual(
      projectRequired(pathContext(safeLabel), "path", "path-label", STRING_ARRAY_SHAPE),
      dotted,
    );

    const ambiguousLabel = serializePathLabelExplode("p", dotted, false);
    assert.equal(ambiguousLabel, ".a.b.c");
    expectDecodeError(() =>
      projectRequired(
        pathContext(ambiguousLabel),
        "path",
        "path-label-explode",
        STRING_ARRAY_SHAPE,
      ),
    );

    const ambiguousObject = serializePathLabelExplode("p", { k: "a.b" }, false);
    assert.equal(ambiguousObject, ".k=a.b");
    expectDecodeError(() =>
      projectRequired(
        pathContext(ambiguousObject),
        "path",
        "path-label-explode",
        STRING_OBJECT_SHAPE,
      ),
    );

    const emptyLabel = serializePathLabelExplode("p", [], false);
    assert.equal(emptyLabel, "");
    expectDecodeError(() =>
      projectRequired(pathContext(emptyLabel), "path", "path-label-explode", STRING_ARRAY_SHAPE),
    );

    const emptyMatrixArray = serializePathMatrixExplode("p", [], false);
    assert.equal(emptyMatrixArray, "");
    assert.deepEqual(
      projectRequired(
        pathContext(emptyMatrixArray),
        "path",
        "path-matrix-explode",
        STRING_ARRAY_SHAPE,
      ),
      [],
    );

    const emptyObjectShape = { kind: "object", properties: {}, additional: false } as const;
    const emptyMatrixObject = serializePathMatrixExplode("p", {}, false);
    assert.equal(emptyMatrixObject, "");
    assert.deepEqual(
      projectRequired(
        pathContext(emptyMatrixObject),
        "path",
        "path-matrix-explode",
        emptyObjectShape,
      ),
      {},
    );

    const wrappedCollections = [
      { kind: "nullable", value: STRING_ARRAY_SHAPE },
      { kind: "union", variants: [STRING_SHAPE, STRING_ARRAY_SHAPE] },
      {
        kind: "intersection",
        variants: [{ kind: "unknown" }, STRING_OBJECT_SHAPE],
      },
    ] as const;
    for (const shape of wrappedCollections) {
      expectDecodeError(() =>
        projectRequired(pathContext(ambiguousLabel), "path", "path-label-explode", shape),
      );
    }

    const wrappedScalars = [
      { kind: "nullable", value: STRING_SHAPE },
      { kind: "union", variants: [STRING_SHAPE] },
      { kind: "intersection", variants: [STRING_SHAPE, STRING_SHAPE] },
    ] as const;
    for (const shape of wrappedScalars) {
      assert.equal(
        projectRequired(pathContext(".blue"), "path", "path-label-explode", shape),
        "blue",
      );
    }
  });

  test("all query helpers invert the real serializers", () => {
    const object = { R: 100, G: 200 };
    const strings = ["blue", "black"];

    const form = serializeQueryForm("p", object, false);
    assert.deepEqual(
      projectRequired(queryContext(form), "query", "query-form", NUMBER_OBJECT_SHAPE),
      object,
    );

    const formExplode = serializeQueryFormExplode("p", strings, false);
    assert.deepEqual(
      projectRequired(queryContext(formExplode), "query", "query-form-explode", STRING_ARRAY_SHAPE),
      strings,
    );

    const space = serializeQuerySpaceDelimited("p", strings, false);
    assert.deepEqual(
      projectRequired(queryContext(space), "query", "query-space-delimited", STRING_ARRAY_SHAPE),
      strings,
    );

    const spaceObject = serializeQuerySpaceDelimitedObject("p", object, false);
    assert.deepEqual(
      projectRequired(
        queryContext(spaceObject),
        "query",
        "query-space-delimited-object",
        NUMBER_OBJECT_SHAPE,
      ),
      object,
    );

    const pipe = serializeQueryPipeDelimited("p", strings, false);
    assert.deepEqual(
      projectRequired(queryContext(pipe), "query", "query-pipe-delimited", STRING_ARRAY_SHAPE),
      strings,
    );

    const pipeObject = serializeQueryPipeDelimitedObject("p", object, false);
    assert.deepEqual(
      projectRequired(
        queryContext(pipeObject),
        "query",
        "query-pipe-delimited-object",
        NUMBER_OBJECT_SHAPE,
      ),
      object,
    );

    const deep = serializeQueryDeepObject("p", object, false);
    assert.deepEqual(
      projectRequired(queryContext(deep), "query", "query-deep-object", NUMBER_OBJECT_SHAPE),
      object,
    );

    const extended = serializeQueryDeepObjectExtended("p", strings, false);
    assert.deepEqual(
      projectRequired(
        queryContext(extended),
        "query",
        "query-deep-object-extended",
        STRING_ARRAY_SHAPE,
      ),
      strings,
    );

    const json = { name: "blue", tags: ["a", "b"], active: true };
    const content = serializeContentJsonQuery("p", json, false);
    assert.deepEqual(
      projectRequired(queryContext(content), "query", "content-json-query", JSON_SHAPE),
      json,
    );

    const reservedArray = ["a,b", "c"];
    const reservedArrayWire = serializeQueryForm("p", reservedArray, true);
    assert.equal(reservedArrayWire, "p=a,b,c");
    expectDecodeError(() =>
      projectParameter(queryContext(reservedArrayWire), {
        location: "query",
        name: "p",
        helper: "query-form",
        required: true,
        allowReserved: true,
        shape: STRING_ARRAY_SHAPE,
        sourcePointer: SOURCE_POINTER,
        applicationPath: ["p"],
        queryParameterNames: ["p"],
      }),
    );

    const reservedScalar = "a&b=1";
    const reservedScalarWire = serializeQueryForm("p", reservedScalar, true);
    assert.equal(reservedScalarWire, "p=a&b=1");
    expectDecodeError(() =>
      projectParameter(queryContext(reservedScalarWire), {
        location: "query",
        name: "p",
        helper: "query-form",
        required: true,
        allowReserved: true,
        shape: STRING_SHAPE,
        sourcePointer: SOURCE_POINTER,
        applicationPath: ["p"],
        queryParameterNames: ["p"],
      }),
    );
  });

  test("all header helpers invert the real serializers", () => {
    const object = { R: 100, G: 200 };
    const simple = serializeHeaderSimple("X-Value", object, false);
    assert.deepEqual(
      projectRequired(
        headerContext("X-Value", simple),
        "header",
        "header-simple",
        NUMBER_OBJECT_SHAPE,
        "X-Value",
      ),
      object,
    );

    const exploded = serializeHeaderSimpleExplode("X-Value", object, false);
    assert.deepEqual(
      projectRequired(
        headerContext("X-Value", exploded),
        "header",
        "header-simple-explode",
        NUMBER_OBJECT_SHAPE,
        "X-Value",
      ),
      object,
    );

    for (const value of ["%41", "a%2Cb", "50%"] as const) {
      const wire = serializeHeaderSimple("X-Value", value, false);
      assert.equal(wire, value);
      assert.equal(
        projectRequired(
          headerContext("X-Value", wire),
          "header",
          "header-simple",
          STRING_SHAPE,
          "X-Value",
        ),
        value,
      );
    }

    const delimited = { k: "a,b" };
    const delimitedWire = serializeHeaderSimpleExplode("X-Value", delimited, false);
    assert.equal(delimitedWire, "k=a,b");
    assert.deepEqual(
      projectRequired(
        headerContext("X-Value", delimitedWire),
        "header",
        "header-simple-explode",
        STRING_OBJECT_SHAPE,
        "X-Value",
      ),
      delimited,
    );

    const array = ["%41", "50%"];
    const arrayWire = serializeHeaderSimple("X-Value", array, false);
    assert.equal(arrayWire, "%41,50%");
    assert.deepEqual(
      projectRequired(
        headerContext("X-Value", arrayWire),
        "header",
        "header-simple",
        STRING_ARRAY_SHAPE,
        "X-Value",
      ),
      array,
    );

    const emptyObject = { kind: "object", properties: {}, additional: false } as const;
    assert.deepEqual(
      projectRequired(
        headerContext("X-Value", ""),
        "header",
        "header-simple-explode",
        emptyObject,
        "X-Value",
      ),
      {},
    );

    const openObject = {
      kind: "object",
      properties: {},
      additional: STRING_SHAPE,
    } as const;
    assert.deepEqual(
      projectRequired(
        headerContext("X-Value", "first=a,second=b"),
        "header",
        "header-simple-explode",
        openObject,
        "X-Value",
      ),
      { first: "a", second: "b" },
    );

    const json = { name: "blue", tags: ["a", "b"] };
    const content = serializeContentJsonHeader("X-Value", json, false);
    assert.deepEqual(
      projectRequired(
        headerContext("X-Value", content),
        "header",
        "content-json-header",
        JSON_SHAPE,
        "X-Value",
      ),
      json,
    );
  });

  test("cookie helpers invert the client serializers", () => {
    const object = { k: "a,b" };
    const wire = serializeQueryForm("p", object, false);
    assert.equal(wire, "p=k,a%2Cb");
    assert.deepEqual(
      projectRequired(cookieContext(wire), "cookie", "query-form", STRING_OBJECT_SHAPE),
      object,
    );

    const json = { name: "blue", tags: ["a", "b"] };
    const jsonWire = serializeContentJsonQuery("p", json, false);
    assert.deepEqual(
      projectRequired(cookieContext(jsonWire), "cookie", "content-json-query", JSON_SHAPE),
      json,
    );
  });
});

describe("MSW malformed parameter projection", () => {
  test("an optional absent value stays absent", () => {
    assert.equal(
      projectOptional(queryContext("other=value"), "query", "query-form", STRING_SHAPE),
      undefined,
    );
    assert.equal(
      projectOptional(pathContext("value"), "cookie", "query-form", STRING_SHAPE),
      undefined,
    );
    assert.equal(
      projectOptional(
        { ...pathContext("value"), cookies: {} },
        "cookie",
        "query-form",
        STRING_SHAPE,
      ),
      undefined,
    );
    assert.equal(
      projectOptional(pathContext("value"), "cookie", "content-json-query", STRING_SHAPE),
      undefined,
    );
  });

  test("a malformed required value rejects before the resolver can run", () => {
    assert.throws(
      () => projectRequired(pathContext("not-an-integer"), "path", "path-simple", INTEGER_SHAPE),
      (error: unknown) => {
        assert.ok(error instanceof OastsHandlerError);
        assert.equal(error.code, "parameter-decode");
        assert.deepEqual(error.sourcePointer, SOURCE_POINTER);
        assert.deepEqual(error.applicationPath, ["p"]);
        assert.ok(error.cause instanceof TypeError);
        return true;
      },
    );
  });

  test("missing values and path mismatches are decode errors only when required", () => {
    const noQuery: ProjectionContext = {
      request: new Request("https://api.test/v1/items/value"),
      baseUrl: "https://api.test/v1",
      pathTemplate: PATH_TEMPLATE,
    };
    assert.equal(projectOptional(noQuery, "query", "query-form", STRING_SHAPE), undefined);
    assert.equal(projectOptional(noQuery, "query", "content-json-query", STRING_SHAPE), undefined);
    assert.equal(projectOptional(noQuery, "header", "header-simple", STRING_SHAPE), undefined);
    assert.equal(
      projectOptional(noQuery, "header", "content-json-header", STRING_SHAPE),
      undefined,
    );
    assert.equal(
      projectOptional(pathContext("value"), "path", "path-simple", STRING_SHAPE, "absent"),
      undefined,
    );
    assert.equal(
      projectOptional(pathContext("value"), "path", "content-json-path", STRING_SHAPE, "absent"),
      undefined,
    );

    expectDecodeError(() => projectRequired(noQuery, "query", "query-form", STRING_SHAPE));
    const wrongPath: ProjectionContext = {
      request: new Request("https://api.test/v1/other/value"),
      baseUrl: "https://api.test/v1",
      pathTemplate: PATH_TEMPLATE,
    };
    expectDecodeError(() => projectRequired(wrongPath, "path", "path-simple", STRING_SHAPE));

    const root: ProjectionContext = {
      request: new Request("https://api.test/"),
      baseUrl: "https://api.test",
      pathTemplate: [],
    };
    assert.equal(projectOptional(root, "path", "path-simple", STRING_SHAPE), undefined);
  });

  test("invalid helper/location pairings and query framing are rejected", () => {
    expectDecodeError(() =>
      projectRequired(pathContext("x"), "path", "header-simple", STRING_SHAPE),
    );
    expectDecodeError(() =>
      projectRequired(headerContext("p", "x"), "header", "path-simple", STRING_SHAPE),
    );
    expectDecodeError(() =>
      projectRequired(queryContext("p=x"), "query", "path-simple", STRING_SHAPE),
    );
    expectDecodeError(() =>
      projectRequired(queryContext("p=a&p=b"), "query", "query-form", STRING_SHAPE),
    );
    assert.equal(projectRequired(queryContext("p"), "query", "query-form", STRING_SHAPE), "");
    expectDecodeError(() =>
      projectRequired(queryContext("p=%ZZ"), "query", "query-form", STRING_SHAPE),
    );
    expectDecodeError(() =>
      projectRequired(cookieContext("p=x"), "cookie", "query-form-explode", STRING_SHAPE),
    );
  });

  test("form explode projects primitive and object shapes without stealing sibling parameters", () => {
    assert.equal(
      projectRequired(queryContext("p=true"), "query", "query-form-explode", BOOLEAN_SHAPE),
      true,
    );
    assert.equal(
      projectRequired(queryContext("p=null"), "query", "query-form-explode", {
        kind: "nullable",
        value: INTEGER_SHAPE,
      } as const),
      null,
    );
    assert.equal(
      projectOptional(
        queryContext("other=value"),
        "query",
        "query-form-explode",
        STRING_ARRAY_SHAPE,
      ),
      undefined,
    );
    assert.equal(
      projectOptional(queryContext("other=value"), "query", "query-form-explode", STRING_SHAPE),
      undefined,
    );
    assert.deepEqual(
      projectRequired(
        queryContext("R=100&G=200&other=leave"),
        "query",
        "query-form-explode",
        NUMBER_OBJECT_SHAPE,
        "p",
        ["p", "other"],
      ),
      { R: 100, G: 200 },
    );
    assert.equal(
      projectOptional(
        queryContext("other=leave"),
        "query",
        "query-form-explode",
        NUMBER_OBJECT_SHAPE,
      ),
      undefined,
    );
    const openObject = { kind: "object", properties: {}, additional: true } as const;
    assert.equal(
      projectOptional(queryContext("other=leave"), "query", "query-form-explode", openObject, "p", [
        "p",
        "other",
      ]),
      undefined,
    );
    assert.deepEqual(
      projectRequired(queryContext("extra=value"), "query", "query-form-explode", openObject),
      { extra: "value" },
    );
  });

  test("delimited and deep-object malformed forms fail closed", () => {
    expectDecodeError(() =>
      projectRequired(queryContext("p=x"), "query", "query-space-delimited", STRING_SHAPE),
    );
    assert.equal(
      projectOptional(queryContext("other=x"), "query", "query-pipe-delimited", STRING_ARRAY_SHAPE),
      undefined,
    );
    assert.deepEqual(
      projectRequired(queryContext("p="), "query", "query-space-delimited", STRING_ARRAY_SHAPE),
      [],
    );
    expectDecodeError(() =>
      projectRequired(queryContext("p=null"), "query", "query-pipe-delimited", {
        kind: "nullable",
        value: STRING_ARRAY_SHAPE,
      } as const),
    );
    assert.equal(
      projectOptional(
        queryContext("other=x"),
        "query",
        "query-deep-object-extended",
        STRING_ARRAY_SHAPE,
      ),
      undefined,
    );
    assert.equal(
      projectOptional(queryContext("other=x"), "query", "query-deep-object", NUMBER_OBJECT_SHAPE),
      undefined,
    );
    expectDecodeError(() =>
      projectRequired(
        queryContext("p[1]=x"),
        "query",
        "query-deep-object-extended",
        STRING_ARRAY_SHAPE,
      ),
    );
    for (const malformed of ["p[-1]=x", "p[01]=x", "p[x]=x"]) {
      expectDecodeError(() =>
        projectRequired(
          queryContext(malformed),
          "query",
          "query-deep-object-extended",
          STRING_ARRAY_SHAPE,
        ),
      );
    }
    assert.equal(
      projectRequired(queryContext("p=true"), "query", "query-deep-object-extended", BOOLEAN_SHAPE),
      true,
    );
    assert.equal(
      projectRequired(queryContext("p=null"), "query", "query-deep-object-extended", {
        kind: "nullable",
        value: INTEGER_SHAPE,
      } as const),
      null,
    );
    assert.equal(
      projectOptional(
        queryContext("other=x"),
        "query",
        "query-deep-object-extended",
        BOOLEAN_SHAPE,
      ),
      undefined,
    );
    expectDecodeError(() =>
      projectRequired(queryContext("p=x"), "query", "query-deep-object", STRING_SHAPE),
    );
  });

  test("matrix framing covers primitive and array forms and rejects malformed entries", () => {
    assert.equal(
      projectRequired(pathContext(";p=true"), "path", "path-matrix-explode", BOOLEAN_SHAPE),
      true,
    );
    assert.equal(
      projectRequired(pathContext(";p=null"), "path", "path-matrix-explode", {
        kind: "nullable",
        value: INTEGER_SHAPE,
      } as const),
      null,
    );
    assert.deepEqual(
      projectRequired(pathContext(";p=a;p=b"), "path", "path-matrix-explode", STRING_ARRAY_SHAPE),
      ["a", "b"],
    );
    for (const raw of [";other=a", "p=a", ";p"]) {
      expectDecodeError(() =>
        projectRequired(pathContext(raw), "path", "path-matrix-explode", STRING_ARRAY_SHAPE),
      );
    }
    expectDecodeError(() =>
      projectRequired(pathContext(";other=true"), "path", "path-matrix-explode", BOOLEAN_SHAPE),
    );
    expectDecodeError(() =>
      projectRequired(pathContext(""), "path", "path-matrix-explode", BOOLEAN_SHAPE),
    );

    const encodedName = "p!";
    const context: ProjectionContext = {
      request: new Request("https://api.test/v1/items/;p%21=x"),
      baseUrl: "https://api.test/v1",
      pathTemplate: [[{ literal: "items" }], [{ parameter: encodedName }]],
    };
    assert.equal(projectRequired(context, "path", "path-matrix", STRING_SHAPE, encodedName), "x");
  });

  test("simple framing validates separators, declared properties, and empty collections", () => {
    assert.deepEqual(
      projectRequired(pathContext(""), "path", "path-simple", STRING_ARRAY_SHAPE),
      [],
    );
    const emptyObject = {
      kind: "object",
      properties: {},
      additional: false,
    } as const;
    assert.deepEqual(
      projectRequired(headerContext("p", ""), "header", "header-simple", emptyObject),
      {},
    );
    expectDecodeError(() =>
      projectRequired(headerContext("p", "R"), "header", "header-simple", NUMBER_OBJECT_SHAPE),
    );
    expectDecodeError(() =>
      projectRequired(
        headerContext("p", "R,100,R,200"),
        "header",
        "header-simple",
        NUMBER_OBJECT_SHAPE,
      ),
    );
    expectDecodeError(() =>
      projectRequired(
        headerContext("p", "R=100,bad"),
        "header",
        "header-simple-explode",
        NUMBER_OBJECT_SHAPE,
      ),
    );
    expectDecodeError(() =>
      projectRequired(
        headerContext("p", "R=100,X=bad"),
        "header",
        "header-simple-explode",
        NUMBER_OBJECT_SHAPE,
      ),
    );
    expectDecodeError(() =>
      projectRequired(
        headerContext("p", "bad"),
        "header",
        "header-simple-explode",
        STRING_OBJECT_SHAPE,
      ),
    );
    expectDecodeError(() =>
      projectRequired(pathContext("R=100,bad"), "path", "path-simple-explode", NUMBER_OBJECT_SHAPE),
    );
    expectDecodeError(() =>
      projectRequired(
        headerContext("p", "X,100,G,200"),
        "header",
        "header-simple",
        NUMBER_OBJECT_SHAPE,
      ),
    );
    expectDecodeError(() =>
      projectRequired(headerContext("p", "R,100"), "header", "header-simple", NUMBER_OBJECT_SHAPE),
    );
    expectDecodeError(() =>
      projectRequired(pathContext("blue"), "path", "path-label", STRING_SHAPE),
    );
  });

  test("open and schema-valued object properties are decoded safely", () => {
    const open = {
      kind: "object",
      properties: {},
      additional: true,
    } as const;
    assert.deepEqual(
      projectRequired(headerContext("p", "extra,value"), "header", "header-simple", open),
      { extra: "value" },
    );
    const numeric = {
      kind: "object",
      properties: {},
      additional: NUMBER_SHAPE,
    } as const;
    assert.deepEqual(
      projectRequired(headerContext("p", "extra,1"), "header", "header-simple", numeric),
      { extra: 1 },
    );
    const proto = projectRequired(
      headerContext("p", "__proto__,safe"),
      "header",
      "header-simple",
      open,
    );
    assert.deepEqual(Object.keys(proto), ["__proto__"]);

    const declaredProto = {
      kind: "object",
      properties: {
        ["__proto__"]: { required: true, shape: STRING_SHAPE },
      },
      additional: false,
    } as const;
    assert.deepEqual(
      projectRequired(
        headerContext("p", "__proto__,safe"),
        "header",
        "header-simple",
        declaredProto,
      ),
      { ["__proto__"]: "safe" },
    );
  });

  test("scalar coercion follows nullable, literal, union, and intersection declarations", () => {
    const nullable = { kind: "nullable", value: INTEGER_SHAPE } as const;
    assert.equal(projectRequired(pathContext("null"), "path", "path-simple", nullable), null);
    assert.equal(projectRequired(pathContext("2"), "path", "path-simple", nullable), 2);

    const literal = {
      kind: "literal",
      values: [{ ignored: true }, "blue", 2, true, null],
    } as const;
    assert.equal(projectRequired(pathContext("blue"), "path", "path-simple", literal), "blue");
    expectDecodeError(() =>
      projectRequired(pathContext("missing"), "path", "path-simple", literal),
    );

    const union = {
      kind: "union",
      variants: [INTEGER_SHAPE, BOOLEAN_SHAPE],
    } as const;
    assert.equal(projectRequired(pathContext("true"), "path", "path-simple", union), true);
    const sameUnion = {
      kind: "union",
      variants: [STRING_SHAPE, { kind: "literal", values: ["x"] }],
    } as const;
    assert.equal(projectRequired(pathContext("x"), "path", "path-simple", sameUnion), "x");
    const distinctUnion = {
      kind: "union",
      variants: [STRING_SHAPE, INTEGER_SHAPE],
    } as const;
    expectDecodeError(() =>
      projectRequired(pathContext("1"), "path", "path-simple", distinctUnion),
    );
    const arrayUnion = {
      kind: "union",
      variants: [STRING_ARRAY_SHAPE, { kind: "array", items: { kind: "literal", values: ["x"] } }],
    } as const;
    assert.deepEqual(
      projectRequired(queryContext("p=x&p=x"), "query", "query-form-explode", arrayUnion),
      ["x", "x"],
    );
    const objectUnion = {
      kind: "union",
      variants: [
        {
          kind: "object",
          properties: { R: { required: true, shape: NUMBER_SHAPE } },
          additional: false,
        },
        {
          kind: "object",
          properties: { G: { required: true, shape: NUMBER_SHAPE } },
          additional: false,
        },
      ],
    } as const;
    const green = { G: 200 };
    assert.deepEqual(
      projectRequired(
        queryContext(serializeQueryForm("p", green, false)),
        "query",
        "query-form",
        objectUnion,
      ),
      green,
    );

    const intersection = {
      kind: "intersection",
      variants: [STRING_SHAPE, { kind: "literal", values: ["x"] }],
    } as const;
    assert.equal(projectRequired(pathContext("x"), "path", "path-simple", intersection), "x");
    expectDecodeError(() =>
      projectRequired(pathContext("1"), "path", "path-simple", {
        kind: "intersection",
        variants: [STRING_SHAPE, INTEGER_SHAPE],
      } as const),
    );
    expectDecodeError(() =>
      projectRequired(pathContext("x"), "path", "path-simple", {
        kind: "intersection",
        variants: [],
      } as const),
    );

    const composedProperties = {
      kind: "object",
      properties: {
        nullable: { required: true, shape: nullable },
        union: { required: true, shape: union },
        intersection: { required: true, shape: intersection },
      },
      additional: false,
    } as const;
    assert.deepEqual(
      projectRequired(
        headerContext("p", "nullable,null,union,true,intersection,x"),
        "header",
        "header-simple",
        composedProperties,
      ),
      { nullable: null, union: true, intersection: "x" },
    );
    assert.deepEqual(
      projectRequired(
        headerContext("p", "nullable,2,union,true,intersection,x"),
        "header",
        "header-simple",
        composedProperties,
      ),
      { nullable: 2, union: true, intersection: "x" },
    );
  });

  test("scalar enums preserve their inferred members and reject undeclared values", () => {
    const sorting = { kind: "string", enum: ["asc", "desc"] } as const;
    const sort: "asc" | "desc" = projectRequired(
      queryContext("p=asc"),
      "query",
      "query-form",
      sorting,
    );
    assert.equal(sort, "asc");

    const authors = {
      kind: "array",
      items: { kind: "string", enum: ["user", "bot"] },
    } as const;
    const authorTypes: ("user" | "bot")[] = projectRequired(
      queryContext("p=user&p=bot"),
      "query",
      "query-form-explode",
      authors,
    );
    assert.deepEqual(authorTypes, ["user", "bot"]);

    assert.equal(
      projectRequired(pathContext("2"), "path", "path-simple", {
        kind: "integer",
        enum: [1, 2],
      } as const),
      2,
    );
    assert.equal(
      projectRequired(pathContext("null"), "path", "path-simple", {
        kind: "null",
        enum: [null],
      } as const),
      null,
    );

    assert.throws(
      () => projectRequired(queryContext("p=sideways"), "query", "query-form", sorting),
      (error: unknown) => {
        assert.ok(error instanceof OastsHandlerError);
        assert.equal(error.code, "parameter-decode");
        assert.ok(error.cause instanceof TypeError);
        return true;
      },
    );
    expectDecodeError(() =>
      projectRequired(queryContext("p=user&p=system"), "query", "query-form-explode", authors),
    );
    expectDecodeError(() =>
      projectRequired(pathContext("3"), "path", "path-simple", {
        kind: "integer",
        enum: [1, 2],
      } as const),
    );
  });

  test("primitive scalar coercion accepts only canonical values", () => {
    assert.equal(
      projectRequired(pathContext("false"), "path", "path-simple", BOOLEAN_SHAPE),
      false,
    );
    expectDecodeError(() =>
      projectRequired(pathContext("yes"), "path", "path-simple", BOOLEAN_SHAPE),
    );
    for (const value of ["yes", "1.0", "Infinity", "NaN"]) {
      expectDecodeError(() =>
        projectRequired(pathContext(value), "path", "path-simple", NUMBER_SHAPE),
      );
    }
    expectDecodeError(() =>
      projectRequired(pathContext("1.5"), "path", "path-simple", INTEGER_SHAPE),
    );
    assert.equal(
      projectRequired(pathContext("null"), "path", "path-simple", { kind: "null" } as const),
      null,
    );
    expectDecodeError(() =>
      projectRequired(pathContext("x"), "path", "path-simple", { kind: "null" } as const),
    );
    expectDecodeError(() =>
      projectRequired(pathContext("x"), "path", "path-simple", { kind: "never" } as const),
    );
    expectDecodeError(() =>
      projectRequired(pathContext("x"), "path", "path-simple", {
        kind: "array",
        items: { kind: "object", properties: {}, additional: false },
      } as const),
    );
  });

  test("content JSON validates every supported schema shape", () => {
    const content = <const S extends ParameterShape>(value: string, shape: S) =>
      projectRequired(headerContext("p", value), "header", "content-json-header", shape);

    assert.equal(content("null", { kind: "nullable", value: STRING_SHAPE } as const), null);
    assert.equal(content('"x"', { kind: "nullable", value: STRING_SHAPE } as const), "x");
    assert.equal(content("null", { kind: "null" } as const), null);
    assert.equal(content("true", BOOLEAN_SHAPE), true);
    assert.equal(content("1.5", NUMBER_SHAPE), 1.5);
    assert.deepEqual(content("[1,2]", { kind: "array", items: INTEGER_SHAPE } as const), [1, 2]);
    assert.deepEqual(content('{"x":1}', { kind: "unknown" } as const), { x: 1 });

    const union = { kind: "union", variants: [INTEGER_SHAPE, STRING_SHAPE] } as const;
    assert.equal(content('"x"', union), "x");
    const intersection = {
      kind: "intersection",
      variants: [{ kind: "unknown" }, NUMBER_SHAPE],
    } as const;
    assert.equal(content("2", intersection), 2);
    assert.deepEqual(
      content('[1,{"x":2}]', {
        kind: "literal",
        values: [[1, { x: 2 }], [1], { x: 2 }],
      } as const),
      [1, { x: 2 }],
    );
    assert.equal(content('"asc"', { kind: "string", enum: ["asc", "desc"] } as const), "asc");
    expectDecodeError(() =>
      content('"sideways"', { kind: "string", enum: ["asc", "desc"] } as const),
    );

    for (const [value, shape] of [
      ["true", { kind: "string" }],
      ['"x"', { kind: "boolean" }],
      ['"x"', { kind: "null" }],
      ['"x"', { kind: "number" }],
      ["1.5", { kind: "integer" }],
      ["{}", { kind: "array", items: STRING_SHAPE }],
      ["[]", JSON_SHAPE],
      ["null", { kind: "never" }],
      ["true", { kind: "literal", values: [false] }],
      ["true", { kind: "union", variants: [STRING_SHAPE, NUMBER_SHAPE] }],
      ["1", { kind: "intersection", variants: [] }],
    ] as const) {
      expectDecodeError(() => content(value, shape));
    }
  });

  test("content JSON objects enforce required and additional-property shapes", () => {
    const content = <const S extends ParameterShape>(value: string, shape: S) =>
      projectRequired(headerContext("p", value), "header", "content-json-header", shape);
    expectDecodeError(() => content('{"tags":[]}', JSON_SHAPE));
    expectDecodeError(() => content('{"name":"x","tags":[],"extra":1}', JSON_SHAPE));

    const optional = {
      kind: "object",
      properties: { value: { required: false, shape: STRING_SHAPE } },
      additional: true,
    } as const;
    assert.deepEqual(content('{"extra":{"nested":true}}', optional), {
      extra: { nested: true },
    });
    const numericAdditional = {
      kind: "object",
      properties: { fixed: { required: true, shape: STRING_SHAPE } },
      additional: NUMBER_SHAPE,
    } as const;
    assert.deepEqual(content('{"fixed":"x","extra":2}', numericAdditional), {
      fixed: "x",
      extra: 2,
    });
    expectDecodeError(() => content('{"fixed":"x","extra":"bad"}', numericAdditional));
  });
});
