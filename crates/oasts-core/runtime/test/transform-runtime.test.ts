/// <reference lib="esnext.temporal" preserve="true" />
import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { TransformError } from "../result.ts";
import {
  decodeDateTimeDate,
  decodeInt64,
  guarded,
  decodeInstant,
  decodePlainDate,
  encodeDateTimeDate,
  encodeInt64,
  encodeInstant,
  encodePlainDate,
  isInstant,
  isPlainDate,
  omit,
  pushPath,
} from "../transform-runtime.ts";
import {
  CANONICAL_DATE_TIME,
  CANONICAL_INSTANT,
  CANONICAL_PLAIN_DATE,
  DATE_ACCEPTED,
  DATE_REJECTED,
  DATE_TIME_ACCEPTED,
  DATE_TIME_NANO_ACCEPTED,
  DATE_TIME_NANO_REJECTED,
  DATE_TIME_REJECTED,
  REQUEST_REJECTED_VALUES,
  TRANSFORM_ERROR_CASES,
  type WireRejectVector,
} from "./vectors-transform.ts";

const POINTER = {
  logicalSourceId: "workspace/openapi.yaml",
  jsonPointer: "/components/schemas/Pet/properties/bornAt",
};
const PATH: readonly (string | number)[] = ["pets", 0, "bornAt"];

// The Temporal codecs are only exercisable on a runtime that has the global. Node needs
// --harmony-temporal for it; the unflagged run exercises the missing-global path instead, and
// scripts/coverage-ts.sh runs flagged so both sides are reachable in one coverage report.
const temporalAvailable = typeof globalThis.Temporal !== "undefined";
const withoutTemporal = (body: () => void): void => {
  const saved = Object.getOwnPropertyDescriptor(globalThis, "Temporal");
  Object.defineProperty(globalThis, "Temporal", { value: undefined, configurable: true });
  try {
    body();
  } finally {
    if (saved === undefined) {
      Reflect.deleteProperty(globalThis, "Temporal");
    } else {
      Object.defineProperty(globalThis, "Temporal", saved);
    }
  }
};

function assertRejects(
  call: () => unknown,
  code: TransformError["code"],
  direction: TransformError["direction"],
  cite: string,
): TransformError {
  let thrown: unknown;
  try {
    call();
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown instanceof TransformError, `${cite}: expected a TransformError`);
  assert.equal(thrown.code, code, cite);
  assert.equal(thrown.direction, direction, cite);
  assert.deepEqual(thrown.sourcePointer, POINTER, cite);
  assert.deepEqual(thrown.applicationPath, PATH, cite);
  return thrown;
}

function rejectsWire(decode: (value: unknown) => unknown, vector: WireRejectVector): void {
  assertRejects(() => decode(vector.wire), "invalid-wire-value", "response", vector.cite);
}

describe("pushPath", () => {
  test("extends a path without mutating the parent", () => {
    const parent: readonly (string | number)[] = ["body"];
    assert.deepEqual(pushPath(parent, "bornAt"), ["body", "bornAt"]);
    assert.deepEqual(pushPath(parent, 2), ["body", 2]);
    assert.deepEqual(parent, ["body"]);
  });

  test("extends the root path", () => {
    assert.deepEqual(pushPath([], "at"), ["at"]);
  });
});

describe("omit", () => {
  test("removes one key without mutating the source", () => {
    const source = { a: 1, b: "two", c: true };
    assert.deepEqual(omit(source, "b"), { a: 1, c: true });
    assert.deepEqual(source, { a: 1, b: "two", c: true });
  });

  test("leaves an already-absent key absent", () => {
    const source: { a: number; b?: string } = { a: 1 };
    const result = omit(source, "b");
    assert.deepEqual(result, { a: 1 });
    assert.equal("b" in result, false);
  });
});

describe("integer: bigint", () => {
  test("decodes every lossless wire shape to bigint", () => {
    assert.equal(decodeInt64(42, POINTER, PATH), 42n);
    assert.equal(decodeInt64(12345678901234567890n, POINTER, PATH), 12345678901234567890n);
  });

  test("encodes exact unquoted digits at any JSON depth", () => {
    const encoded = encodeInt64(12345678901234567890n, POINTER, PATH);
    assert.equal(
      JSON.stringify({ outer: { list: [encoded, 7] } }),
      '{"outer":{"list":[12345678901234567890,7]}}',
    );
  });
});

describe("dateTime: date", () => {
  for (const vector of DATE_TIME_ACCEPTED) {
    test(`decodes ${vector.wire} (${vector.cite})`, () => {
      const decoded = decodeDateTimeDate(vector.wire, POINTER, PATH);
      assert.ok(decoded instanceof Date, vector.cite);
      assert.ok(Number.isFinite(decoded.getTime()), vector.cite);
    });
  }

  for (const vector of DATE_TIME_REJECTED) {
    test(`rejects ${JSON.stringify(vector.wire)} (${vector.cite})`, () => {
      rejectsWire((value) => decodeDateTimeDate(value, POINTER, PATH), vector);
    });
  }

  for (const vector of CANONICAL_DATE_TIME) {
    test(`re-encodes ${vector.wire} as ${vector.canonical}`, () => {
      const decoded = decodeDateTimeDate(vector.wire, POINTER, PATH);
      assert.equal(encodeDateTimeDate(decoded, POINTER, PATH), vector.canonical, vector.cite);
    });
  }

  test("round-trips on instant identity, never on wire-string identity", () => {
    for (const vector of DATE_TIME_ACCEPTED) {
      const decoded = decodeDateTimeDate(vector.wire, POINTER, PATH);
      const round = decodeDateTimeDate(encodeDateTimeDate(decoded, POINTER, PATH), POINTER, PATH);
      assert.equal(round.getTime(), decoded.getTime(), vector.cite);
    }
  });

  test("the wire cause is preserved on the error", () => {
    const error = assertRejects(
      () => decodeDateTimeDate("2024-03-01T12:00:60Z", POINTER, PATH),
      "invalid-wire-value",
      "response",
      "leap second",
    );
    assert.equal(error.cause, "2024-03-01T12:00:60Z");
  });
});

/// Reads the brand predicates on a runtime with no Temporal at all, where they must answer rather
/// than throw on the missing global.
const assertBrandsRefuseEverything = (): void => {
  assert.equal(isInstant("anything"), false);
  assert.equal(isPlainDate("anything"), false);
};

describe("the Temporal brand predicates", () => {
  test("recognize their own type and refuse everything else", { skip: !temporalAvailable }, () => {
    const instant = Temporal.Instant.from("2024-03-01T12:00:00Z");
    const plain = Temporal.PlainDate.from("2024-03-01");
    assert.ok(isInstant(instant));
    assert.ok(isPlainDate(plain));
    assert.equal(isInstant(plain), false);
    assert.equal(isPlainDate(instant), false);
    for (const other of [null, undefined, "2024-03-01", 1, new Date()]) {
      assert.equal(isInstant(other), false);
      assert.equal(isPlainDate(other), false);
    }
  });

  test("answer false rather than throwing where Temporal is missing", () => {
    if (temporalAvailable) {
      withoutTemporal(assertBrandsRefuseEverything);
    } else {
      assertBrandsRefuseEverything();
    }
  });
});

describe("dateTime: temporal", () => {
  for (const vector of DATE_TIME_NANO_ACCEPTED) {
    test(`decodes ${vector.wire} (${vector.cite})`, { skip: !temporalAvailable }, () => {
      const decoded = decodeInstant(vector.wire, POINTER, PATH);
      assert.ok(decoded instanceof Temporal.Instant, vector.cite);
    });
  }

  for (const vector of DATE_TIME_NANO_REJECTED) {
    test(
      `rejects ${JSON.stringify(vector.wire)} (${vector.cite})`,
      { skip: !temporalAvailable },
      () => {
        rejectsWire((value) => decodeInstant(value, POINTER, PATH), vector);
      },
    );
  }

  for (const vector of CANONICAL_INSTANT) {
    test(`re-encodes ${vector.wire} as ${vector.canonical}`, { skip: !temporalAvailable }, () => {
      const decoded = decodeInstant(vector.wire, POINTER, PATH);
      assert.equal(encodeInstant(decoded, POINTER, PATH), vector.canonical, vector.cite);
    });
  }

  test("round-trips on epoch nanoseconds", { skip: !temporalAvailable }, () => {
    for (const vector of DATE_TIME_NANO_ACCEPTED) {
      const decoded = decodeInstant(vector.wire, POINTER, PATH);
      const round = decodeInstant(encodeInstant(decoded, POINTER, PATH), POINTER, PATH);
      assert.ok(round.equals(decoded), vector.cite);
    }
  });
});

describe("date: temporal", () => {
  for (const vector of DATE_ACCEPTED) {
    test(`decodes ${vector.wire} (${vector.cite})`, { skip: !temporalAvailable }, () => {
      const decoded = decodePlainDate(vector.wire, POINTER, PATH);
      assert.ok(decoded instanceof Temporal.PlainDate, vector.cite);
    });
  }

  for (const vector of DATE_REJECTED) {
    test(
      `rejects ${JSON.stringify(vector.wire)} (${vector.cite})`,
      { skip: !temporalAvailable },
      () => {
        rejectsWire((value) => decodePlainDate(value, POINTER, PATH), vector);
      },
    );
  }

  for (const vector of CANONICAL_PLAIN_DATE) {
    test(`re-encodes ${vector.wire} as ${vector.canonical}`, { skip: !temporalAvailable }, () => {
      const decoded = decodePlainDate(vector.wire, POINTER, PATH);
      assert.equal(encodePlainDate(decoded, POINTER, PATH), vector.canonical, vector.cite);
    });
  }

  test("round-trips on PlainDate equality", { skip: !temporalAvailable }, () => {
    for (const vector of DATE_ACCEPTED) {
      const decoded = decodePlainDate(vector.wire, POINTER, PATH);
      const round = decodePlainDate(encodePlainDate(decoded, POINTER, PATH), POINTER, PATH);
      assert.ok(round.equals(decoded), vector.cite);
    }
  });
});

describe("application values no wire string can carry", () => {
  const encoders = {
    "dateTime-date": encodeDateTimeDate,
    "dateTime-temporal": encodeInstant,
    "date-temporal": encodePlainDate,
  };
  for (const vector of REQUEST_REJECTED_VALUES) {
    const needsTemporal = vector.mode !== "dateTime-date";
    test(vector.cite, { skip: needsTemporal && !temporalAvailable }, () => {
      const encode = encoders[vector.mode];
      assertRejects(
        () => encode(vector.build(), POINTER, PATH),
        "invalid-application-value",
        "request",
        vector.cite,
      );
    });
  }
});

describe("a runtime without Temporal", () => {
  test(
    "names the missing global rather than failing opaquely",
    { skip: !temporalAvailable },
    () => {
      withoutTemporal(() => {
        for (const call of [
          () => decodeInstant("2024-03-01T12:00:00Z", POINTER, PATH),
          () => decodePlainDate("2024-03-01", POINTER, PATH),
        ]) {
          assertRejects(call, "temporal-unavailable", "response", "decode without Temporal");
        }
        for (const call of [
          () => encodeInstant("anything", POINTER, PATH),
          () => encodePlainDate("anything", POINTER, PATH),
        ]) {
          assertRejects(call, "temporal-unavailable", "request", "encode without Temporal");
        }
      });
    },
  );

  test("is the path this run takes when Node is unflagged", { skip: temporalAvailable }, () => {
    assertRejects(
      () => decodeInstant("2024-03-01T12:00:00Z", POINTER, PATH),
      "temporal-unavailable",
      "response",
      "decodeInstant",
    );
    assertRejects(
      () => decodePlainDate("2024-03-01", POINTER, PATH),
      "temporal-unavailable",
      "response",
      "decodePlainDate",
    );
    assertRejects(
      () => encodeInstant("anything", POINTER, PATH),
      "temporal-unavailable",
      "request",
      "encodeInstant",
    );
    assertRejects(
      () => encodePlainDate("anything", POINTER, PATH),
      "temporal-unavailable",
      "request",
      "encodePlainDate",
    );
  });
});

describe("the frozen TransformError surface", () => {
  for (const vector of TRANSFORM_ERROR_CASES) {
    test(`${vector.direction} / ${vector.code} preserves every field`, () => {
      const error = new TransformError(vector);
      assert.equal(error.name, "TransformError");
      assert.equal(error.direction, vector.direction);
      assert.equal(error.code, vector.code);
      assert.deepEqual(error.sourcePointer, vector.sourcePointer);
      assert.deepEqual(error.applicationPath, vector.applicationPath);
      assert.equal(error.cause, vector.cause);
      assert.ok(error instanceof Error);
    });
  }
});

describe("guarded", () => {
  const GUARD_POINTER = {
    logicalSourceId: "workspace/openapi.yaml",
    jsonPointer: "/paths/~1events/get/responses/200",
  };

  test("passes a successful conversion straight through", () => {
    assert.equal(
      guarded(() => "converted", "response", GUARD_POINTER),
      "converted",
    );
  });

  test("rethrows a TransformError unchanged, so the leaf's own path survives", () => {
    const original = assertRejects(
      () => decodeDateTimeDate("not a timestamp", POINTER, PATH),
      "invalid-wire-value",
      "response",
      "leaf rejection",
    );
    let thrown: unknown;
    try {
      guarded(
        () => {
          throw original;
        },
        "response",
        GUARD_POINTER,
      );
    } catch (error) {
      thrown = error;
    }
    assert.equal(thrown, original, "the original error is rethrown by identity");
    assert.deepEqual(original.applicationPath, PATH, "its path is not overwritten");
  });

  test("converts a native container fault into a wire-value failure", () => {
    // The realistic trigger — a `null` body where an object is declared — is exercised end to end
    // in test-e2e/transform.test.ts. What this pins is the conversion itself: any non-TransformError
    // becomes a wire-value failure carrying the entry point's pointer and the native error as cause.
    let thrown: unknown;
    const fault = new TypeError("Cannot read properties of null (reading 'occurredAt')");
    try {
      guarded(
        () => {
          throw fault;
        },
        "response",
        GUARD_POINTER,
      );
    } catch (error) {
      thrown = error;
    }
    assert.ok(thrown instanceof TransformError);
    assert.equal(thrown.code, "invalid-wire-value");
    assert.equal(thrown.direction, "response");
    assert.deepEqual(thrown.sourcePointer, GUARD_POINTER);
    assert.equal(thrown.cause, fault, "the native error is preserved as the cause");
  });

  test("an encode-side fault is an application-value failure", () => {
    let thrown: unknown;
    try {
      guarded(
        () => {
          throw new RangeError("nope");
        },
        "request",
        GUARD_POINTER,
      );
    } catch (error) {
      thrown = error;
    }
    assert.ok(thrown instanceof TransformError);
    assert.equal(thrown.code, "invalid-application-value");
    assert.equal(thrown.direction, "request");
  });
});
