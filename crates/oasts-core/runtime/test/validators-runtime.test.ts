import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  appendKey,
  codePointLength,
  compareBigIntToNumber,
  deepEqual,
  hasGet,
  int64WireValue,
  isDate,
  isDateTime,
  isBigIntMultipleOf,
  isInt32,
  isMultipleOf,
  isTime,
  isUuid,
  issue,
  type Issue,
} from "../validators-runtime.ts";

describe("exact bigint constraints", () => {
  test("compares integers against binary64 rationals without coercion", () => {
    assert.equal(compareBigIntToNumber(42n, 42), 0);
    assert.equal(compareBigIntToNumber(9_007_199_254_740_993n, 9_007_199_254_740_992), 1);
    assert.equal(compareBigIntToNumber(1n, 1.5), -1);
  });

  test("evaluates integer and fractional divisors as exact rationals", () => {
    assert.equal(isBigIntMultipleOf(10n, 2), true);
    assert.equal(isBigIntMultipleOf(9_007_199_254_740_993n, 2), false);
    assert.equal(isBigIntMultipleOf(1n << 60n, 2 ** 60), true);
    assert.equal(isBigIntMultipleOf(1n, 0.5), true);
    assert.equal(isBigIntMultipleOf(1n, 0.1), false);
    assert.equal(isBigIntMultipleOf(1n, 0), false);
  });
});

describe("int64WireValue", () => {
  test("normalizes each lossless int64 wire representation", () => {
    assert.equal(int64WireValue(42), 42n);
    assert.equal(int64WireValue(12_345_678_901_234_567_890n), 12_345_678_901_234_567_890n);
    assert.equal(int64WireValue({ rawJSON: "12345678901234567890" }), 12_345_678_901_234_567_890n);
  });

  test("rejects rounded numbers and noncanonical raw tokens", () => {
    assert.equal(int64WireValue(Number.MAX_SAFE_INTEGER + 1), null);
    assert.equal(int64WireValue({ rawJSON: "01" }), null);
    assert.equal(int64WireValue({ rawJSON: "1.5" }), null);
    assert.equal(int64WireValue(null), null);
  });
});

describe("hasGet", () => {
  test("recognizes objects with a get method", () => {
    assert.equal(hasGet(new Headers()), true);
    assert.equal(hasGet({ get: () => null }), true);
  });

  test("rejects values without a get method", () => {
    assert.equal(hasGet(null), false);
    assert.equal(hasGet({}), false);
  });
});

describe("issue", () => {
  test("wraps a path and message into a plain object", () => {
    const path: readonly (string | number)[] = ["items", 0, "id"];
    const result: Issue = issue(path, "must be a string");

    assert.equal(result.message, "must be a string");
    assert.equal(result.path, path);
    assert.deepEqual(JSON.parse(JSON.stringify(result)), {
      message: "must be a string",
      path: ["items", 0, "id"],
    });
    assert.equal(Object.getPrototypeOf(result), Object.prototype);
  });
});

describe("appendKey", () => {
  test("returns a new array with the key appended", () => {
    const path: readonly (string | number)[] = ["a", 1];
    const extended = appendKey(path, "b");

    assert.deepEqual(extended, ["a", 1, "b"]);
    assert.notEqual(extended, path);
    assert.deepEqual(path, ["a", 1]);
    assert.equal(Object.getPrototypeOf(extended), Array.prototype);
  });

  test("accepts a numeric key and an empty parent", () => {
    assert.deepEqual(appendKey([], 3), [3]);
  });
});

describe("deepEqual", () => {
  test("compares primitives by ===", () => {
    assert.equal(deepEqual(1, 1), true);
    assert.equal(deepEqual(1, 2), false);
    assert.equal(deepEqual("x", "x"), true);
    assert.equal(deepEqual("x", "y"), false);
    assert.equal(deepEqual(true, true), true);
    assert.equal(deepEqual(true, false), false);
    assert.equal(deepEqual(null, null), true);
  });

  test("follows === for -0 and NaN", () => {
    assert.equal(deepEqual(0, -0), true);
    assert.equal(deepEqual(Number.NaN, Number.NaN), false);
  });

  test("treats mismatched primitive shapes as unequal", () => {
    assert.equal(deepEqual(1, "1"), false);
    assert.equal(deepEqual(true, 1), false);
    assert.equal(deepEqual(null, 0), false);
  });

  test("compares arrays ordered and pairwise", () => {
    assert.equal(deepEqual([1, 2, 3], [1, 2, 3]), true);
    assert.equal(deepEqual([1, 2, 3], [1, 3, 2]), false);
    assert.equal(deepEqual([1, 2], [1, 2, 3]), false);
    assert.equal(deepEqual([1], 1), false);
  });

  test("compares objects order-insensitively by own keys", () => {
    assert.equal(deepEqual({ a: 1, b: 2 }, { b: 2, a: 1 }), true);
    assert.equal(deepEqual({ a: 1 }, { a: 2 }), false);
    assert.equal(deepEqual({ a: 1 }, { b: 1 }), false);
    assert.equal(deepEqual({ a: 1 }, { a: 1, b: 2 }), false);
  });

  test("treats mismatched container shapes as unequal", () => {
    assert.equal(deepEqual({ a: 1 }, [1]), false);
    assert.equal(deepEqual([1], { a: 1 }), false);
    assert.equal(deepEqual({}, null), false);
    assert.equal(deepEqual({ a: 1 }, 1), false);
  });

  test("recurses through nested structures", () => {
    assert.equal(deepEqual({ a: [1, { b: 2 }], c: null }, { c: null, a: [1, { b: 2 }] }), true);
    assert.equal(deepEqual({ a: [1, { b: 2 }] }, { a: [1, { b: 3 }] }), false);
  });
});

describe("isMultipleOf", () => {
  test("holds the pinned exact-arithmetic anchors", () => {
    assert.equal(isMultipleOf(0.3, 0.1), false);
    assert.equal(isMultipleOf(0.75, 0.25), true);
    assert.equal(isMultipleOf(10, 5), true);
    assert.equal(isMultipleOf(1, 3), false);
    assert.equal(isMultipleOf(-2, 1), true);
  });

  test("handles zero and negative values by exact arithmetic", () => {
    assert.equal(isMultipleOf(0, 5), true);
    assert.equal(isMultipleOf(-0, 1), true);
    assert.equal(isMultipleOf(0.5, 1), false);
    assert.equal(isMultipleOf(5, 10), false);
    assert.equal(isMultipleOf(0.3, 0.3), true);
  });

  test("covers subnormal magnitudes", () => {
    assert.equal(isMultipleOf(Number.MIN_VALUE * 2, Number.MIN_VALUE), true);
    assert.equal(isMultipleOf(Number.MIN_VALUE, Number.MIN_VALUE * 2), false);
    assert.equal(isMultipleOf(-Number.MIN_VALUE, Number.MIN_VALUE), true);
  });

  test("covers large-magnitude values", () => {
    assert.equal(isMultipleOf(2 ** 1000, 2), true);
    assert.equal(isMultipleOf(2 ** 1000, 2 ** 971), true);
    assert.equal(isMultipleOf(2 ** 971, 2 ** 1000), false);
  });
});

describe("codePointLength", () => {
  test("counts Unicode code points, not UTF-16 units", () => {
    assert.equal(codePointLength(""), 0);
    assert.equal(codePointLength("abc"), 3);
    assert.equal(codePointLength("𝒳"), 1);
    assert.equal(codePointLength("a𝒳b"), 3);
    assert.equal(codePointLength("café"), 4);
  });
});

describe("isDateTime", () => {
  test("accepts RFC 3339 date-times", () => {
    assert.equal(isDateTime("2026-07-21T12:30:45Z"), true);
    assert.equal(isDateTime("2026-07-21t12:30:45z"), true);
    assert.equal(isDateTime("2026-07-21T12:30:45.123456+05:30"), true);
    assert.equal(isDateTime("2024-02-29T23:59:60.5Z"), true);
    assert.equal(isDateTime("2026-07-21T00:00:00-00:00"), true);
  });

  test("rejects malformed or out-of-range date-times", () => {
    assert.equal(isDateTime("not-a-datetime"), false);
    assert.equal(isDateTime("2026-13-01T12:00:00Z"), false);
    assert.equal(isDateTime("2026-07-21T25:00:00Z"), false);
    assert.equal(isDateTime("2026-07-21T12:00:00+30:00"), false);
    assert.equal(isDateTime("2026-07-21 12:00:00Z"), false);
  });
});

describe("isDate", () => {
  test("accepts real calendar dates", () => {
    assert.equal(isDate("2026-07-21"), true);
    assert.equal(isDate("2024-02-29"), true);
    assert.equal(isDate("2000-02-29"), true);
    assert.equal(isDate("2026-04-30"), true);
  });

  test("rejects impossible dates", () => {
    assert.equal(isDate("2023-02-29"), false);
    assert.equal(isDate("1900-02-29"), false);
    assert.equal(isDate("2026-02-30"), false);
    assert.equal(isDate("2026-04-31"), false);
    assert.equal(isDate("2026-13-01"), false);
    assert.equal(isDate("2026-00-10"), false);
    assert.equal(isDate("2026-01-00"), false);
    assert.equal(isDate("2026-01-32"), false);
    assert.equal(isDate("21-07-2026"), false);
  });

  test("accepts the last day of a leap February", () => {
    assert.equal(isDate("2023-02-28"), true);
  });
});

describe("isTime", () => {
  test("accepts full-time with a required offset", () => {
    assert.equal(isTime("12:30:45Z"), true);
    assert.equal(isTime("12:30:45z"), true);
    assert.equal(isTime("12:30:45.999+05:30"), true);
    assert.equal(isTime("23:59:60Z"), true);
    assert.equal(isTime("00:00:00-00:00"), true);
  });

  test("rejects missing offsets and out-of-range fields", () => {
    assert.equal(isTime("12:30:45"), false);
    assert.equal(isTime("12:30:45.5"), false);
    assert.equal(isTime("25:00:00Z"), false);
    assert.equal(isTime("12:60:00Z"), false);
    assert.equal(isTime("12:00:61Z"), false);
    assert.equal(isTime("12:00:00+24:00"), false);
    assert.equal(isTime("12:00:00+05:60"), false);
    assert.equal(isTime("noon"), false);
  });
});

describe("isUuid", () => {
  test("accepts 8-4-4-4-12 hex groups of any version, case-insensitive", () => {
    assert.equal(isUuid("f47ac10b-58cc-4372-a567-0e02b2c3d479"), true);
    assert.equal(isUuid("F47AC10B-58CC-4372-A567-0E02B2C3D479"), true);
    assert.equal(isUuid("f47AC10b-58cc-8372-A567-0e02b2c3d479"), true);
    assert.equal(isUuid("00000000-0000-0000-0000-000000000000"), true);
  });

  test("rejects anything but the bare hyphenated form", () => {
    assert.equal(isUuid("f47ac10b58cc4372a5670e02b2c3d479"), false);
    assert.equal(isUuid("f47ac10b-58cc-4372-a567-0e02b2c3d47"), false);
    assert.equal(isUuid("g47ac10b-58cc-4372-a567-0e02b2c3d479"), false);
    assert.equal(isUuid("urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479"), false);
    assert.equal(isUuid("{f47ac10b-58cc-4372-a567-0e02b2c3d479}"), false);
    assert.equal(isUuid(""), false);
  });
});

describe("isInt32", () => {
  test("accepts integers inside the signed 32-bit range", () => {
    assert.equal(isInt32(0), true);
    assert.equal(isInt32(2147483647), true);
    assert.equal(isInt32(-2147483648), true);
  });

  test("rejects non-integers and out-of-range values", () => {
    assert.equal(isInt32(1.5), false);
    assert.equal(isInt32(Number.NaN), false);
    assert.equal(isInt32(2147483648), false);
    assert.equal(isInt32(-2147483649), false);
  });
});
