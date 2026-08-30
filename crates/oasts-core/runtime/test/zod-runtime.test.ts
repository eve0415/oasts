import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { z } from "zod";

import {
  pattern,
  patternProperties,
  bigintMaximum,
  bigintMinimum,
  bigintMultipleOf,
  codePointLength,
  collect,
  compareBigIntToNumber,
  conditional,
  constValue,
  contains,
  deepEqual,
  dependentRequired,
  dependentSchemas,
  headers,
  int32,
  int64Wire,
  int64WireValue,
  integer,
  isBigIntMultipleOf,
  isDate,
  isDateTime,
  isDuration,
  isEmail,
  isHostname,
  isInt32,
  isIpv4,
  isIpv6,
  isMultipleOf,
  type Issue,
  isTime,
  isUri,
  isUriReference,
  isUuid,
  type ItemScope,
  maxLength,
  minLength,
  multipleOf,
  not,
  enumValues,
  oneOf,
  type PropertyScope,
  propertyCount,
  propertyNames,
  stringFormat,
  unevaluatedItems,
  unevaluatedProperties,
  uniqueItems,
} from "../zod-runtime.ts";

function issues<T>(result: z.ZodSafeParseResult<T>): readonly z.core.$ZodIssue[] {
  assert.equal(result.success, false);
  if (result.success) {
    assert.fail("expected parsing to fail");
  }
  return result.error.issues;
}

describe("deepEqual", () => {
  test("compares primitives by ===", () => {
    assert.equal(deepEqual(1, 1), true);
    assert.equal(deepEqual(1, 2), false);
    assert.equal(deepEqual("x", "x"), true);
    assert.equal(deepEqual("x", "y"), false);
    assert.equal(deepEqual(true, true), true);
    assert.equal(deepEqual(true, false), false);
    assert.equal(deepEqual(null, null), true);
    assert.equal(deepEqual(0, -0), true);
    assert.equal(deepEqual(Number.NaN, Number.NaN), false);
  });

  test("compares arrays ordered and pairwise", () => {
    assert.equal(deepEqual([1, 2], [1, 2]), true);
    assert.equal(deepEqual([1, 2], [2, 1]), false);
    assert.equal(deepEqual([1], [1, 2]), false);
    assert.equal(deepEqual([1], 1), false);
  });

  test("compares objects order-insensitively by own keys", () => {
    assert.equal(deepEqual({ a: 1, b: 2 }, { b: 2, a: 1 }), true);
    assert.equal(deepEqual({ a: 1 }, { a: 2 }), false);
    assert.equal(deepEqual({ a: 1 }, { b: 1 }), false);
    assert.equal(deepEqual({ a: 1 }, { a: 1, b: 2 }), false);
    assert.equal(deepEqual({ a: [1, { b: 2 }] }, { a: [1, { b: 2 }] }), true);
    assert.equal(deepEqual({ a: 1 }, [1]), false);
    assert.equal(deepEqual({}, null), false);
  });
});

describe("isMultipleOf", () => {
  test("uses exact IEEE-754 arithmetic", () => {
    assert.equal(isMultipleOf(0.3, 0.1), false);
    assert.equal(isMultipleOf(0.75, 0.25), true);
    assert.equal(isMultipleOf(10, 5), true);
    assert.equal(isMultipleOf(1, 3), false);
    assert.equal(isMultipleOf(-2, 1), true);
  });

  test("handles zero, subnormal, and large magnitudes", () => {
    assert.equal(isMultipleOf(0, 5), true);
    assert.equal(isMultipleOf(-0, 1), true);
    assert.equal(isMultipleOf(Number.MIN_VALUE * 2, Number.MIN_VALUE), true);
    assert.equal(isMultipleOf(Number.MIN_VALUE, Number.MIN_VALUE * 2), false);
    assert.equal(isMultipleOf(-Number.MIN_VALUE, Number.MIN_VALUE), true);
    assert.equal(isMultipleOf(2 ** 1000, 2 ** 971), true);
    assert.equal(isMultipleOf(2 ** 971, 2 ** 1000), false);
  });
});

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

  test("reports inclusive and exclusive bounds without narrowing to number", () => {
    const minimum = z.custom<bigint>().check(bigintMinimum(10, false));
    const exclusiveMinimum = z.custom<bigint>().check(bigintMinimum(10, true));
    const maximum = z.custom<bigint>().check(bigintMaximum(20, false));
    const exclusiveMaximum = z.custom<bigint>().check(bigintMaximum(20, true));

    assert.equal(minimum.safeParse(9n).success, false);
    assert.equal(minimum.safeParse(10n).success, true);
    assert.equal(exclusiveMinimum.safeParse(10n).success, false);
    assert.equal(exclusiveMinimum.safeParse(11n).success, true);
    assert.equal(maximum.safeParse(21n).success, false);
    assert.equal(maximum.safeParse(20n).success, true);
    assert.equal(exclusiveMaximum.safeParse(20n).success, false);
    assert.equal(exclusiveMaximum.safeParse(19n).success, true);
  });
});

describe("codePointLength", () => {
  test("counts Unicode code points instead of UTF-16 code units", () => {
    assert.equal(codePointLength(""), 0);
    assert.equal(codePointLength("abc"), 3);
    assert.equal(codePointLength("\u{1f600}"), 1);
    assert.equal(codePointLength("a\u{1f600}b"), 3);
  });
});

describe("isDateTime", () => {
  test("accepts RFC 3339 offsets, lowercase separators, and leap seconds", () => {
    assert.equal(isDateTime("2026-07-21T12:30:45Z"), true);
    assert.equal(isDateTime("2026-07-21t12:30:45z"), true);
    assert.equal(isDateTime("2026-07-21T12:30:45.123+05:30"), true);
    assert.equal(isDateTime("2024-02-29T23:59:60Z"), true);
  });

  test("rejects missing offsets and invalid calendar or time fields", () => {
    assert.equal(isDateTime("2026-07-21T12:30:45"), false);
    assert.equal(isDateTime("2021-02-29T12:30:45Z"), false);
    assert.equal(isDateTime("2026-07-21T24:00:00Z"), false);
    assert.equal(isDateTime("2026-07-21T12:60:00Z"), false);
    assert.equal(isDateTime("2026-07-21T12:00:61Z"), false);
    assert.equal(isDateTime("2026-07-21T12:00:00+24:00"), false);
    assert.equal(isDateTime("2026-07-21T12:00:00+05:60"), false);
  });
});

describe("isDate", () => {
  test("accepts real calendar dates including leap days", () => {
    assert.equal(isDate("2026-07-21"), true);
    assert.equal(isDate("2024-02-29"), true);
    assert.equal(isDate("2000-02-29"), true);
    assert.equal(isDate("2023-02-28"), true);
  });

  test("rejects malformed and impossible dates", () => {
    assert.equal(isDate("2023-02-29"), false);
    assert.equal(isDate("1900-02-29"), false);
    assert.equal(isDate("2026-00-10"), false);
    assert.equal(isDate("2026-13-01"), false);
    assert.equal(isDate("2026-01-00"), false);
    assert.equal(isDate("2026-01-32"), false);
    assert.equal(isDate("21-07-2026"), false);
  });
});

describe("isTime", () => {
  test("accepts full times with valid offsets", () => {
    assert.equal(isTime("12:30:45Z"), true);
    assert.equal(isTime("12:30:45z"), true);
    assert.equal(isTime("12:30:45.999+05:30"), true);
    assert.equal(isTime("23:59:60-00:00"), true);
  });

  test("rejects malformed and out-of-range times", () => {
    assert.equal(isTime("12:30:45"), false);
    assert.equal(isTime("25:00:00Z"), false);
    assert.equal(isTime("12:60:00Z"), false);
    assert.equal(isTime("12:00:61Z"), false);
    assert.equal(isTime("12:00:00+24:00"), false);
    assert.equal(isTime("12:00:00+05:60"), false);
  });
});

describe("isUuid", () => {
  test("accepts only bare 8-4-4-4-12 hexadecimal groups", () => {
    assert.equal(isUuid("f47ac10b-58cc-4372-a567-0e02b2c3d479"), true);
    assert.equal(isUuid("F47AC10B-58CC-4372-A567-0E02B2C3D479"), true);
    assert.equal(isUuid("f47ac10b58cc4372a5670e02b2c3d479"), false);
    assert.equal(isUuid("urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479"), false);
  });
});

describe("isInt32", () => {
  test("recognizes integers in the signed 32-bit range", () => {
    assert.equal(isInt32(0), true);
    assert.equal(isInt32(2147483647), true);
    assert.equal(isInt32(-2147483648), true);
    assert.equal(isInt32(1.5), false);
    assert.equal(isInt32(2147483648), false);
    assert.equal(isInt32(-2147483649), false);
  });
});

describe("int64WireValue", () => {
  test("normalizes each lossless wire representation", () => {
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

describe("scalar checks", () => {
  test("integer accepts every finite whole number", () => {
    const schema = z.number().check(integer());

    assert.equal(schema.safeParse(1e300).success, true);
    assert.equal(schema.safeParse(2 ** 53).success, true);
    assert.equal(z.number().int().safeParse(1e300).success, false);
    assert.equal(
      z
        .number()
        .int()
        .safeParse(2 ** 53).success,
      false,
    );
    assert.equal(schema.safeParse(1.5).success, false);
  });

  test("minLength and maxLength count code points", () => {
    const minimum = z.string().check(minLength(2));
    const maximum = z.string().check(maxLength(1));

    assert.equal(minimum.safeParse("ab").success, true);
    assert.equal(minimum.safeParse("a").success, false);
    assert.equal(maximum.safeParse("\u{1f600}").success, true);
    assert.equal(z.string().max(1).safeParse("\u{1f600}").success, false);
    assert.equal(maximum.safeParse("ab").success, false);
  });

  test("pattern reports non-matches", () => {
    const schema = z.string().check(pattern(/^[a-z]+$/u));

    assert.equal(schema.safeParse("abc").success, true);
    assert.equal(schema.safeParse("123").success, false);
  });

  test("multipleOf preserves exact arithmetic", () => {
    const schema = z.number().check(multipleOf(0.1));

    assert.equal(schema.safeParse(0.3).success, false);
    assert.equal(schema.safeParse(0.2).success, true);
    assert.equal(z.number().multipleOf(0.1).safeParse(0.3).success, true);
  });

  test("stringFormat reports the supplied format name", () => {
    const schema = z.string().check(stringFormat((value) => value === "valid", "example"));

    assert.equal(schema.safeParse("valid").success, true);
    assert.equal(issues(schema.safeParse("invalid"))[0]?.message, "invalid example format");
  });

  test("int32 reports values outside its domain", () => {
    const schema = z.number().check(int32());

    assert.equal(schema.safeParse(2147483647).success, true);
    assert.equal(schema.safeParse(2147483648).success, false);
  });

  test("int64Wire accepts every exact wire shape and rejects the rest", () => {
    const schema = z.unknown().check(int64Wire());

    assert.equal(schema.safeParse(42).success, true);
    assert.equal(schema.safeParse(-(2n ** 63n)).success, true);
    assert.equal(schema.safeParse(-(2n ** 63n) - 1n).success, false);
    assert.equal(schema.safeParse(2n ** 63n).success, false);
    assert.equal(schema.safeParse(9_007_199_254_740_993n).success, true);
    assert.equal(schema.safeParse({ rawJSON: "9007199254740993" }).success, true);
    assert.equal(
      issues(schema.safeParse({ rawJSON: "12345678901234567890" }))[0]?.message,
      "out of int64 range",
    );
    assert.equal(
      issues(schema.safeParse(Number.MAX_SAFE_INTEGER + 1))[0]?.message,
      "expected type integer",
    );
  });

  test("constrained int64Wire relays the numeric schema verdict", () => {
    const schema = z
      .unknown()
      .check(
        int64Wire(
          z.custom<bigint>().check(bigintMinimum(10, false)).check(bigintMaximum(20, false)),
        ),
      );

    assert.equal(schema.safeParse(10n).success, true);
    assert.equal(schema.safeParse({ rawJSON: "20" }).success, true);
    assert.equal(schema.safeParse(9n).success, false);
    assert.equal(schema.safeParse({ rawJSON: "21" }).success, false);
  });

  test("int64Wire evaluates multipleOf before binary64 can round the value", () => {
    const schema = z.unknown().check(int64Wire(z.custom<bigint>().check(bigintMultipleOf(2))));

    assert.equal(schema.safeParse(9_007_199_254_740_992n).success, true);
    assert.equal(schema.safeParse(9_007_199_254_740_993n).success, false);
  });

  test("enumValues and constValue use deep JSON equality", () => {
    const enumSchema = z.unknown().check(enumValues([{ a: 1, b: 2 }, [1, 2]]));
    const constSchema = z.unknown().check(constValue({ a: 1, b: 2 }));

    assert.equal(enumSchema.safeParse({ b: 2, a: 1 }).success, true);
    assert.equal(enumSchema.safeParse([2, 1]).success, false);
    assert.equal(constSchema.safeParse({ b: 2, a: 1 }).success, true);
    assert.equal(constSchema.safeParse({ a: 2, b: 1 }).success, false);
  });

  test("continues after an issue and rebases paths under the checked node", () => {
    const schema = z.object({
      value: z.string().check(minLength(2)).check(pattern(/^z/u)),
    });
    const resultIssues = issues(schema.safeParse({ value: "a" }));

    assert.equal(resultIssues.length, 2);
    assert.deepEqual(
      resultIssues.map((issue) => issue.path),
      [["value"], ["value"]],
    );
  });
});

describe("array checks", () => {
  test("uniqueItems compares values deeply", () => {
    const schema = z.array(z.unknown()).check(uniqueItems());

    assert.equal(schema.safeParse([]).success, true);
    assert.equal(schema.safeParse([{ a: 1 }, { a: 2 }]).success, true);
    assert.equal(
      schema.safeParse([
        { a: 1, b: 2 },
        { b: 2, a: 1 },
      ]).success,
      false,
    );
  });

  test("contains covers every min and max presence combination", () => {
    const item = z.literal("hit");
    const unboundedImplicit = z
      .array(z.unknown())
      .check(contains(item, undefined, undefined, false));
    const unboundedExplicit = z
      .array(z.unknown())
      .check(contains(item, undefined, undefined, true));
    const minimumImplicit = z.array(z.unknown()).check(contains(item, 1, undefined, false));
    const minimumExplicit = z.array(z.unknown()).check(contains(item, 2, undefined, true));
    const maximumImplicit = z.array(z.unknown()).check(contains(item, undefined, 1, false));
    const maximumExplicit = z.array(z.unknown()).check(contains(item, undefined, 1, true));
    const boundedImplicit = z.array(z.unknown()).check(contains(item, 1, 1, false));
    const boundedExplicit = z.array(z.unknown()).check(contains(item, 1, 1, true));

    assert.equal(unboundedImplicit.safeParse([]).success, true);
    assert.equal(unboundedExplicit.safeParse(["miss"]).success, true);
    assert.equal(
      issues(minimumImplicit.safeParse([]))[0]?.message,
      "no array item matches contains schema",
    );
    assert.equal(
      issues(minimumExplicit.safeParse(["hit"]))[0]?.message,
      "fewer matching items than minContains 2",
    );
    assert.equal(maximumImplicit.safeParse(["hit", "miss"]).success, true);
    assert.equal(maximumExplicit.safeParse(["hit", "hit"]).success, false);
    assert.equal(boundedImplicit.safeParse(["miss"]).success, false);
    assert.equal(boundedImplicit.safeParse(["hit", "hit"]).success, false);
    assert.equal(boundedExplicit.safeParse(["hit"]).success, true);
  });
});

describe("object checks", () => {
  test("propertyCount enforces optional minimum and maximum bounds", () => {
    const open = z.looseObject({}).check(propertyCount(undefined, undefined));
    const minimum = z.looseObject({}).check(propertyCount(2, undefined));
    const maximum = z.looseObject({}).check(propertyCount(undefined, 1));
    const bounded = z.looseObject({}).check(propertyCount(1, 2));

    assert.equal(open.safeParse({ a: 1 }).success, true);
    assert.equal(minimum.safeParse({ a: 1 }).success, false);
    assert.equal(minimum.safeParse({ a: 1, b: 2 }).success, true);
    assert.equal(maximum.safeParse({ a: 1, b: 2 }).success, false);
    assert.equal(bounded.safeParse({}).success, false);
    assert.equal(bounded.safeParse({ a: 1, b: 2, c: 3 }).success, false);
  });

  test("dependentRequired uses own-key presence", () => {
    const schema = z.looseObject({}).check(
      dependentRequired([
        ["creditCard", ["billingAddress", "securityCode"]],
        ["absent", ["ignored"]],
      ]),
    );

    assert.equal(schema.safeParse({}).success, true);
    assert.equal(
      schema.safeParse({ creditCard: true, billingAddress: undefined, securityCode: "123" })
        .success,
      true,
    );
    assert.equal(schema.safeParse({ creditCard: true }).success, false);
  });

  test("dependentSchemas relays only triggered schema issues", () => {
    const schema = z.looseObject({}).check(
      dependentSchemas([
        ["enabled", z.looseObject({ required: z.string() })],
        ["absent", z.never()],
      ]),
    );

    assert.equal(schema.safeParse({}).success, true);
    assert.equal(schema.safeParse({ enabled: true, required: "yes" }).success, true);
    assert.deepEqual(issues(schema.safeParse({ enabled: true }))[0]?.path, ["required"]);
  });

  test("propertyNames reports failures at each property key", () => {
    const schema = z.looseObject({}).check(propertyNames(z.string().check(pattern(/^[a-z]+$/u))));

    assert.equal(schema.safeParse({ valid: 1 }).success, true);
    assert.deepEqual(issues(schema.safeParse({ "not-valid": 1 }))[0]?.path, ["not-valid"]);
  });

  test("patternProperties validates matches and forbids additional properties", () => {
    const schema = z
      .looseObject({})
      .check(patternProperties([[/^x-/u, z.number()]], ["declared"], false));

    assert.equal(schema.safeParse({ declared: true, "x-count": 1 }).success, true);
    assert.deepEqual(issues(schema.safeParse({ "x-count": "one" }))[0]?.path, ["x-count"]);
    assert.deepEqual(issues(schema.safeParse({ extra: true }))[0]?.path, ["extra"]);
  });

  test("patternProperties validates additional properties with a schema", () => {
    const schema = z.looseObject({}).check(patternProperties([], [], z.boolean()));

    assert.equal(schema.safeParse({ allowed: true }).success, true);
    assert.deepEqual(issues(schema.safeParse({ rejected: 1 }))[0]?.path, ["rejected"]);
  });

  test("patternProperties permits additional properties when unspecified", () => {
    const schema = z.looseObject({}).check(patternProperties([], [], undefined));

    assert.equal(schema.safeParse({ anything: true }).success, true);
  });

  test("conditional selects only the applicable defined branch", () => {
    const condition = z.literal("if");
    const thenBranch = z.literal("then");
    const elseBranch = z.literal("else");
    const withBoth = z.unknown().check(conditional(condition, thenBranch, elseBranch));
    const withoutThen = z.unknown().check(conditional(condition, undefined, elseBranch));
    const withoutElse = z.unknown().check(conditional(condition, thenBranch, undefined));

    assert.equal(withBoth.safeParse("if").success, false);
    assert.equal(withBoth.safeParse("other").success, false);
    assert.equal(withoutThen.safeParse("if").success, true);
    assert.equal(withoutElse.safeParse("other").success, true);
  });

  test("not rejects only matching values", () => {
    const schema = z.unknown().check(not(z.literal("blocked")));

    assert.equal(schema.safeParse("allowed").success, true);
    assert.equal(schema.safeParse("blocked").success, false);
  });

  test("oneOf requires exactly one matching branch", () => {
    const schema = z
      .unknown()
      .check(oneOf([z.string(), z.literal("fixed"), z.number().check(integer())]));

    assert.equal(schema.safeParse(true).success, false);
    assert.equal(schema.safeParse(1).success, true);
    assert.equal(schema.safeParse("fixed").success, false);
  });
});

describe("unevaluatedProperties", () => {
  const scope: PropertyScope = {
    declared: ["tag", "flag", "declared"],
    patterns: [/^pattern/u],
    additional: false,
    allOf: [{ declared: ["allOf"] }],
    branches: [
      [z.looseObject({ tag: z.literal("match") }), { declared: ["matchingBranch"] }],
      [z.looseObject({ tag: z.literal("miss") }), { declared: ["nonMatchingBranch"] }],
    ],
    conditional: {
      condition: z.looseObject({ flag: z.literal(true) }),
      whenTrue: { declared: ["trueBranch"] },
      whenFalse: { declared: ["falseBranch"] },
    },
  };

  test("collects declared, pattern, allOf, matching branch, and true conditional keys", () => {
    const schema = z.looseObject({}).check(unevaluatedProperties(scope, false));
    const resultIssues = issues(
      schema.safeParse({
        tag: "match",
        flag: true,
        declared: 1,
        patternKey: 1,
        allOf: 1,
        matchingBranch: 1,
        nonMatchingBranch: 1,
        trueBranch: 1,
        falseBranch: 1,
        leftover: 1,
      }),
    );

    assert.deepEqual(
      resultIssues.map((issue) => issue.path),
      [["nonMatchingBranch"], ["falseBranch"], ["leftover"]],
    );
  });

  test("collects keys from the false conditional direction", () => {
    const schema = z.looseObject({}).check(unevaluatedProperties(scope, false));

    assert.equal(
      schema.safeParse({ tag: "match", flag: false, matchingBranch: 1, falseBranch: 1 }).success,
      true,
    );
  });

  test("additional true evaluates every property", () => {
    const schema = z.looseObject({}).check(unevaluatedProperties({ additional: true }, false));

    assert.equal(schema.safeParse({ arbitrary: 1 }).success, true);
  });

  test("validates unevaluated properties with the allowed schema", () => {
    const schema = z
      .looseObject({})
      .check(unevaluatedProperties({ declared: ["known"] }, z.string().min(2)));
    const resultIssues = issues(schema.safeParse({ known: true, valid: "ok", invalid: "x" }));

    assert.deepEqual(
      resultIssues.map((issue) => issue.path),
      [["invalid"]],
    );
  });

  test("handles conditional scopes without a selected nested scope", () => {
    const trueSchema = z.looseObject({}).check(
      unevaluatedProperties(
        {
          conditional: {
            condition: z.looseObject({ value: z.literal(true) }),
            whenFalse: { additional: true },
          },
        },
        false,
      ),
    );
    const falseSchema = z.looseObject({}).check(
      unevaluatedProperties(
        {
          conditional: {
            condition: z.looseObject({ value: z.literal(true) }),
            whenTrue: { additional: true },
          },
        },
        false,
      ),
    );

    assert.equal(trueSchema.safeParse({ value: true }).success, false);
    assert.equal(falseSchema.safeParse({ value: false }).success, false);
  });
});

describe("unevaluatedItems", () => {
  test("collects prefix and contains indexes and reports relative item paths", () => {
    const scope: ItemScope = { prefixCount: 1, contains: [z.literal("hit")] };
    const schema = z.array(z.unknown()).check(unevaluatedItems(scope, false));

    assert.deepEqual(issues(schema.safeParse(["prefix", "hit", "leftover"]))[0]?.path, [2]);
  });

  test("itemsCovers evaluates every index", () => {
    const scope: ItemScope = { prefixCount: 10, itemsCovers: true, contains: [] };
    const schema = z.array(z.unknown()).check(unevaluatedItems(scope, false));

    assert.equal(schema.safeParse([1, 2]).success, true);
  });

  test("validates unevaluated indexes with the allowed schema", () => {
    const schema = z.array(z.unknown()).check(unevaluatedItems({}, z.string().min(2)));
    const resultIssues = issues(schema.safeParse(["ok", "x"]));

    assert.deepEqual(
      resultIssues.map((issue) => issue.path),
      [[1]],
    );
  });
});

describe("collect", () => {
  test("reports nothing for a passing value", () => {
    const found: Issue[] = [];
    collect(z.string(), "ok", [], found);

    assert.deepEqual(found, []);
  });

  test("prefixes the base path onto each issue", () => {
    const found: Issue[] = [];
    collect(z.looseObject({ a: z.string() }), { a: 1 }, ["body"], found);

    assert.equal(found.length, 1);
    assert.deepEqual(found[0]?.path, ["body", "a"]);
    assert.equal(typeof found[0]?.message, "string");
  });

  test("keeps a symbol path segment total rather than dropping it", () => {
    // Zod types a path segment as PropertyKey. Decoded wire values are JSON and carry no symbol
    // keys, but a check is free to push one, and the path must stay reportable when it does.
    const marker = Symbol("marker");
    const schema = z.unknown().check((ctx) => {
      ctx.issues.push({
        code: "custom",
        message: "sym",
        input: ctx.value,
        path: [marker],
        continue: true,
      });
    });
    const found: Issue[] = [];
    collect(schema, "x", ["base"], found);

    assert.deepEqual(found[0]?.path, ["base", "Symbol(marker)"]);
  });

  test("reports every issue a schema finds", () => {
    const found: Issue[] = [];
    collect(z.looseObject({ a: z.string(), b: z.string() }), { a: 1, b: 2 }, [], found);

    assert.deepEqual(
      found.map((issue) => issue.path),
      [["a"], ["b"]],
    );
  });
});

describe("headers", () => {
  const schema = z.custom<unknown>().check(
    headers([
      { name: "X-Opaque", required: true },
      // An optional opaque header carries neither a presence check nor a schema, so it is skipped
      // outright — the one header shape that contributes nothing at all.
      { name: "X-Opaque-Optional", required: false },
      { name: "X-Schema", required: false, schema: z.string().min(3) },
      { name: "X-Json", required: false, schema: z.looseObject({ n: z.number() }), json: true },
    ]),
  );

  test("rejects a value that is not a Headers object", () => {
    // The last two are the near-misses: a `get` that is not callable, which the guard must catch
    // before it calls it.
    for (const value of [null, undefined, 42, { "X-Opaque": "x" }, { get: "not-a-function" }]) {
      const result = schema.safeParse(value);
      assert.equal(result.success, false, `expected ${JSON.stringify(value)} to be rejected`);
    }
  });

  test("ignores a Headers-like get that yields a non-string", () => {
    // `Headers.get` yields a string or null, but the object is a public seam, so a value that is
    // neither is skipped rather than handed to JSON.parse or a schema.
    const exotic = { get: (): unknown => 42 };
    const result = schema.safeParse(exotic);

    assert.equal(result.success, true);
  });

  test("accepts a Headers object satisfying every declared header", () => {
    const value = new Headers({
      "X-Opaque": "anything",
      "X-Schema": "long-enough",
      "X-Json": JSON.stringify({ n: 1 }),
    });
    const result = schema.safeParse(value);

    assert.equal(result.success, true);
    // Assert-only: the Headers object itself comes back, not a reconstruction.
    assert.equal(result.success && result.data === value, true);
  });

  test("reports a missing required header at the object path", () => {
    const resultIssues = issues(schema.safeParse(new Headers({})));

    assert.equal(resultIssues.length, 1);
    assert.deepEqual(resultIssues[0]?.path, []);
    assert.match(resultIssues[0]?.message ?? "", /missing required header X-Opaque/u);
  });

  test("checks a schema-style header against its wire string", () => {
    const resultIssues = issues(
      schema.safeParse(new Headers({ "X-Opaque": "x", "X-Schema": "ab" })),
    );

    assert.deepEqual(
      resultIssues.map((issue) => issue.path),
      [["X-Schema"]],
    );
  });

  test("reports unparseable JSON on a content header", () => {
    const resultIssues = issues(
      schema.safeParse(new Headers({ "X-Opaque": "x", "X-Json": "{not json" })),
    );

    assert.deepEqual(
      resultIssues.map((issue) => issue.path),
      [["X-Json"]],
    );
    assert.match(resultIssues[0]?.message ?? "", /not valid JSON/u);
  });

  test("checks the decoded value of a content header", () => {
    const resultIssues = issues(
      schema.safeParse(new Headers({ "X-Opaque": "x", "X-Json": JSON.stringify({ n: "no" }) })),
    );

    assert.deepEqual(
      resultIssues.map((issue) => issue.path),
      [["X-Json", "n"]],
    );
  });

  test("skips an absent optional header entirely", () => {
    assert.equal(schema.safeParse(new Headers({ "X-Opaque": "x" })).success, true);
  });

  test("an optional opaque header is never checked, present or not", () => {
    assert.equal(
      schema.safeParse(new Headers({ "X-Opaque": "x", "X-Opaque-Optional": "" })).success,
      true,
    );
  });
});

describe("isIpv4", () => {
  test("accepts four decimal octets in range", () => {
    assert.equal(isIpv4("0.0.0.0"), true);
    assert.equal(isIpv4("255.255.255.255"), true);
    assert.equal(isIpv4("10.20.30.40"), true);
    assert.equal(isIpv4("200.0.0.0"), true);
  });

  test("rejects wrong component counts, leading zeros and out-of-range octets", () => {
    assert.equal(isIpv4("127.0.0"), false);
    assert.equal(isIpv4("127.0.0.0.1"), false);
    assert.equal(isIpv4("256.0.0.1"), false);
    assert.equal(isIpv4("192.168.0.256"), false);
    assert.equal(isIpv4("01.2.3.4"), false);
    assert.equal(isIpv4("192.168.a.1"), false);
    assert.equal(isIpv4("+1.2.3.4"), false);
    assert.equal(isIpv4("192.168..1"), false);
    assert.equal(isIpv4("1২7.0.0.1"), false);
    assert.equal(isIpv4(""), false);
  });
});

describe("isIpv6", () => {
  test("accepts the full, elided and IPv4-tailed forms", () => {
    assert.equal(isIpv6("1:2:3:4:5:6:7:8"), true);
    assert.equal(isIpv6("2001:0db8:0000:0000:0000:0000:0000:0001"), true);
    assert.equal(isIpv6("2001:DB8::1"), true);
    assert.equal(isIpv6("::"), true);
    assert.equal(isIpv6("::1"), true);
    assert.equal(isIpv6("d6::"), true);
    assert.equal(isIpv6("1:d6::42"), true);
    assert.equal(isIpv6("::ffff:192.168.0.1"), true);
    assert.equal(isIpv6("1000:1000:1000:1000:1000:1000:255.255.255.255"), true);
  });

  test("rejects malformed groups, repeated elisions and stray suffixes", () => {
    assert.equal(isIpv6("1:2:3:4:5:6:7"), false);
    assert.equal(isIpv6("1:1:1:1:1:1:1:1:1"), false);
    assert.equal(isIpv6("1:2:3:4:5:6:7:8::"), false);
    assert.equal(isIpv6("12345::"), false);
    assert.equal(isIpv6("::abcef"), false);
    assert.equal(isIpv6("::laptop"), false);
    assert.equal(isIpv6("1::d6::42"), false);
    assert.equal(isIpv6("1:2:3:4:5:::8"), false);
    assert.equal(isIpv6(":2:3:4:5:6:7:8"), false);
    assert.equal(isIpv6("1:2:3:4:5:6:7:"), false);
    assert.equal(isIpv6("1:2:3:4:1.2.3"), false);
    assert.equal(isIpv6("::ffff:192.168.0.01"), false);
    assert.equal(isIpv6("fe80::a%eth1"), false);
    assert.equal(isIpv6("[::1]"), false);
    assert.equal(isIpv6("127.0.0.1"), false);
    assert.equal(isIpv6("1"), false);
  });

  test("accepts a dotted-quad only as the low-order tail", () => {
    assert.equal(isIpv6("1:2:3:4:5:6:1.2.3.4"), true);
    assert.equal(isIpv6("::1.2.3.4"), true);
    assert.equal(isIpv6("1:2::192.168.0.1"), true);
    assert.equal(isIpv6("1.2.3.4::1"), false);
    assert.equal(isIpv6("1.2.3.4::"), false);
    assert.equal(isIpv6("1.2.3.4::2:3"), false);
    assert.equal(isIpv6("1.2.3.4::5.6.7.8"), false);
    assert.equal(isIpv6("1:2:3:4:5:6:7:1.2.3.4"), false);
  });
});

describe("isHostname", () => {
  test("accepts RFC 1123 label sequences", () => {
    assert.equal(isHostname("www.example.com"), true);
    assert.equal(isHostname("hostname"), true);
    assert.equal(isHostname("1host"), true);
    assert.equal(isHostname("host-name"), true);
    assert.equal(isHostname("a--b.com"), true);
    assert.equal(isHostname(`${"a".repeat(63)}.com`), true);
  });

  test("rejects empty, over-long, hyphen-edged and non-ASCII labels", () => {
    assert.equal(isHostname(""), false);
    assert.equal(isHostname("."), false);
    assert.equal(isHostname(".example"), false);
    assert.equal(isHostname("example."), false);
    assert.equal(isHostname("-hostname"), false);
    assert.equal(isHostname("hostname-"), false);
    assert.equal(isHostname("host_name"), false);
    assert.equal(isHostname("example．com"), false);
    assert.equal(isHostname(`${"a".repeat(64)}.com`), false);
    assert.equal(isHostname(`${`${"a".repeat(63)}.`.repeat(4)}com`), false);
  });
});

describe("isEmail", () => {
  test("accepts dot-atom and quoted local parts", () => {
    assert.equal(isEmail("joe.bloggs@example.com"), true);
    assert.equal(isEmail("te~st@example.com"), true);
    assert.equal(isEmail("test@io"), true);
    assert.equal(isEmail("test@123.com"), true);
    assert.equal(isEmail('"joe bloggs"@example.com'), true);
    assert.equal(isEmail('"joe@bloggs"@example.com'), true);
    assert.equal(isEmail('""@iana.org'), true);
    assert.equal(isEmail('"\\""@iana.org'), true);
  });

  test("accepts bracketed address literals after the at-sign", () => {
    assert.equal(isEmail("joe.bloggs@[127.0.0.1]"), true);
    assert.equal(isEmail("joe.bloggs@[IPv6:::1]"), true);
    assert.equal(isEmail("a@[ipv6:::1]"), true);
  });

  test("rejects malformed local parts, domains and literals", () => {
    assert.equal(isEmail("2962"), false);
    assert.equal(isEmail("@example.com"), false);
    assert.equal(isEmail("joe.bloggs@"), false);
    assert.equal(isEmail(".test@example.com"), false);
    assert.equal(isEmail("te..st@example.com"), false);
    assert.equal(isEmail("joe bloggs@example.com"), false);
    assert.equal(isEmail('"test"test@iana.org'), false);
    assert.equal(isEmail("a@b@c.org"), false);
    assert.equal(isEmail("aé@iana.org"), false);
    assert.equal(isEmail("test@-iana.org"), false);
    assert.equal(isEmail("test@[1.2.3.4"), false);
    assert.equal(isEmail("a@[1.2.3]"), false);
    assert.equal(isEmail("test@[RFC-5322-domain-literal]"), false);
    assert.equal(isEmail("joe.bloggs@[127.0.0.300]"), false);
    assert.equal(isEmail(""), false);
  });
});

describe("isUri", () => {
  test("accepts absolute URIs with and without an authority", () => {
    assert.equal(isUri("http://foo.bar/?baz=qux#quux"), true);
    assert.equal(isUri("http://foo.com/blah_(wikipedia)_blah#cite-1"), true);
    assert.equal(isUri("http://foo.bar/?q=Test%20URL-encoded%20stuff"), true);
    assert.equal(isUri("http://-.~_!$&'()*+,;=:%40:80%2f::::::@example.com"), true);
    assert.equal(isUri("ldap://[2001:db8::7]/c=GB?objectClass?one"), true);
    assert.equal(isUri("mailto:John.Doe@example.com"), true);
    assert.equal(isUri("tel:+1-816-555-1212"), true);
    assert.equal(isUri("urn:oasis:names:specification:docbook:dtd:xml:4.1.2"), true);
    assert.equal(isUri("http://999.999.999.999/"), true);
  });

  test("rejects relative references, bad schemes, hosts and escapes", () => {
    assert.equal(isUri("//foo.bar/?baz=qux#quux"), false);
    assert.equal(isUri("/abc"), false);
    assert.equal(isUri("abc"), false);
    assert.equal(isUri("1http://example.com"), false);
    assert.equal(isUri("ht_tp://example.com"), false);
    assert.equal(isUri("bar,baz:foo"), false);
    assert.equal(isUri("http:// shouldfail.com"), false);
    assert.equal(isUri("https://[@example.org/test.txt"), false);
    assert.equal(isUri("http://example.com:abc/path"), false);
    assert.equal(isUri("http://[::ffff:01.2.3.4]"), false);
    assert.equal(isUri("http:/[::1]"), false);
    assert.equal(isUri("http://example.com/%6G"), false);
    assert.equal(isUri("http://example.com/%"), false);
    assert.equal(isUri("https://example.org/foobar®.txt"), false);
    assert.equal(isUri("https://example.org/foo bar.txt"), false);
    assert.equal(isUri("\\\\WINDOWS\\fileshare"), false);
  });
});

describe("isUriReference", () => {
  test("accepts relative, network-path and empty references", () => {
    assert.equal(isUriReference("http://foo.bar/?baz=qux#quux"), true);
    assert.equal(isUriReference("//foo.bar/?baz=qux#quux"), true);
    assert.equal(isUriReference("/abc"), true);
    assert.equal(isUriReference("abc"), true);
    assert.equal(isUriReference("#fragment"), true);
    assert.equal(isUriReference("?query=1"), true);
    assert.equal(isUriReference(""), true);
    assert.equal(isUriReference("//"), true);
    assert.equal(isUriReference("./this:that"), true);
    assert.equal(isUriReference("//[V1.fe]/p"), true);
  });

  test("rejects a colon in the first relative segment and bad components", () => {
    assert.equal(isUriReference("1:b"), false);
    assert.equal(isUriReference("#frag\\ment"), false);
    assert.equal(isUriReference("/%zz"), false);
    assert.equal(isUriReference('/a"b'), false);
    assert.equal(isUriReference("/[::1]"), false);
    assert.equal(isUriReference("//[::1/p"), false);
    assert.equal(isUriReference("//example.com:abc/p"), false);
    assert.equal(isUriReference("//a@b@example.com/"), false);
    assert.equal(isUriReference("//[::ffff:192.168.0.01]/p"), false);
    assert.equal(isUriReference("/foobar®.txt"), false);
    assert.equal(isUriReference("/p\n"), false);
  });
});

describe("isDuration", () => {
  test("accepts nested date and time runs and a bare week count", () => {
    assert.equal(isDuration("P4DT12H30M5S"), true);
    assert.equal(isDuration("P4Y"), true);
    assert.equal(isDuration("P1Y2M3DT4H5M6S"), true);
    assert.equal(isDuration("P1Y2M"), true);
    assert.equal(isDuration("P1M2D"), true);
    assert.equal(isDuration("PT0S"), true);
    assert.equal(isDuration("PT1H2M"), true);
    assert.equal(isDuration("PT1M2S"), true);
    assert.equal(isDuration("P2W"), true);
    assert.equal(isDuration("P01D"), true);
  });

  test("rejects skipped, reordered, unsigned-violating and fractional runs", () => {
    assert.equal(isDuration("P"), false);
    assert.equal(isDuration("PT"), false);
    assert.equal(isDuration("P1YT"), false);
    assert.equal(isDuration("PT1D"), false);
    assert.equal(isDuration("P2S"), false);
    assert.equal(isDuration("P1"), false);
    assert.equal(isDuration("P1Y2D"), false);
    assert.equal(isDuration("PT1H2S"), false);
    assert.equal(isDuration("P2D1Y"), false);
    assert.equal(isDuration("P1D2H"), false);
    assert.equal(isDuration("P1D2T3H"), false);
    assert.equal(isDuration("P1Y2W"), false);
    assert.equal(isDuration("P1WT1H"), false);
    assert.equal(isDuration("PT0.5S"), false);
    assert.equal(isDuration("P-1D"), false);
    assert.equal(isDuration("-P1D"), false);
    assert.equal(isDuration("P1e2D"), false);
    assert.equal(isDuration("P২Y"), false);
    assert.equal(isDuration("P1D "), false);
    assert.equal(isDuration(""), false);
  });
});
