import assert from "node:assert/strict";
import { test } from "node:test";

import { findSerializabilityViolation } from "../src/config/serializable.ts";

test("accepts plain JSON data", () => {
  assert.equal(
    findSerializabilityViolation({
      schemaVersion: 1,
      input: { path: "./openapi.yaml" },
      output: "./generated",
      nested: { list: [1, "two", true, null], empty: {}, nullProto: { __proto__: null } },
    }),
    null,
  );
});

test("rejects every non-JSON value type with its path", () => {
  const cases: Array<[unknown, string, string]> = [
    [{ a: () => 1 }, "a", "functions"],
    [{ a: { b: 1n } }, "a.b", "bigint"],
    [{ a: Symbol("s") }, "a", "symbol values"],
    [{ a: [undefined] }, "a[0]", "undefined"],
    [{ a: Promise.resolve(1) }, "a", "non-plain class instances"],
    [{ a: { then: () => 1 } }, "a", "thenable"],
    [{ a: new Date() }, "a", "non-plain class instances"],
    [{ a: new Map() }, "a", "non-plain class instances"],
  ];
  for (const [value, path, reason] of cases) {
    const violation = findSerializabilityViolation(value);
    assert.notEqual(violation, null, path);
    assert.equal(violation?.path, path);
    assert.match(violation?.reason ?? "", new RegExp(reason));
  }
});

test("rejects symbol keys, accessors, holes, and cycles", () => {
  assert.match(
    findSerializabilityViolation({ a: { [Symbol("k")]: 1 } })?.reason ?? "",
    /symbol keys/,
  );

  const withGetter: Record<string, unknown> = {};
  Object.defineProperty(withGetter, "secret", { get: () => 1, enumerable: true });
  const getterViolation = findSerializabilityViolation({ a: withGetter });
  assert.equal(getterViolation?.path, "a.secret");
  assert.match(getterViolation?.reason ?? "", /accessor/);

  const withArrayGetter: unknown[] = [1];
  Object.defineProperty(withArrayGetter, 1, { get: () => 2, enumerable: true });
  const arrayGetterViolation = findSerializabilityViolation({ a: withArrayGetter });
  assert.equal(arrayGetterViolation?.path, "a[1]");
  assert.match(arrayGetterViolation?.reason ?? "", /accessor/);

  const sparse = [1, , 3];
  const holeViolation = findSerializabilityViolation({ a: sparse });
  assert.equal(holeViolation?.path, "a[1]");
  assert.match(holeViolation?.reason ?? "", /sparse array holes/);

  const cyclic: { self?: unknown } = {};
  cyclic.self = cyclic;
  assert.match(findSerializabilityViolation(cyclic)?.reason ?? "", /cyclic/);

  const cyclicArray: unknown[] = [];
  cyclicArray.push(cyclicArray);
  assert.match(findSerializabilityViolation({ a: cyclicArray })?.reason ?? "", /cyclic/);
});

test("accepts repeated non-cyclic references and names the root", () => {
  const shared = { ok: true };
  assert.equal(findSerializabilityViolation({ a: shared, b: [shared] }), null);
  assert.equal(findSerializabilityViolation(7n)?.path, "config");
  assert.equal(findSerializabilityViolation("top-level"), null);
});
