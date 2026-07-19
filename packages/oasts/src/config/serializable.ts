/**
 * Plain-JSON validation for evaluated script configs.
 *
 * The config export must survive `JSON.stringify` without loss or surprise:
 * functions, promises/thenables, symbols (as values or keys), `bigint`,
 * `undefined`, cycles, accessor properties, and non-plain class instances are
 * rejected anywhere in the value. Property inspection goes through
 * `Object.getOwnPropertyDescriptor` so validation never invokes getters —
 * config evaluation already ran; validation must not run more user code.
 */

/** A violation naming the offending path, e.g. `spec.hooks[0]`. */
export interface SerializabilityViolation {
  path: string;
  reason: string;
}

function isPlainObject(value: object): boolean {
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function violation(path: string, reason: string): SerializabilityViolation {
  return { path: path === "" ? "config" : path, reason };
}

function validateValue(
  value: unknown,
  path: string,
  seen: Set<object>,
): SerializabilityViolation | null {
  switch (typeof value) {
    case "string":
    case "number":
    case "boolean":
      return null;
    case "bigint":
      return violation(path, "bigint values cannot be represented in JSON");
    case "symbol":
      return violation(path, "symbol values cannot be represented in JSON");
    case "undefined":
      return violation(path, "undefined cannot be represented in JSON");
    case "function":
      return violation(path, "functions cannot be represented in JSON");
    case "object":
      break;
  }
  if (value === null) {
    return null;
  }
  const objectValue: object = value;
  if (seen.has(objectValue)) {
    return violation(path, "cyclic references cannot be represented in JSON");
  }

  const thenDescriptor = Object.getOwnPropertyDescriptor(objectValue, "then");
  if (thenDescriptor !== undefined && typeof thenDescriptor.value === "function") {
    return violation(path, "thenable values are not synchronous plain data");
  }

  if (Array.isArray(objectValue)) {
    seen.add(objectValue);
    for (let index = 0; index < objectValue.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(objectValue, index);
      if (descriptor === undefined) {
        return violation(`${path}[${index}]`, "sparse array holes cannot be represented in JSON");
      }
      if (descriptor.get !== undefined || descriptor.set !== undefined) {
        return violation(`${path}[${index}]`, "accessor properties are not plain data");
      }
      const elementViolation = validateValue(descriptor.value, `${path}[${index}]`, seen);
      if (elementViolation !== null) {
        return elementViolation;
      }
    }
    seen.delete(objectValue);
    return null;
  }

  if (!isPlainObject(objectValue)) {
    return violation(path, "non-plain class instances are not plain data");
  }
  if (Object.getOwnPropertySymbols(objectValue).length > 0) {
    return violation(path, "symbol keys cannot be represented in JSON");
  }

  seen.add(objectValue);
  for (const key of Object.getOwnPropertyNames(objectValue)) {
    const keyPath = path === "" ? key : `${path}.${key}`;
    const descriptor = Object.getOwnPropertyDescriptor(objectValue, key);
    if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined) {
      return violation(keyPath, "accessor properties are not plain data");
    }
    const propertyViolation = validateValue(descriptor.value, keyPath, seen);
    if (propertyViolation !== null) {
      return propertyViolation;
    }
  }
  seen.delete(objectValue);
  return null;
}

/**
 * Returns the first violation in `value`, or `null` when it is plain JSON
 * data safe to `JSON.stringify` and hand to the Rust core.
 */
export function findSerializabilityViolation(value: unknown): SerializabilityViolation | null {
  return validateValue(value, "", new Set());
}
