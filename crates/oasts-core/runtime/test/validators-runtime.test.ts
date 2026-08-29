import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  appendKey,
  codePointLength,
  compareBigIntToNumber,
  deepEqual,
  hasGet,
  int64WireValue,
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
  issue,
  type Issue,
  isTime,
  isUri,
  isUriReference,
  isUuid,
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
