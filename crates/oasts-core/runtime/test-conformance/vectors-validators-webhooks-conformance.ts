import type { ConformanceCase } from "./vectors-validators-conformance.ts";

export const cases: readonly ConformanceCase[] = [
  {
    id: "webhook/request-body-valid",
    matrixRow: "type",
    validator: "newPetPostRequestBodyValidator",
    input: { id: "p1", name: "Rex" },
    expected: { verdict: "pass" },
  },
  {
    id: "webhook/request-body-invalid",
    matrixRow: "required",
    validator: "newPetPostRequestBodyValidator",
    input: { id: "p1" },
    expected: {
      verdict: "fail",
      issues: [{ message: "missing required property name", path: [] }],
    },
  },
  {
    id: "callback/request-body-valid",
    matrixRow: "type",
    validator: "createSubscriptionSubscriptionEvents_1PostRequestBodyValidator",
    input: { id: "p2", name: "Milo" },
    expected: { verdict: "pass" },
  },
];
