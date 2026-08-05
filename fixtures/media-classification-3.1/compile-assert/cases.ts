import type {
  RoundTripApplicationXmlInput,
  RoundTripApplicationXmlResult,
} from "../generated/client/operations/roundtripapplicationxml.js";
import type {
  RoundTripSvgInput,
  RoundTripSvgResult,
} from "../generated/client/operations/roundtripsvg.js";
import type {
  RoundTripTextXmlInput,
  RoundTripTextXmlResult,
} from "../generated/client/operations/roundtriptextxml.js";
import type { SendPlainTextInput } from "../generated/client/operations/sendplaintext.js";
import type {
  SendTextJsonInput,
  SendTextJsonResult,
} from "../generated/client/operations/sendtextjson.js";

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

type AssertApplicationXmlRequestIsOpaque = Expect<
  Equal<RoundTripApplicationXmlInput["body"], Uint8Array>
>;
type AssertApplicationXmlResponseIsOpaque = Expect<
  Equal<Extract<RoundTripApplicationXmlResult, { outcome: 200 }>["data"], unknown>
>;
type AssertTextXmlRequestIsText = Expect<Equal<RoundTripTextXmlInput["body"], string>>;
type AssertTextXmlResponseIsOpaque = Expect<
  Equal<Extract<RoundTripTextXmlResult, { outcome: 200 }>["data"], unknown>
>;
type AssertSvgRequestIsOpaque = Expect<Equal<RoundTripSvgInput["body"], Uint8Array>>;
type AssertSvgResponseIsOpaque = Expect<
  Equal<Extract<RoundTripSvgResult, { outcome: 200 }>["data"], unknown>
>;
type AssertTextJsonRequestIsText = Expect<Equal<SendTextJsonInput["body"], string>>;
// text/json is unregistered, so both directions are text: the response arrives as the string on
// the wire, exactly like the text/plain operation below.
type AssertTextJsonResponseIsText = Expect<
  Equal<Extract<SendTextJsonResult, { outcome: 202 }>["data"], string>
>;
type AssertPlainTextRequestStaysString = Expect<Equal<SendPlainTextInput["body"], string>>;

export type {
  AssertApplicationXmlRequestIsOpaque,
  AssertApplicationXmlResponseIsOpaque,
  AssertTextXmlRequestIsText,
  AssertTextXmlResponseIsOpaque,
  AssertSvgRequestIsOpaque,
  AssertSvgResponseIsOpaque,
  AssertTextJsonRequestIsText,
  AssertTextJsonResponseIsText,
  AssertPlainTextRequestStaysString,
};
