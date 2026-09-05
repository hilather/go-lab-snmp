import { describe, expect, it } from "vitest";
import { leafTypeForOID, overlayJSONValue } from "./overlay";

describe("overlayJSONValue", () => {
  it("sends a JSON number for safe integer leaves", () => {
    expect(overlayJSONValue("integer", "2")).toBe(2);
    expect(overlayJSONValue("counter32", "10")).toBe(10);
  });

  it("keeps digit-only octetString as a string", () => {
    expect(overlayJSONValue("octetString", "123")).toBe("123");
    expect(typeof overlayJSONValue("octetString", "123")).toBe("string");
  });

  it("does not use Number() for counter64 above 2^53", () => {
    const raw = "18446744073709551615";
    const v = overlayJSONValue("counter64", raw);
    expect(v).toBe(raw);
    expect(typeof v).toBe("string");
  });

  it("looks up leaf type by OID", () => {
    expect(leafTypeForOID([{ oid: "1.2.3", type: "integer" }], "1.2.3")).toBe("integer");
    expect(leafTypeForOID([{ oid: "1.2.3", type: "integer" }], "9")).toBe("");
  });
});
