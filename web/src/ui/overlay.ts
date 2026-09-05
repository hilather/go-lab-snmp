const INTEGER_TYPES = new Set([
  "integer",
  "counter32",
  "gauge32",
  "unsigned32",
  "timeTicks",
  "counter64",
]);

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const MIN_SAFE = BigInt(Number.MIN_SAFE_INTEGER);

const DIGITS = /^-?\d+$/;

export function leafTypeForOID(objects: ReadonlyArray<{ oid: string; type: string }> | undefined, oid: string): string {
  return objects?.find((o) => o.oid === oid)?.type ?? "";
}

/** Encode an overlay value without using Number() on unsafe or non-integer types. */
export function overlayJSONValue(leafType: string, raw: string): unknown {
  if (!INTEGER_TYPES.has(leafType) || !DIGITS.test(raw)) {
    return raw;
  }
  let n: bigint;
  try {
    n = BigInt(raw);
  } catch {
    return raw;
  }
  if (n <= MAX_SAFE && n >= MIN_SAFE) {
    if (leafType !== "integer" && n < 0n) {
      return raw;
    }
    return Number(raw);
  }
  return raw;
}
