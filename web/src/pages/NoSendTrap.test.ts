import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const pagesDir = join(import.meta.dirname);

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, name.name);
    if (name.isDirectory()) {
      out.push(...walk(p));
      continue;
    }
    if (name.name.endsWith(".test.ts") || name.name.endsWith(".test.tsx")) {
      continue;
    }
    if (name.name.endsWith(".ts") || name.name.endsWith(".tsx")) {
      out.push(p);
    }
  }
  return out;
}

describe("no send-trap control", () => {
  it("does not expose a send-trap or traps:send control", () => {
    const files = walk(join(pagesDir, ".."));
    const hits: string[] = [];
    for (const file of files) {
      if (file.endsWith("NoSendTrap.test.ts")) {
        continue;
      }
      const body = readFileSync(file, "utf8");
      if (/send[- ]?trap|traps:send|snmptrap\b|originate trap/i.test(body) && !/no send-trap/i.test(body)) {
        hits.push(file);
      }
    }
    expect(hits).toEqual([]);
  });
});
