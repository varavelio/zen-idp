// Playwright fixtures that give every browser test its own isolated Zen
// IdP instance and always tear it down, attaching the server output and
// configuration to the test report when the test fails.

import { expect, test as base } from "@playwright/test";
import { attachDiagnostics } from "./diagnostics.ts";
import { Harness, type HarnessOptions } from "./index.ts";

/** Fixtures provided to every test of the browser suite. */
export interface HarnessFixtures {
  /**
   * Per-test instance options, set with test.use. When omitted, the
   * harness fixture fails with a message that points at the missing
   * configuration.
   */
  harnessOptions: HarnessOptions | undefined;
  /** The running instance of the test, stopped automatically. */
  harness: Harness;
}

/**
 * Test function of the browser suite. Every test receives its own
 * isolated instance in `harness` and can additionally use the regular
 * Playwright fixtures such as `page` and `browser`.
 */
export const test = base.extend<HarnessFixtures>({
  harnessOptions: [undefined, { option: true }],
  harness: async ({ harnessOptions }, use, testInfo) => {
    if (harnessOptions === undefined) {
      throw new Error(
        "harness: configuration is required (call test.use({ harnessOptions: { config: ... } }))",
      );
    }
    const harness = await Harness.start(harnessOptions);
    try {
      await use(harness);
    } finally {
      if (testInfo.status === "failed" || testInfo.status === "timedOut") {
        await attachDiagnostics(testInfo, harness);
      }
      await harness.stop();
    }
  },
});

export { expect };
