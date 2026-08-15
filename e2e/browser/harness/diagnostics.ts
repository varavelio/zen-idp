// Attaches the server output and configuration of an instance to the
// report of a failed test, so failures can be diagnosed from the instance
// side.

import type { TestInfo } from "@playwright/test";
import type { Harness } from "./harness.ts";

export async function attachDiagnostics(testInfo: TestInfo, harness: Harness): Promise<void> {
  await testInfo.attach("server.log", {
    body: harness.serverLog(),
    contentType: "text/plain",
  });
  await testInfo.attach("config.yaml", {
    body: await harness.configYaml(),
    contentType: "text/yaml",
  });
}
