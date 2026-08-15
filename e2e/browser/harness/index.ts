// Public surface of the browser harness: import everything from here.

export { assertBinary, binaryPath, type CommandResult, runBinary } from "./binary.ts";
export { Client, Response } from "./client.ts";
export {
  buildConfigDocument,
  type ClientConfig,
  type ConfigDocument,
  dumpYaml,
  type UserConfig,
  validateConfig,
} from "./config.ts";
export { deriveTOTPSecret, totpCode } from "./crypto.ts";
export { defaultRootSecret, Harness, type HarnessOptions } from "./harness.ts";
export { findOTPAuthSecret, findToken, formValue } from "./html.ts";
