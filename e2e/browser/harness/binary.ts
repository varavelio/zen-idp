// The compiled zen-idp executable and helpers to invoke it.

// binaryPath is the compiled zen-idp executable used by the whole suite. It
// is hardcoded because the suite always runs inside the devcontainer, where
// the e2e task builds the binary to this exact location before running the
// tests, so the harness never compiles it itself.
export const binaryPath = "/workspaces/zen-idp/dist/zen-idp";

/** Result of one invocation of the compiled binary. */
export interface CommandResult {
  /** Standard output as text. */
  stdout: string;
  /** Standard error as text. */
  stderr: string;
  /** Process exit code. */
  exitCode: number;
}

/**
 * Fails fast when the compiled binary is not where the suite expects it,
 * so errors point at the missing build instead of the test.
 */
export function assertBinary(): void {
  try {
    Deno.statSync(binaryPath);
  } catch {
    throw new Error(`compiled binary not found at ${binaryPath} (run \`task build\` first)`);
  }
}

/**
 * Runs the compiled binary once with the given arguments and returns its
 * captured output, for tests that exercise command-line behavior.
 */
export async function runBinary(
  args: string[],
  options: { env?: Record<string, string>; cwd?: string } = {},
): Promise<CommandResult> {
  assertBinary();
  const command = new Deno.Command(binaryPath, {
    args,
    cwd: options.cwd,
    env: options.env,
    stdout: "piped",
    stderr: "piped",
  });
  const { code, stdout, stderr } = await command.output();
  const decoder = new TextDecoder();
  return { stdout: decoder.decode(stdout), stderr: decoder.decode(stderr), exitCode: code };
}
