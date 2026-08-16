// Helpers that extract values from rendered HTML pages with regular
// expressions, mirroring the e2e/http/harness Go package.

const inputPattern = /<input[^>]*>/g;
const namePattern = /name="([^"]+)"/;
const valuePattern = /value="([^"]*)"/;

/**
 * Returns the value of the first rendered form field with the given name,
 * or undefined when the page renders no such field.
 */
export function formValue(html: string, name: string): string | undefined {
  for (const input of html.match(inputPattern) ?? []) {
    const match = input.match(namePattern);
    if (match?.[1] !== name) {
      continue;
    }
    return input.match(valuePattern)?.[1];
  }
  return undefined;
}

// tokenPattern matches the rendered form of a one-use Zen IdP token.
const tokenPattern = /tok_[A-Za-z0-9]+_[A-Za-z0-9]+/;

/** Returns the first one-use token rendered in the given page, if any. */
export function findToken(text: string): string | undefined {
  return text.match(tokenPattern)?.[0];
}

// manualSecretPattern matches the TOTP shared secret revealed by the
// enrollment-ready page, carried by the copy button of the manual entry
// code.
const manualSecretPattern = /data-copy="([A-Z2-7]{52})"/;

/**
 * Returns the TOTP shared secret revealed by the first enrollment-ready
 * page of the given text, if any.
 */
export function findOTPAuthSecret(text: string): string | undefined {
  return text.match(manualSecretPattern)?.[1];
}
