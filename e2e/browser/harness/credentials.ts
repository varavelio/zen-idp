// Shared credentials of the browser suite. The hashes are precomputed
// Argon2id PHC values anchored in the HTTP suite, and the plaintext
// secrets are known only to the tests.

/** Root secret of every instance of the suite. */
export const testRootSecret = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

/** Administrator password whose Argon2id hash is testAdminHash. */
export const testAdminPassword = "test-admin-password";

/** Argon2id PHC hash of testAdminPassword. */
export const testAdminHash =
  "$argon2id$v=19$m=65536,t=2,p=2$INy39hwa9rMN8WhprspfDQ$45uH4EsaLtb2h9bUkVfgAAoLKsgPK1ALYprlwxm16B4";

/** Confidential client secret whose Argon2id hash is testClientHash. */
export const testClientSecret = "test-client-secret";

/** Argon2id PHC hash of testClientSecret. */
export const testClientHash =
  "$argon2id$v=19$m=65536,t=2,p=2$5XEq+R1hozyGGEdvY7KVYA$cEyyXwpgnzm0IMtpsDu3+O6eBxBdO2VaFEpyLHUetIo";
