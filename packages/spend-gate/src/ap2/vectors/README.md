# AP2 test vectors

`spec-open-closed-chain.txt` is the encoded token from the example "Open Payment
Mandate chained with a closed Payment Mandate" in `docs/ap2/payment_mandate.md`
of https://github.com/google-agentic-commerce/AP2 (main branch, fetched
2026-11-02). Copyright Google LLC, Apache License 2.0.

The spec does not publish the root issuer key (`kid: agent-provider-key-1`), so
the tests check the key-bound hop's ES256 signature, its `sd_hash` and the
disclosures. They cannot check the root signature.
