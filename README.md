# anyoauth_sdk

Generated AnyOAuth elixir confidential-backend SDK, version 0.1.0. MIT licensed. Model descriptors are generated from OpenAPI and embedded in the runtime (also published in schema.json). Objects use JSON field names; optional additive response fields are preserved.

## Install / build

Add `{:anyoauth_sdk, path: "path/to/sdks/elixir"}` to Mix dependencies; run `mix deps.get && mix compile`. Jason is the only package dependency.

From this SDK repository root:

```sh
mix deps.get && mix compile --warnings-as-errors
python3 tests/selftest.py
elixir -pa _build/dev/lib/anyoauth_sdk/ebin -pa _build/dev/lib/jason/ebin tests/conformance.exs < input.json
```

The runner reads one JSON object and prints one JSON result. Example input: `{"action":"pkceChallenge","params":{"codeVerifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}`. Tests use a local HTTP server and dummy credentials only.

## Public API

Construct `AnyOAuth.new(client_id, client_secret, base_url)` and pass the returned client as the first argument to each method. The origin defaults to https://api.anyoauth.com. Each operation accepts a parameter map with string keys.

- `exchange_code`
- `profile`
- `revoke`
- `providers`
- `pkce_challenge`
- `authorization_url`
- `validate_callback`
- `create_transaction`

Canonical parameters: exchangeCode {code, codeVerifier, redirectUri}; profile/revoke {accessToken}; pkceChallenge {codeVerifier}; authorizationUrl {provider, redirectUri, state, codeChallenge}; validateCallback {callbackUrl, redirectUri, state, expiresAt}; createTransaction {}. Revocation returns null/nil. Errors expose status, code and safe message. Default timeout is 10 seconds with no redirects or retries.

Persist the transaction in the initiating browser's server session, binding it to the exact registered callback. Construct the authorization URL locally, then navigate the browser. Validate the callback and consume the saved transaction atomically (including provider denial). Exchange once with the original verifier, retrieve profile, identify by subject rather than email, and create your application's session. Nullable profile fields are legitimate. Keep secrets on the backend; never put tokens or the verifier in URLs. Helpers do not manage session storage.

Generated reproducibly by `node sdks/generate.mjs --target=elixir`; edit sdks/templates/server-dynamic.mjs rather than generated sources.

## Standalone conformance

Run `node tests/check.mjs` from this package after installing/building dependencies. The shared suite exercises all eight public actions through the native runtime, schema failures, wire formats, redirects, no retries, and deadlines. Node is a test harness dependency only.

## Source and releases

Repository: https://github.com/AnyOAuth/anyoauth-elixir

GitHub prerelease: https://github.com/AnyOAuth/anyoauth-elixir/releases/tag/v0.1.0

Clone this repository, then run `node verify.mjs` with the native toolchain installed to build and execute the package's conformance suite. Source is generated in the AnyOAuth monorepo; propose changes there so every language stays aligned. GitHub hosts source archives and checksums. Package registry publication is separate.

This initial source release has full advertised-method conformance coverage. Runtime line/branch coverage for the whole language matrix remains a separate release gate; see https://anyoauth.com/docs/libraries/.
