// src/cli/action.ts
import { randomUUID } from "node:crypto";

// src/sdk/redact.ts
var REDACTED = "[redacted]";
var KAL_TOKEN = /\bkal_([A-Za-z0-9]{1,16})_[A-Za-z0-9_-]+/g;
var BEARER = /\bBearer\s+(?!kal_[A-Za-z0-9]{1,16}_\[redacted\])\S+/gi;
var MIN_SECRET_CHARS = 8;
function redact(text2, token) {
  let out = text2;
  if (token !== "") {
    const kal = /^kal_([A-Za-z0-9]{1,16})_(.+)$/.exec(token);
    out = out.split(token).join(kal === null ? REDACTED : `kal_${kal[1] ?? ""}_${REDACTED}`);
    const secret = kal?.[2] ?? "";
    if (secret.length >= MIN_SECRET_CHARS) {
      out = out.split(secret).join(REDACTED);
    }
  }
  return out.replace(KAL_TOKEN, `kal_$1_${REDACTED}`).replace(BEARER, `Bearer ${REDACTED}`);
}
var SOURCE_CREDENTIAL = /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|npm_[A-Za-z0-9]{36,}|pypi-[A-Za-z0-9_-]{50,})/;
var CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;
function holdsUnsafeText(value, token) {
  if (typeof value === "string") {
    return redact(value, token) !== value || SOURCE_CREDENTIAL.test(value) || value.search(CONTROL_CHARS) !== -1;
  }
  if (typeof value !== "object" || value === null) {
    return false;
  }
  return Object.entries(value).some(([key, entry]) => holdsUnsafeText(key, token) || holdsUnsafeText(entry, token));
}
function messageOf(error) {
  if (error instanceof Error) {
    return error.message;
  }
  return typeof error === "string" ? error : "unknown error";
}
function clip(text2, max) {
  return text2.length <= max ? text2 : `${text2.slice(0, max)}...`;
}

// src/sdk/errors.ts
var FeederError = class extends Error {
  constructor(message) {
    super(message);
    this.name = new.target.name;
  }
};
var InvalidClaimError = class extends FeederError {
};
var FeederConfigError = class extends FeederError {
};
var FeederNetworkError = class extends FeederError {
};
var KINDS = {
  400: "bad_request",
  401: "unauthenticated",
  403: "forbidden",
  404: "not_found",
  405: "method_not_allowed",
  413: "too_large",
  501: "not_implemented"
};
function isRetryableStatus(status) {
  return status >= 500 && status !== 501;
}
function kindOf(status) {
  return KINDS[status] ?? (isRetryableStatus(status) ? "unavailable" : "unexpected");
}
var FeederHttpError = class extends FeederError {
  status;
  kind;
  /** The server's typed error name (`ApiError.error`, for example `invalid_argument`), or null when it sent none. */
  code;
  /** The server's message (`ApiError.message`), redacted, or null when it sent none. */
  serverMessage;
  /** The response body, redacted and cut to 2,000 characters. */
  body;
  constructor(status, body, server = null) {
    const said = server === null ? body === "" ? "" : `: ${body}` : ` ${server.code}: ${server.message}`;
    super(`the feeder endpoint answered HTTP ${status}${said}`);
    this.status = status;
    this.kind = kindOf(status);
    this.code = server?.code ?? null;
    this.serverMessage = server?.message ?? null;
    this.body = body;
  }
};
var FeederProtocolError = class extends FeederError {
  body;
  constructor(message, body) {
    super(`${message}${body === "" ? "" : `: ${body}`}`);
    this.body = body;
  }
};
function isUnavailable(error) {
  return error instanceof FeederNetworkError || error instanceof FeederHttpError && error.kind === "unavailable";
}

// src/sdk/wire.ts
var FEEDER_CLAIM_PATH = "/api/v1/feeder/claim";
var FEEDER_HEALTH_PATH = "/api/v1/health";
var FEEDER_BATCH_MAX = 100;
var OUTCOMES = {
  advanced: true,
  challenged: true,
  provisional: true,
  unchanged: true,
  idempotent_replay: true,
  conflict: true,
  stale_observation: true,
  lifecycle_regress: true,
  source_not_allowed: true,
  invalid_observation_time: true,
  stored_as_key_proposal: true
};
var TOOL_ERRORS = {
  not_found: true,
  ambiguous: true,
  invalid_argument: true,
  keyed_claims_are_team: true,
  viewer_read_only: true,
  machine_token_limited: true,
  not_active: true,
  version_conflict: true,
  content_too_long: true,
  guard_rejected: true,
  dependents_present: true,
  undo_window_passed: true,
  rate_limited: true,
  space_full: true
};
var STATES = { current: true, challenged: true, disputed: true, history: true, rejected: true, proposed_key: true };
var HEALTH_STATES = { fresh: true, past_window: true, no_claim: true, no_window: true };
var SUBJECT = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;
var FACT = /^[a-z0-9][a-z0-9_-]*$/;
var KEY_NAME_MAX = 200;
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function has(table, value) {
  return typeof value === "string" && Object.hasOwn(table, value);
}
function isKeyName(value) {
  const dot = value.lastIndexOf(".");
  return value.length <= KEY_NAME_MAX && dot > 0 && SUBJECT.test(value.slice(0, dot)) && FACT.test(value.slice(dot + 1));
}
function chunk(items, size) {
  const out = [];
  for (let at = 0; at < items.length; at += size) {
    out.push(items.slice(at, at + size));
  }
  return out;
}
function encodeBatch(batch) {
  try {
    return JSON.stringify(batch);
  } catch {
    throw new InvalidClaimError("every claim value must be plain JSON");
  }
}
async function idempotencyKey(body) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)));
  return `feeder-${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
function nullableText(value) {
  return value === null || typeof value === "string";
}
function readResult(value) {
  if (!isRecord(value) || typeof value.key !== "string" || !has(OUTCOMES, value.outcome) || !has(STATES, value.state)) {
    return null;
  }
  if (!nullableText(value.claim) || !nullableText(value.ref) || !nullableText(value.dispute)) {
    return null;
  }
  const result = { key: value.key, outcome: value.outcome, state: value.state, claim: value.claim, ref: value.ref, dispute: value.dispute };
  if (value.error === void 0) {
    return result;
  }
  return has(TOOL_ERRORS, value.error) ? { ...result, error: value.error } : null;
}
function readResults(body, sent, text2) {
  if (!isRecord(body) || typeof body.as_of !== "string" || !Array.isArray(body.results)) {
    throw new FeederProtocolError("the feeder endpoint answered 200 without { as_of, results }", text2);
  }
  const results = body.results.map(readResult);
  if (results.length !== sent.length) {
    throw new FeederProtocolError(`the feeder endpoint answered ${results.length} results for ${sent.length} claims`, text2);
  }
  const typed = [];
  for (const [index, result] of results.entries()) {
    if (result === null || result.key !== sent[index]?.key.trim()) {
      throw new FeederProtocolError(`result ${index} is not a FeederClaimResult for ${sent[index]?.key ?? "the claim sent"}`, text2);
    }
    typed.push(result);
  }
  return { asOf: body.as_of, results: typed };
}
function readHealth(body, text2) {
  const row = (value) => isRecord(value) && typeof value.key === "string" && has(HEALTH_STATES, value.state) && nullableText(value.last_fed_at);
  if (!isRecord(body) || typeof body.as_of !== "string" || typeof body.ok !== "boolean" || !Array.isArray(body.keys) || !body.keys.every(row)) {
    throw new FeederProtocolError("the health endpoint answered 200 without a HealthReport", text2);
  }
  return { as_of: body.as_of, ok: body.ok, keys: body.keys };
}
function readApiError(body) {
  return isRecord(body) && typeof body.error === "string" && typeof body.message === "string" ? { code: body.error, message: body.message } : null;
}
function isLanded(result) {
  return result.state === "current";
}

// src/cli/deps.ts
var UsageError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "UsageError";
  }
};
var SourceError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "SourceError";
  }
};
function optionString(values, name) {
  const value = values[name];
  return typeof value === "string" ? value : void 0;
}
function optionList(values, name) {
  const value = values[name];
  const list = Array.isArray(value) ? value.filter((item) => typeof item === "string") : typeof value === "string" ? [value] : [];
  return [...new Set(list)];
}
function optionFlag(values, name) {
  return values[name] === true;
}
function optionKeys(values, example, fallback) {
  const keys = optionList(values, "key");
  if (keys.length === 0 && fallback === void 0) {
    throw new UsageError(`--key is required, for example --key ${example}`);
  }
  for (const key of keys) {
    if (!isKeyName(key)) {
      throw new UsageError(`--key must be lower-case subject.fact, for example ${example}`);
    }
  }
  return keys.length === 0 && fallback !== void 0 ? [fallback] : keys;
}

// src/cli/run.ts
import { parseArgs } from "node:util";

// src/sdk/spool.ts
function encodeSpoolLine(batch, spooledAt) {
  return JSON.stringify({ spooledAt: spooledAt.toISOString(), batch });
}
function decodeSpoolLine(line) {
  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch {
    return null;
  }
  const batch = isRecord(parsed) ? parsed.batch : void 0;
  if (!isRecord(batch) || typeof batch.space !== "string" || batch.space === "" || !Array.isArray(batch.claims) || batch.claims.length === 0) {
    return null;
  }
  const entry = (value) => isRecord(value) && typeof value.key === "string" && isRecord(value.claim);
  return batch.claims.every(entry) ? batch : null;
}

// src/sdk/client.ts
var DEFAULT_RETRIES = { attempts: 3, baseMs: 500 };
var DEFAULT_TIMEOUT_MS = 15e3;
var ERROR_BODY_MAX = 2e3;
function defaultSleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
function parseJson(text2) {
  if (text2 === "") {
    return void 0;
  }
  try {
    return JSON.parse(text2);
  } catch {
    return void 0;
  }
}
function isLoopback(hostname) {
  return hostname === "localhost" || hostname.endsWith(".localhost") || hostname === "127.0.0.1" || hostname === "[::1]";
}
function baseUrl(raw, allowInsecureHttp) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new FeederConfigError("url is not a valid URL");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new FeederConfigError("url must start with https:// (or http:// for localhost)");
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new FeederConfigError("url must not contain credentials; pass the token as the token option");
  }
  if (parsed.protocol === "http:" && !isLoopback(parsed.hostname) && !allowInsecureHttp) {
    throw new FeederConfigError("refusing to send a credential over plain http; use https, or set allowInsecureHttp for a private network");
  }
  return `${parsed.origin}${parsed.pathname}`.replace(/\/+$/, "").replace(/\/api\/v1$/, "");
}
function checkRetries(retries) {
  if (!Number.isInteger(retries.attempts) || retries.attempts < 1) {
    throw new FeederConfigError("retries.attempts must be an integer of at least 1");
  }
  if (!Number.isFinite(retries.baseMs) || retries.baseMs < 0) {
    throw new FeederConfigError("retries.baseMs must be zero or more");
  }
}
function createFeederClient(options) {
  const token = options.token;
  if (typeof token !== "string" || !/^[\x21-\x7e]+$/.test(token)) {
    throw new FeederConfigError("token must be a non-empty string of printable characters without spaces");
  }
  const base = baseUrl(options.url, options.allowInsecureHttp === true);
  const retries = options.retries ?? DEFAULT_RETRIES;
  checkRetries(retries);
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const now = options.now ?? (() => /* @__PURE__ */ new Date());
  const sleep = options.sleep ?? defaultSleep;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const spool = options.spool;
  const userAgent = `kalibrate-feeders/${options.version ?? "unknown"}`;
  const safe = (text2) => redact(text2, token);
  const log = (line) => {
    options.log?.(safe(line));
  };
  function httpError(status, text2) {
    const server = readApiError(parseJson(text2));
    return new FeederHttpError(status, clip(safe(text2), ERROR_BODY_MAX), server === null ? null : { code: safe(server.code), message: safe(server.message) });
  }
  async function send(path, init) {
    let failure;
    for (let attempt = 1; attempt <= retries.attempts; attempt += 1) {
      let reason;
      try {
        const response = await fetchImpl(`${base}${path}`, { ...init, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
        const text2 = await response.text();
        if (!isRetryableStatus(response.status)) {
          return { status: response.status, text: text2 };
        }
        failure = httpError(response.status, text2);
        reason = `HTTP ${response.status}`;
      } catch (error) {
        failure = new FeederNetworkError(`could not reach the feeder endpoint: ${safe(messageOf(error))}`);
        reason = safe(messageOf(error));
      }
      if (attempt < retries.attempts) {
        const wait = retries.baseMs * 2 ** (attempt - 1);
        log(`attempt ${attempt} of ${retries.attempts} failed (${reason}); retrying in ${wait} ms`);
        await sleep(wait);
      }
    }
    throw failure ?? new FeederNetworkError("could not reach the feeder endpoint");
  }
  function authHeaders() {
    return { Authorization: `Bearer ${token}`, "User-Agent": userAgent };
  }
  async function post(batch, body) {
    const reply = await send(FEEDER_CLAIM_PATH, {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json", "Idempotency-Key": await idempotencyKey(body) },
      body
    });
    if (reply.status !== 200) {
      throw httpError(reply.status, reply.text);
    }
    return readResults(parseJson(reply.text), batch.claims, clip(safe(reply.text), ERROR_BODY_MAX));
  }
  async function claim(space, claims) {
    const batches = chunk(claims, FEEDER_BATCH_MAX).map((part) => {
      const batch = { space, claims: part };
      const body = encodeBatch(batch);
      const unsafe = JSON.parse(body).claims.findIndex((entry) => holdsUnsafeText(entry, token));
      if (unsafe !== -1) {
        const key = part[unsafe]?.key ?? "";
        const named = holdsUnsafeText(key, token) ? "one key" : key;
        throw new InvalidClaimError(`the claim for ${named} holds a credential or a control character; nothing was sent`);
      }
      return { batch, body };
    });
    const results = [];
    let asOf = null;
    for (const [index, { batch, body }] of batches.entries()) {
      try {
        const answer = await post(batch, body);
        results.push(...answer.results);
        asOf = answer.asOf;
      } catch (error) {
        if (spool === void 0 || !isUnavailable(error)) {
          throw error;
        }
        const rest = batches.slice(index).map((entry) => entry.batch);
        const reason = safe(messageOf(error));
        try {
          for (const waiting of rest) {
            await spool.append(encodeSpoolLine(waiting, now()));
          }
        } catch (spoolError) {
          throw new FeederNetworkError(`${reason}; the batch could not be spooled either: ${safe(messageOf(spoolError))}`);
        }
        const spooled = rest.flatMap((waiting) => waiting.claims);
        log(`the feeder endpoint is unavailable (${reason}); ${spooled.length} claims were spooled`);
        return { results, asOf, spooled, warning: reason };
      }
    }
    return { results, asOf, spooled: [], warning: null };
  }
  async function health() {
    const reply = await send(FEEDER_HEALTH_PATH, { method: "GET", headers: { ...authHeaders(), Accept: "application/json" } });
    if (reply.status !== 200) {
      throw httpError(reply.status, reply.text);
    }
    return readHealth(parseJson(reply.text), clip(safe(reply.text), ERROR_BODY_MAX));
  }
  async function flushSpool() {
    const report = { sent: 0, remaining: 0, results: [], errors: [] };
    if (spool === void 0) {
      return report;
    }
    const lines = await spool.readAll();
    const keep = [];
    let unavailable = false;
    for (const [index, line] of lines.entries()) {
      if (unavailable) {
        keep.push(line);
        continue;
      }
      const batch = decodeSpoolLine(line);
      if (batch === null) {
        report.errors.push(`spool line ${index + 1} is not a spooled batch and was dropped`);
        continue;
      }
      try {
        report.results.push(...(await post(batch, encodeBatch(batch))).results);
        report.sent += 1;
      } catch (error) {
        keep.push(line);
        report.errors.push(`spool line ${index + 1}: ${safe(messageOf(error))}`);
        unavailable = isUnavailable(error);
      }
    }
    await spool.replace(keep);
    report.remaining = keep.length;
    return report;
  }
  return { claim, health, flushSpool };
}

// src/cli/run.ts
var EXIT = {
  /** Every claim landed, or the server already held it. */
  ok: 0,
  /** The server refused the batch or could not be reached, or the feeder's own source could not be read. */
  failed: 1,
  /** A usage error or a missing environment variable. Nothing was sent. */
  usage: 2,
  /** The server took the batch but refused at least one claim; stderr names each key and why. */
  refused: 3
};
var COMMON_OPTIONS = {
  space: { type: "string" },
  "dry-run": { type: "boolean" },
  help: { type: "boolean", short: "h" }
};
var COMMON_USAGE = `Environment:
  KALIBRATE_URL            the server's base URL (required unless --dry-run)
  KALIBRATE_FEEDER_TOKEN   the machine token, kal_<prefix>_<secret> (required unless --dry-run)
  KALIBRATE_SPACE          the space slug the keys belong to (or --space)
  KALIBRATE_ALLOW_INSECURE_HTTP=1   allow plain http to a non-localhost host

Options:
  --space <slug>  the space, over KALIBRATE_SPACE
  --dry-run       print the batch as JSON and send nothing
  -h, --help      print this text

Exit codes: 0 every claim landed or was already held, 1 the server refused the batch or could not be reached,
2 usage error or missing environment, 3 the server refused some claims (stderr says which and why).`;
var WHY = {
  advanced: "",
  challenged: "the key holds a higher-standing value; this one waits for that value's owner",
  provisional: "",
  unchanged: "",
  idempotent_replay: "",
  conflict: "the key is in dispute",
  stale_observation: "the server holds a newer observation",
  lifecycle_regress: "the lifecycle would move backwards",
  source_not_allowed: "the key does not accept this token's authority; add it to the key's allowed sources or use another token",
  invalid_observation_time: "validFrom is outside the accepted window",
  stored_as_key_proposal: "the key is not registered in this space"
};
var TOKEN_LIMITED = "the key is outside this token's allowedKeys; widen the token's allowedKeys";
function why(result) {
  const reason = result.error === "machine_token_limited" ? TOKEN_LIMITED : WHY[result.outcome];
  return `${reason}${result.dispute === null ? "" : ` (dispute ${result.dispute})`}`;
}
function verdict(result) {
  return `${result.outcome} (${result.state}${result.error === void 0 ? "" : `, ${result.error}`})`;
}
function spaceOf(values, deps) {
  const space = (optionString(values, "space") ?? deps.env.KALIBRATE_SPACE ?? "").trim();
  return space === "" ? void 0 : space;
}
async function deliver(command6, claims, space, deps) {
  const url = deps.env.KALIBRATE_URL?.trim() ?? "";
  const token = deps.env.KALIBRATE_FEEDER_TOKEN?.trim() ?? "";
  if (url === "") {
    throw new UsageError("KALIBRATE_URL is not set");
  }
  if (token === "") {
    throw new UsageError("KALIBRATE_FEEDER_TOKEN is not set");
  }
  if (space === void 0) {
    throw new UsageError("no space: set KALIBRATE_SPACE or pass --space <slug>");
  }
  const out = (line) => deps.stdout(redact(line, token));
  const err = (line) => deps.stderr(redact(line, token));
  let report;
  try {
    const client = createFeederClient({
      url,
      token,
      fetch: deps.fetch,
      now: deps.now,
      sleep: deps.sleep,
      version: deps.version,
      allowInsecureHttp: deps.env.KALIBRATE_ALLOW_INSECURE_HTTP === "1",
      log: (line) => err(`${command6.name}: ${line}`)
    });
    report = await client.claim(space, claims);
  } catch (error) {
    if (error instanceof FeederConfigError) {
      throw new UsageError(error.message);
    }
    if (!(error instanceof FeederError) || error instanceof InvalidClaimError) {
      throw error;
    }
    const what = isUnavailable(error) ? "the batch was not delivered: " : error instanceof FeederHttpError ? "the server refused the batch: " : "";
    err(`${command6.name}: ${what}${error.message}`);
    return EXIT.failed;
  }
  const refused = report.results.filter((result) => !isLanded(result));
  for (const result of report.results.filter(isLanded)) {
    out(`${result.outcome} ${result.key}${result.ref === null ? "" : ` (${result.ref})`}`);
  }
  for (const result of refused) {
    err(`${command6.name}: refused: ${result.key}: ${verdict(result)}: ${why(result)}`);
  }
  return refused.length === 0 ? EXIT.ok : EXIT.refused;
}
async function execute(command6, argv, deps) {
  const secret = deps.env.KALIBRATE_FEEDER_TOKEN?.trim() ?? "";
  const err = (line) => deps.stderr(redact(line, secret));
  try {
    let values;
    try {
      values = parseArgs({
        args: [...argv],
        options: { ...command6.options, ...COMMON_OPTIONS },
        allowPositionals: false,
        strict: true
      }).values;
    } catch (error) {
      err(`${command6.name}: ${messageOf(error)}`);
      err(command6.usage);
      return EXIT.usage;
    }
    if (optionFlag(values, "help")) {
      deps.stdout(`${command6.usage}

${COMMON_USAGE}`);
      return EXIT.ok;
    }
    const claims = await command6.build(values, deps);
    const space = spaceOf(values, deps);
    if (optionFlag(values, "dry-run")) {
      deps.stdout(JSON.stringify({ space: space ?? null, claims }, null, 2));
      return EXIT.ok;
    }
    return await deliver(command6, claims, space, deps);
  } catch (error) {
    if (error instanceof UsageError || error instanceof InvalidClaimError) {
      err(`${command6.name}: ${error.message}`);
      return EXIT.usage;
    }
    if (error instanceof SourceError) {
      err(`${command6.name}: ${error.message}`);
      return EXIT.failed;
    }
    err(`${command6.name}: unexpected error: ${messageOf(error)}`);
    return EXIT.failed;
  }
}
async function runFeeder(command6, argv, deps) {
  deps.exit(await execute(command6, argv, deps));
}

// src/feeders/github-release.ts
var DEFAULT_RELEASE_KEY = "kalibrate.release.version";
var USAGE = `Usage: kalibrate-feed-github-release [--event <file>] [--key <subject.fact>]... [--space <slug>] [--dry-run]

Writes the version of a published GitHub release as a keyed fact, one claim per --key, in one batch. Reads the
release event from --event, or from the file GITHUB_EVENT_PATH names (set by GitHub Actions). A bare release
object, as the releases API returns it, works too. In a GitLab tag pipeline, with no event file, it writes the
release of the pipeline's tag. The default key is ${DEFAULT_RELEASE_KEY}.`;
function text(source, field) {
  const value = source[field];
  if (typeof value !== "string" || value === "") {
    throw new UsageError(`the release has no ${field}`);
  }
  return value;
}
function parseReleaseEvent(payload, fallbackRepository) {
  const release = isRecord(payload) && isRecord(payload.release) ? payload.release : payload;
  if (!isRecord(release) || typeof release.tag_name !== "string") {
    throw new UsageError("the event file holds no release; expected a GitHub release event");
  }
  const rawId = release.id;
  if (typeof rawId !== "number" && typeof rawId !== "string" || String(rawId) === "") {
    throw new UsageError("the release has no id");
  }
  if (typeof release.published_at !== "string" || Number.isNaN(Date.parse(release.published_at))) {
    throw new UsageError("the release has no published_at; a draft release cannot be fed");
  }
  const fromPayload = isRecord(payload) && isRecord(payload.repository) && typeof payload.repository.full_name === "string" ? payload.repository.full_name : void 0;
  const repository = fromPayload ?? fallbackRepository;
  if (repository === void 0 || !/^[^/\s]+\/[^/\s]+$/.test(repository)) {
    throw new UsageError("cannot tell which repository the release belongs to; set GITHUB_REPOSITORY");
  }
  const tag = text(release, "tag_name");
  return {
    eventKey: `github:${repository}:release:${String(rawId)}:${tag}`,
    tag,
    url: text(release, "html_url"),
    prerelease: release.prerelease === true,
    publishedAt: release.published_at
  };
}
function parseGitlabTag(env) {
  const { CI_COMMIT_TAG: tag, CI_COMMIT_SHA: sha, CI_PROJECT_URL: project, CI_PIPELINE_CREATED_AT: createdAt } = env;
  if (tag === void 0 || tag === "") {
    throw new UsageError("not a tag pipeline: GitLab sets CI_COMMIT_TAG only in a pipeline for a tag");
  }
  if (sha === void 0 || project === void 0 || createdAt === void 0 || Number.isNaN(Date.parse(createdAt))) {
    throw new UsageError("the GitLab job has no CI_COMMIT_SHA, CI_PROJECT_URL or CI_PIPELINE_CREATED_AT");
  }
  return {
    eventKey: `gitlab:${project.replace(/^https?:\/\//, "")}:release:${sha}:${tag}`,
    tag,
    url: `${project}/-/releases/${encodeURIComponent(tag)}`,
    prerelease: /^v?\d+\.\d+\.\d+-/i.test(tag),
    publishedAt: createdAt
  };
}
function buildReleaseClaims(info, keys) {
  const version = info.tag.replace(/^v/i, "");
  if (version === "") {
    throw new UsageError("the release tag is empty after removing a leading v");
  }
  return keys.map((key) => ({
    key,
    claim: {
      value: { version, tag: info.tag, url: info.url, prerelease: info.prerelease },
      validFrom: info.publishedAt,
      sourceEventKey: info.eventKey,
      evidence: [{ url: info.url }]
    }
  }));
}
async function build(values, deps) {
  const keys = optionKeys(values, DEFAULT_RELEASE_KEY, DEFAULT_RELEASE_KEY);
  const path = optionString(values, "event") ?? deps.env.GITHUB_EVENT_PATH;
  if (path === void 0 || path === "") {
    if (deps.env.GITLAB_CI === "true") {
      return buildReleaseClaims(parseGitlabTag(deps.env), keys);
    }
    throw new UsageError("no event file: pass --event <file>, or run inside GitHub Actions (GITHUB_EVENT_PATH) or a GitLab tag pipeline");
  }
  let payload;
  try {
    payload = JSON.parse(await deps.readFile(path));
  } catch (error) {
    throw new UsageError(`cannot read the event file as JSON: ${messageOf(error)}`);
  }
  return buildReleaseClaims(parseReleaseEvent(payload, deps.env.GITHUB_REPOSITORY), keys);
}
var command = {
  name: "kalibrate-feed-github-release",
  usage: USAGE,
  options: { event: { type: "string" }, key: { type: "string", multiple: true } },
  build
};

// src/feeders/http-probe.ts
var PROBE_TIMEOUT_MS = 1e4;
var BODY_MAX_BYTES = 1048576;
var ERROR_MAX = 200;
var EXAMPLE_KEY = "api.health.status";
var DEFAULT_INTERVAL_S = 60;
var INTERVAL_MAX_S = 86400;
var USAGE2 = `Usage: kalibrate-feed-http-probe --url <url> --key <subject.fact>... [--expect-status 200] [--expect-body <regex>]
       [--interval <seconds>] [--space <slug>] [--dry-run]

Requests the URL with GET and writes { status, ok, matched } as a keyed fact, one claim per --key, in one batch.
This is the dead-man probe: a target that cannot be reached is written as ok: false, never skipped. The exit code
says whether the server took the claims, not whether the target is up; the verdict is in the fact. Runs inside one
--interval (default ${DEFAULT_INTERVAL_S} seconds) are one event. Only the first 1 MiB of the body is read.`;
function describeFetchError(error) {
  const cause = error instanceof Error && error.cause !== void 0 ? ` (${messageOf(error.cause)})` : "";
  return clip(`${messageOf(error)}${cause}`, ERROR_MAX);
}
async function readCapped(response, maxBytes) {
  const reader = response.body?.getReader();
  if (reader === void 0) {
    return "";
  }
  const decoder = new TextDecoder();
  let received = 0;
  let body = "";
  for (; ; ) {
    const chunk2 = await reader.read();
    if (chunk2.done) {
      break;
    }
    const room = maxBytes - received;
    const part = chunk2.value.byteLength > room ? chunk2.value.subarray(0, room) : chunk2.value;
    received += part.byteLength;
    body += decoder.decode(part, { stream: true });
    if (received >= maxBytes) {
      await reader.cancel();
      break;
    }
  }
  return body + decoder.decode();
}
async function runProbe(spec, deps) {
  let response;
  try {
    response = await deps.fetch(spec.url, {
      method: "GET",
      headers: { "User-Agent": `kalibrate-feeders/${deps.version}` },
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS)
    });
  } catch (error) {
    return { status: null, ok: false, matched: null, error: describeFetchError(error) };
  }
  let matched = null;
  try {
    if (spec.expectBody === void 0) {
      await response.body?.cancel();
    } else {
      matched = spec.expectBody.test(await readCapped(response, BODY_MAX_BYTES));
    }
  } catch (error) {
    return { status: response.status, ok: false, matched: null, error: describeFetchError(error) };
  }
  const ok = response.status === spec.expectStatus && matched !== false;
  return { status: response.status, ok, matched };
}
function intervalStart(at, intervalS) {
  const ms = intervalS * 1e3;
  return new Date(Math.floor(at.getTime() / ms) * ms).toISOString();
}
function buildProbeClaims(keys, spec, value, observedAt) {
  const at = intervalStart(observedAt, spec.intervalS);
  return keys.map((key) => ({
    key,
    claim: {
      value: { ...value },
      validFrom: observedAt.toISOString(),
      sourceEventKey: `probe:${key}:${at}`,
      evidence: [{ url: `${spec.url.origin}${spec.url.pathname}` }]
    }
  }));
}
function parseSpec(values) {
  const rawUrl = optionString(values, "url");
  if (rawUrl === void 0) {
    throw new UsageError("--url is required");
  }
  const keys = optionKeys(values, EXAMPLE_KEY);
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new UsageError("--url is not a valid URL");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new UsageError("--url must start with http:// or https://");
  }
  if (url.username !== "" || url.password !== "") {
    throw new UsageError("--url must not contain credentials");
  }
  const rawStatus = optionString(values, "expect-status") ?? "200";
  const expectStatus = Number(rawStatus);
  if (!Number.isInteger(expectStatus) || expectStatus < 100 || expectStatus > 599) {
    throw new UsageError("--expect-status must be an HTTP status between 100 and 599");
  }
  const rawInterval = optionString(values, "interval") ?? String(DEFAULT_INTERVAL_S);
  const intervalS = Number(rawInterval);
  if (!Number.isInteger(intervalS) || intervalS < 1 || intervalS > INTERVAL_MAX_S) {
    throw new UsageError(`--interval must be a whole number of seconds from 1 to ${INTERVAL_MAX_S}`);
  }
  const rawBody = optionString(values, "expect-body");
  let expectBody;
  if (rawBody !== void 0) {
    try {
      expectBody = new RegExp(rawBody);
    } catch {
      throw new UsageError("--expect-body is not a valid regular expression");
    }
  }
  return { keys, spec: expectBody === void 0 ? { url, expectStatus, intervalS } : { url, expectStatus, expectBody, intervalS } };
}
async function build2(values, deps) {
  const { keys, spec } = parseSpec(values);
  const observedAt = deps.now();
  return buildProbeClaims(keys, spec, await runProbe(spec, deps), observedAt);
}
var command2 = {
  name: "kalibrate-feed-http-probe",
  usage: USAGE2,
  options: {
    url: { type: "string" },
    key: { type: "string", multiple: true },
    "expect-status": { type: "string" },
    interval: { type: "string" },
    "expect-body": { type: "string" }
  },
  build: build2
};

// src/feeders/image-tag.ts
var FETCH_TIMEOUT_MS = 15e3;
var EXAMPLE_KEY2 = "api.image.digest";
var DOCKER_HUB = "docker.io";
var DOCKER_HUB_API = "registry-1.docker.io";
var MANIFEST_TYPES = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.docker.distribution.manifest.v2+json"
].join(", ");
var REGISTRY = /^(?:localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d{1,5})?$/;
var NAME = /^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:\/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*$/;
var TAG = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;
var DIGEST = /^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[A-Za-z0-9=_-]{32,256}$/;
var ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
var MAX_NAME_CHARS = 255;
var USAGE3 = `Usage: kalibrate-feed-image-tag --image <registry/name:tag> --key <subject.fact>... [--space <slug>] [--dry-run]
       kalibrate-feed-image-tag --registry <host> --repository <name> --tag <tag> --key <subject.fact>...

Writes the digest a tag points to in an OCI registry (GHCR, Docker Hub, ECR, ACR or any registry speaking the OCI
Distribution API) as a keyed fact, one claim per --key, in one batch. A name with no registry is on Docker Hub, and
a one-part Docker Hub name is an official image (nginx is docker.io/library/nginx). The tag defaults to latest.

Private registries:
  --username <name>        the registry user
  --password-env <NAME>    the environment variable that holds the registry password or token; never pass the
                           password itself as an argument. It is sent only to the registry and never printed.`;
function parseImage(image) {
  if (image.includes("@")) {
    throw new UsageError("--image names a tag, not a digest");
  }
  const slash = image.indexOf("/");
  const first = image.slice(0, Math.max(slash, 0));
  const hasRegistry = slash > 0 && (first.includes(".") || first.includes(":") || first === "localhost");
  const rest = hasRegistry ? image.slice(slash + 1) : image;
  const colon = rest.lastIndexOf(":");
  const tagged = colon > rest.lastIndexOf("/");
  return imageRef(hasRegistry ? first : DOCKER_HUB, tagged ? rest.slice(0, colon) : rest, tagged ? rest.slice(colon + 1) : "latest");
}
function imageRef(registry, name, tag) {
  const host = registry.toLowerCase() === "index.docker.io" ? DOCKER_HUB : registry.toLowerCase();
  if (!REGISTRY.test(host)) {
    throw new UsageError("the registry must be a host name, with a port if it needs one");
  }
  const full = host === DOCKER_HUB && !name.includes("/") ? `library/${name}` : name;
  if (!NAME.test(full) || full.length > MAX_NAME_CHARS) {
    throw new UsageError("the repository name must be lower-case path parts, for example owner/app");
  }
  if (!TAG.test(tag)) {
    throw new UsageError("the tag must be letters, digits, dots, dashes and underscores, at most 128 characters");
  }
  return { registry: host, name: full, tag };
}
function manifestUrl(ref) {
  return `https://${ref.registry === DOCKER_HUB ? DOCKER_HUB_API : ref.registry}/v2/${ref.name}/manifests/${ref.tag}`;
}
function tagPageUrl(ref) {
  if (ref.registry === "ghcr.io") {
    return `https://ghcr.io/${ref.name}`;
  }
  if (ref.registry === DOCKER_HUB) {
    const page = ref.name.startsWith("library/") ? `_/${ref.name.slice("library/".length)}` : `r/${ref.name}`;
    return `https://hub.docker.com/${page}/tags?name=${encodeURIComponent(ref.tag)}`;
  }
  return manifestUrl(ref);
}
function buildImageClaims(ref, digest, keys, observedAt) {
  const image = `${ref.registry}/${ref.name}`;
  return keys.map((key) => ({
    key,
    claim: {
      value: { image, tag: ref.tag, digest },
      validFrom: observedAt.toISOString(),
      sourceEventKey: `image:${image}:${ref.tag}@${digest}`,
      evidence: [{ url: tagPageUrl(ref) }]
    }
  }));
}
function parseChallenge(header) {
  const scheme = /^\s*(\S+)/.exec(header)?.[1]?.toLowerCase() ?? "";
  const params = {};
  for (const match of header.matchAll(/([A-Za-z]+)="([^"]*)"|([A-Za-z]+)=([^\s,"]+)/g)) {
    const name = (match[1] ?? match[3] ?? "").toLowerCase();
    params[name] = match[2] ?? match[4] ?? "";
  }
  return { scheme, params };
}
async function get(session, url, method, authorization) {
  const headers = { Accept: MANIFEST_TYPES, "User-Agent": `kalibrate-feeders/${session.deps.version}` };
  if (authorization !== void 0) {
    headers.Authorization = authorization;
  }
  return session.deps.fetch(url, { method, headers, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
}
function httpsUrl(text2) {
  try {
    const url = new URL(text2);
    return url.protocol === "https:" ? url : void 0;
  } catch {
    return void 0;
  }
}
async function answerChallenge(session, header) {
  const { registry, name } = session.ref;
  const { scheme, params } = parseChallenge(header);
  if (scheme === "basic") {
    if (session.basic === void 0) {
      throw new SourceError(`${registry} needs a login for ${name}: pass --username and --password-env`);
    }
    return session.basic;
  }
  const realm = scheme === "bearer" ? httpsUrl(params.realm ?? "") : void 0;
  if (realm === void 0) {
    throw new SourceError(`${registry} asked for a login this feeder cannot give: it follows basic auth or a token realm over https`);
  }
  realm.searchParams.set("scope", params.scope ?? `repository:${name}:pull`);
  if (params.service !== void 0) {
    realm.searchParams.set("service", params.service);
  }
  const response = await get(session, realm.href, "GET", session.basic);
  if (response.status !== 200) {
    const why2 = session.basic === void 0 ? "; a private image needs --username and --password-env" : "";
    throw new SourceError(`the token service of ${registry} answered ${response.status} for ${name}${why2}`);
  }
  const body = await response.json();
  const token = isRecord(body) ? body.token ?? body.access_token : void 0;
  if (typeof token !== "string" || token === "") {
    throw new SourceError(`the token service of ${registry} gave no token for ${name}`);
  }
  return `Bearer ${token}`;
}
async function readDigest(session) {
  const { ref } = session;
  const url = manifestUrl(ref);
  let authorization;
  let response = await get(session, url, "HEAD", authorization);
  if (response.status === 401) {
    authorization = await answerChallenge(session, response.headers.get("WWW-Authenticate") ?? "");
    response = await get(session, url, "HEAD", authorization);
  }
  if (response.status === 404) {
    throw new SourceError(`${ref.registry} has no tag ${ref.tag} for ${ref.name}`);
  }
  if (response.status !== 200) {
    throw new SourceError(`${ref.registry} answered ${response.status} for ${ref.name}:${ref.tag}`);
  }
  let digest = response.headers.get("Docker-Content-Digest") ?? "";
  if (digest === "") {
    const body = await get(session, url, "GET", authorization);
    if (body.status !== 200) {
      throw new SourceError(`${ref.registry} answered ${body.status} for the manifest of ${ref.name}:${ref.tag}`);
    }
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", await body.arrayBuffer()));
    digest = `sha256:${Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  }
  if (!DIGEST.test(digest)) {
    throw new SourceError(`${ref.registry} sent a digest that is not one for ${ref.name}:${ref.tag}`);
  }
  return digest;
}
function readRef(values) {
  const image = optionString(values, "image");
  const [registry, repository, tag] = ["registry", "repository", "tag"].map((name) => optionString(values, name));
  if (image !== void 0) {
    if (registry !== void 0 || repository !== void 0 || tag !== void 0) {
      throw new UsageError("pass --image, or --registry, --repository and --tag, not both");
    }
    return parseImage(image);
  }
  if (repository === void 0) {
    throw new UsageError("--image is required, for example --image ghcr.io/owner/app:v1.4.0");
  }
  return imageRef(registry ?? DOCKER_HUB, repository, tag ?? "latest");
}
function readLogin(values, deps) {
  const username = optionString(values, "username");
  const variable = optionString(values, "password-env");
  if (username === void 0 && variable === void 0) {
    return { basic: void 0, secrets: [] };
  }
  if (username === void 0 || variable === void 0) {
    throw new UsageError("--username and --password-env go together");
  }
  if (!ENV_NAME.test(variable)) {
    throw new UsageError("--password-env takes the name of an environment variable, not the password");
  }
  const password = deps.env[variable] ?? "";
  if (password === "") {
    throw new UsageError(`${variable} is not set`);
  }
  const encoded = btoa(String.fromCodePoint(...new TextEncoder().encode(`${username}:${password}`)));
  return { basic: `Basic ${encoded}`, secrets: [password, encoded] };
}
async function build3(values, deps) {
  const ref = readRef(values);
  const keys = optionKeys(values, EXAMPLE_KEY2);
  const { basic, secrets } = readLogin(values, deps);
  const observedAt = deps.now();
  let digest;
  try {
    digest = await readDigest({ ref, deps, basic });
  } catch (error) {
    const message = error instanceof SourceError ? error.message : `could not read ${ref.registry} for ${ref.name}:${ref.tag}: ${messageOf(error)}`;
    throw new SourceError(secrets.reduce((text2, secret) => redact(text2, secret), message));
  }
  return buildImageClaims(ref, digest, keys, observedAt);
}
var command3 = {
  name: "kalibrate-feed-image-tag",
  usage: USAGE3,
  options: {
    image: { type: "string" },
    registry: { type: "string" },
    repository: { type: "string" },
    tag: { type: "string" },
    username: { type: "string" },
    "password-env": { type: "string" },
    key: { type: "string", multiple: true }
  },
  build: build3
};

// src/feeders/npm-version.ts
var NPM_REGISTRY = "https://registry.npmjs.org";
var FETCH_TIMEOUT_MS2 = 15e3;
var PACKAGE_NAME = /^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*\/)?[A-Za-z0-9][A-Za-z0-9._~-]*$/;
var EXAMPLE_KEY3 = "web.sdk.version";
var USAGE4 = `Usage: kalibrate-feed-npm-version --package <name> --key <subject.fact>... [--space <slug>] [--dry-run]

Writes the version npm serves as "latest" for a package as a keyed fact, one claim per --key, in one batch. Reads
the public registry (${NPM_REGISTRY}); no npm credential is needed.`;
function packageUrl(name) {
  return `${NPM_REGISTRY}/${name.replace("/", "%2F")}`;
}
function readLatest(name, body) {
  const tags = isRecord(body) ? body["dist-tags"] : void 0;
  const version = isRecord(tags) ? tags.latest : void 0;
  if (typeof version !== "string" || version === "" || version.length > 100) {
    throw new SourceError(`the npm registry document for ${name} has no latest version`);
  }
  const times = isRecord(body) ? body.time : void 0;
  const published = isRecord(times) ? times[version] : void 0;
  const publishedAt = typeof published === "string" && !Number.isNaN(Date.parse(published)) ? new Date(published).toISOString() : null;
  return { version, publishedAt };
}
function buildNpmClaims(name, latest, keys, observedAt) {
  const event = `npm:${name}:${latest.version}${latest.publishedAt === null ? "" : `:${latest.publishedAt}`}`;
  return keys.map((key) => ({
    key,
    claim: {
      value: { package: name, version: latest.version },
      validFrom: observedAt.toISOString(),
      sourceEventKey: event,
      evidence: [{ url: `${packageUrl(name)}/${encodeURIComponent(latest.version)}` }]
    }
  }));
}
async function build4(values, deps) {
  const name = optionString(values, "package");
  if (name === void 0) {
    throw new UsageError("--package is required");
  }
  if (!PACKAGE_NAME.test(name)) {
    throw new UsageError("--package is not a valid npm package name");
  }
  const keys = optionKeys(values, EXAMPLE_KEY3);
  const observedAt = deps.now();
  let body;
  try {
    const response = await deps.fetch(packageUrl(name), {
      headers: { Accept: "application/json", "User-Agent": `kalibrate-feeders/${deps.version}` },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS2)
    });
    if (response.status !== 200) {
      throw new SourceError(`the npm registry answered ${response.status} for ${name}`);
    }
    body = await response.json();
  } catch (error) {
    if (error instanceof SourceError) {
      throw error;
    }
    throw new SourceError(`could not read the npm registry for ${name}: ${messageOf(error)}`);
  }
  return buildNpmClaims(name, readLatest(name, body), keys, observedAt);
}
var command4 = {
  name: "kalibrate-feed-npm-version",
  usage: USAGE4,
  options: { package: { type: "string" }, key: { type: "string", multiple: true } },
  build: build4
};

// src/feeders/pypi-version.ts
var PYPI_URL = "https://pypi.org";
var FETCH_TIMEOUT_MS3 = 15e3;
var PROJECT_NAME = /^(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$/;
var EXAMPLE_KEY4 = "web.sdk.version";
var USAGE5 = `Usage: kalibrate-feed-pypi-version --package <project> --key <subject.fact>... [--space <slug>] [--dry-run]

Writes the version PyPI serves as the latest for a project as a keyed fact, one claim per --key, in one batch. Reads
the public index (${PYPI_URL}); no PyPI credential is needed. A private index (Artifactory, CodeArtifact, Azure
Artifacts) is not supported.`;
function normalizeProject(name) {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}
function projectUrl(project) {
  return `${PYPI_URL}/pypi/${project}/json`;
}
function releaseUrl(project, version) {
  return `${PYPI_URL}/project/${project}/${encodeURIComponent(version)}/`;
}
function readLatest2(project, body) {
  const info = isRecord(body) ? body.info : void 0;
  const version = isRecord(info) ? info.version : void 0;
  if (typeof version !== "string" || version === "" || version.length > 100) {
    throw new SourceError(`the PyPI document for ${project} has no latest version`);
  }
  const releases = isRecord(body) ? body.releases : void 0;
  const files = isRecord(releases) ? releases[version] : void 0;
  const first = Array.isArray(files) ? files[0] : void 0;
  const uploaded = isRecord(first) ? first.upload_time_iso_8601 : void 0;
  const publishedAt = typeof uploaded === "string" && !Number.isNaN(Date.parse(uploaded)) ? new Date(uploaded).toISOString() : null;
  return { version, publishedAt };
}
function buildPypiClaims(project, latest, keys, observedAt) {
  const event = `pypi:${project}:${latest.version}${latest.publishedAt === null ? "" : `:${latest.publishedAt}`}`;
  return keys.map((key) => ({
    key,
    claim: {
      value: { package: project, version: latest.version },
      validFrom: observedAt.toISOString(),
      sourceEventKey: event,
      evidence: [{ url: releaseUrl(project, latest.version) }]
    }
  }));
}
async function build5(values, deps) {
  const given = optionString(values, "package");
  if (given === void 0) {
    throw new UsageError("--package is required");
  }
  if (!PROJECT_NAME.test(given)) {
    throw new UsageError("--package is not a valid PyPI project name");
  }
  const project = normalizeProject(given);
  const keys = optionKeys(values, EXAMPLE_KEY4);
  const observedAt = deps.now();
  let body;
  try {
    const response = await deps.fetch(projectUrl(project), {
      headers: { Accept: "application/json", "User-Agent": `kalibrate-feeders/${deps.version}` },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS3)
    });
    if (response.status !== 200) {
      throw new SourceError(`PyPI answered ${response.status} for ${project}`);
    }
    body = await response.json();
  } catch (error) {
    if (error instanceof SourceError) {
      throw error;
    }
    throw new SourceError(`could not read PyPI for ${project}: ${messageOf(error)}`);
  }
  return buildPypiClaims(project, readLatest2(project, body), keys, observedAt);
}
var command5 = {
  name: "kalibrate-feed-pypi-version",
  usage: USAGE5,
  options: { package: { type: "string" }, key: { type: "string", multiple: true } },
  build: build5
};

// src/cli/action.ts
var FEEDERS = {
  "github-release": { command, flags: [] },
  "npm-version": { command: command4, flags: ["package"] },
  "pypi-version": { command: command5, flags: ["package"] },
  "http-probe": { command: command2, flags: ["url", "expect-status", "expect-body", "interval"] },
  "image-tag": { command: command3, flags: ["image"] }
};
var REGISTRY_PASSWORD_ENV = "KALIBRATE_REGISTRY_PASSWORD";
var ActionInputError = class extends Error {
};
function input(env, name) {
  return env[`INPUT_${name.toUpperCase()}`]?.trim() ?? "";
}
function parseInputs(env) {
  const name = input(env, "feeder");
  const feeder = Object.hasOwn(FEEDERS, name) ? FEEDERS[name] : void 0;
  if (feeder === void 0) {
    throw new ActionInputError(`feeder must be one of ${Object.keys(FEEDERS).join(", ")}`);
  }
  const missing = ["token", "server-url", "space", "key"].filter((field) => input(env, field) === "");
  if (missing.length > 0) {
    throw new ActionInputError(`missing input: ${missing.join(", ")}`);
  }
  const argv = [`--key=${input(env, "key")}`];
  for (const flag of feeder.flags) {
    const value = input(env, flag);
    if (value !== "") {
      argv.push(`--${flag}=${value}`);
    }
  }
  const username = input(env, "registry-username");
  const password = feeder.command === command3 ? input(env, "registry-password") : "";
  if (feeder.command === command3 && username === "" !== (password === "")) {
    throw new ActionInputError("registry-username and registry-password go together");
  }
  if (password !== "") {
    argv.push(`--username=${username}`, `--password-env=${REGISTRY_PASSWORD_ENV}`);
  }
  return {
    command: feeder.command,
    argv,
    env: {
      ...env,
      KALIBRATE_URL: input(env, "server-url"),
      KALIBRATE_FEEDER_TOKEN: input(env, "token"),
      KALIBRATE_SPACE: input(env, "space"),
      [REGISTRY_PASSWORD_ENV]: password === "" ? void 0 : password,
      // The token never goes over plain http to a remote host, whatever the workflow's own env says.
      KALIBRATE_ALLOW_INSECURE_HTTP: void 0
    }
  };
}
async function checkReleaseEvent(deps) {
  const { GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_REPOSITORY } = deps.env;
  if (GITHUB_EVENT_NAME !== "release" || GITHUB_EVENT_PATH === void 0 || GITHUB_REPOSITORY === void 0) {
    throw new ActionInputError("feeder github-release runs only in a workflow started by a release event (on: release: types: [published])");
  }
  let event;
  try {
    event = JSON.parse(await deps.readFile(GITHUB_EVENT_PATH));
  } catch (error) {
    throw new ActionInputError(`cannot read the release event: ${messageOf(error)}`);
  }
  const repository = isRecord(event) && isRecord(event.repository) ? event.repository.full_name : void 0;
  if (repository !== GITHUB_REPOSITORY) {
    throw new ActionInputError(`the release event belongs to ${String(repository)}, not ${GITHUB_REPOSITORY}`);
  }
  if (!isRecord(event) || !isRecord(event.release) || event.release.draft !== false) {
    throw new ActionInputError("the release is a draft; feed it once it is published");
  }
  const { tag_name: tag, html_url: page } = event.release;
  const releases = `${(deps.env.GITHUB_SERVER_URL ?? "https://github.com").replace(/\/+$/, "")}/${GITHUB_REPOSITORY}/releases/tag/`;
  if (typeof tag !== "string" || typeof page !== "string" || page !== releases + encodeURIComponent(tag) && page !== releases + encodeURI(tag)) {
    throw new ActionInputError(`the release page is not ${releases}<tag>; nothing was sent`);
  }
}
function logLine(line) {
  return line.replace(CONTROL_CHARS, " ").replaceAll("##[", "# #[");
}
async function runAction(deps) {
  const secrets = [input(deps.env, "token"), input(deps.env, "registry-password")];
  for (const piece of secrets.join(" ").split(/\s+/)) {
    if (piece !== "") {
      deps.stdout(`::add-mask::${piece}`);
    }
  }
  const resume = randomUUID();
  deps.stdout(`::stop-commands::${resume}`);
  let code = EXIT.usage;
  try {
    const run = parseInputs(deps.env);
    if (run.command === command) {
      await checkReleaseEvent(deps);
    }
    const exit = (feederCode) => {
      code = feederCode;
    };
    const stdout = (line) => deps.stdout(logLine(line));
    const stderr = (line) => deps.stderr(logLine(line));
    await runFeeder(run.command, run.argv, { ...deps, env: run.env, exit, stdout, stderr });
  } catch (error) {
    const message = error instanceof ActionInputError ? error.message : `unexpected error: ${messageOf(error)}`;
    deps.stderr(logLine(`koalafix: ${secrets.reduce((text2, secret) => redact(text2, secret), message)}`));
  } finally {
    deps.stdout(`::${resume}::`);
  }
  deps.exit(code);
}

// src/cli/node-deps.ts
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
function readVersion() {
  try {
    const pkg = createRequire(import.meta.url)("../../package.json");
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
}
function nodeDeps() {
  return {
    env: process.env,
    fetch: globalThis.fetch,
    now: () => /* @__PURE__ */ new Date(),
    sleep: (ms) => new Promise((resolve) => {
      setTimeout(resolve, ms);
    }),
    stdout: (line) => {
      process.stdout.write(`${line}
`);
    },
    stderr: (line) => {
      process.stderr.write(`${line}
`);
    },
    // exitCode, not exit(): lets pending output flush.
    exit: (code) => {
      process.exitCode = code;
    },
    readFile: (path) => readFile(path, "utf8"),
    version: readVersion()
  };
}

// src/action.ts
await runAction(nodeDeps());
