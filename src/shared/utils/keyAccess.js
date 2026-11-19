// Per-API-key access control: pure helpers (no DB, no
// request objects), shared by the DB repo, the API routes and the engine.
import { RE2JS } from "re2js";
import {
  KEY_ACCESS_MAX_ENTRIES,
  KEY_ACCESS_MAX_ENTRY_LENGTH,
  KEY_ACCESS_UNRESTRICTED,
} from "@/shared/constants/keyAccess.js";

/**
 * Normalize an allow list: keep strings only, trim, drop empties, de-duplicate
 * case-insensitively (the first spelling wins). Order is preserved.
 */
export function normalizeAllowList(list) {
  if (!Array.isArray(list)) return [];
  const seen = new Set();
  const out = [];
  for (const item of list) {
    if (typeof item !== "string") continue;
    const entry = item.trim();
    if (!entry) continue;
    const k = entry.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(entry);
  }
  return out;
}

export function compileModelPattern(pattern) {
  if (typeof pattern !== "string" || !pattern.trim() || pattern.length > KEY_ACCESS_MAX_ENTRY_LENGTH) return null;
  try {
    return RE2JS.compile(pattern, RE2JS.CASE_INSENSITIVE);
  } catch {
    return null;
  }
}

/**
 * Build the access object from the two apiKeys columns.
 *
 * Fails CLOSED: the restricted flag has its own INTEGER column, so a corrupt or
 * unparsable allow list can only ever shrink what a restricted key may call
 * (to nothing); it can never turn a restricted key into an unrestricted one.
 */
export function keyAccessFromColumns(restrictedCol, allowCol) {
  const restricted = restrictedCol === 1 || restrictedCol === true;
  if (!restricted) return { restricted: false, allow: [] };
  let parsed = [];
  if (typeof allowCol === "string" && allowCol) {
    try { parsed = JSON.parse(allowCol); } catch { parsed = []; }
  }
  const access = { restricted: true, allow: normalizeAllowList(parsed) };
  // Tagged entries share the existing JSON column without reinterpreting
  // any exact model or combo names stored by older versions.
  const patterns = Array.isArray(parsed)
    ? parsed.map((entry) => entry?.modelPattern).filter((pattern) => typeof pattern === "string")
    : [];
  if (patterns.length) access.modelPatterns = [...new Set(patterns)];
  return access;
}

/** Columns to persist for an access object (already validated/normalized). */
export function keyAccessToColumns(access) {
  const value = access || KEY_ACCESS_UNRESTRICTED;
  const entries = value.restricted ? normalizeAllowList(value.allow) : [];
  if (value.restricted && value.modelPatterns) {
    entries.push(...value.modelPatterns.map((modelPattern) => ({ modelPattern })));
  }
  return {
    accessRestricted: value.restricted ? 1 : 0,
    accessAllow: JSON.stringify(entries),
  };
}

/**
 * Validate client input for an access update ({ restricted, allow, modelPatterns }).
 * Rejects rather than repairs: wrong types, too many entries, overlong entries.
 * @returns {{ ok: true, value: {restricted: boolean, allow: string[], modelPatterns?: string[]} } | { ok: false, error: string }}
 */
export function validateKeyAccessInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, error: "access must be an object { restricted, allow, modelPatterns }" };
  }
  const extra = Object.keys(input).filter((k) => !["restricted", "allow", "modelPatterns"].includes(k));
  if (extra.length) return { ok: false, error: `access: unexpected field(s) ${extra.join(", ")}` };
  if (typeof input.restricted !== "boolean") {
    return { ok: false, error: "access.restricted must be a boolean" };
  }
  const allow = input.allow === undefined ? [] : input.allow;
  if (!Array.isArray(allow) || allow.some((e) => typeof e !== "string")) {
    return { ok: false, error: "access.allow must be an array of strings" };
  }
  const patterns = input.modelPatterns === undefined ? [] : input.modelPatterns;
  if (!Array.isArray(patterns) || patterns.some((pattern) => typeof pattern !== "string")) {
    return { ok: false, error: "access.modelPatterns must be an array of strings" };
  }
  if (allow.length + patterns.length > KEY_ACCESS_MAX_ENTRIES) {
    return { ok: false, error: `Use at most ${KEY_ACCESS_MAX_ENTRIES} allowed entries per key.` };
  }
  if (allow.some((e) => e.trim().length > KEY_ACCESS_MAX_ENTRY_LENGTH)) {
    return { ok: false, error: `access.allow entries must be at most ${KEY_ACCESS_MAX_ENTRY_LENGTH} characters` };
  }
  const modelPatterns = [...new Set(patterns.map((pattern) => pattern.trim()))];
  if (modelPatterns.some((pattern) => pattern.length > KEY_ACCESS_MAX_ENTRY_LENGTH)) {
    return { ok: false, error: `Model regexes must be at most ${KEY_ACCESS_MAX_ENTRY_LENGTH} characters.` };
  }
  if (modelPatterns.some((pattern) => !compileModelPattern(pattern))) {
    return { ok: false, error: "Enter a valid RE2 model regex." };
  }
  const value = { restricted: input.restricted, allow: normalizeAllowList(allow) };
  if (modelPatterns.length) value.modelPatterns = modelPatterns;
  return { ok: true, value };
}
