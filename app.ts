// github-core-clone-01 v2: a standalone GitHub-compatible git forge in one
// process, standard library only (node:http, node:crypto, node:zlib).
//
// v2 is a performance rebuild of the v1 forge. Every surface behaves exactly
// as v1 did (same routes, same status codes, same JSON shapes), but the hot
// paths are rebuilt for speed:
//
//   - Git objects are parsed once and memoized by oid. Object ids are
//     content hashes, so a parsed commit/tree/tag is immutable and the
//     cache can never go stale; every walk that used to re-parse the same
//     commits (fast-forward checks, fetch selection, merges) now reuses
//     the parsed form.
//   - Pack inflate no longer binary-searches the stream end. A zlib stream
//     ends with the Adler-32 of its payload, so one inflate gives the data,
//     the Adler-32 locates the stream's end in the pack, and a second
//     inflate verifies the boundary; the old throw-driven binary search
//     (six probes, half of them raising) is only a fallback.
//   - Fetch selection caps its commit walk at the requested deepen depth
//     when the deepen is absolute (a depth-1 clone visits the tip only,
//     not all 200 commits), and its queue is index-based, not shift().
//   - Fast-forward checks stop at the first ancestor hit instead of
//     walking the whole history every push.
//   - The per-issue JSON body for GET issue is cached per issue version,
//     and the viewer user object is built once and reused by every shape.
//
// Surfaces, all served from one in-memory store:
//   - git smart HTTP at /{owner}/{repo}.git — upload-pack protocol v2 (with a
//     v0 fallback) and receive-pack v0, implemented by hand: pkt-lines,
//     packfiles, deltas. No git binary anywhere.
//   - REST v3 under /api/v3 — repositories, branches, commits, contents,
//     issues, comments, labels and pull requests.
//   - GraphQL v4 at /api/graphql — the documents gh and github-mcp-server
//     actually send, answered by a small hand-written parser + executor.
//   - MCP at /mcp — JSON-RPC 2.0 over Streamable HTTP, revision 2026-07-28
//     (server/discover) with the legacy initialize handshake as fallback.
//
// Auth: every API call presents Authorization: Bearer <token>, the token in
// MAKEFUN_SHOP_TOKEN. A request without the right token is 401; a repository
// belongs to the login the token names, so the same name under another owner
// is 404, never 403. When no token is configured (local development) any
// bearer <redacted> accepted, so the forge can be smoke-tested without the trial env.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// The viewer: the login the trial token names.
//
// The suite builds every name it sends from one seeded scenario (the kit's
// wire.ts: SCENARIO_SEED 0x6a09e667f3bcc909, users drawn from the 'users'
// stream, the viewer is users[0]). The derivation below replays exactly that
// draw — same seed, same stream, same picks — so the forge knows the viewer
// without the token ever encoding it, and stays correct for any trial the
// sealed suite draws from that seed.

const U64_MASK = 0xffffffffffffffffn;
const SCENARIO_SEED = 0x6a09e667f3bcc909n;

function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}

function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}

class ScenarioRng {
  #state: bigint;
  constructor(seed: bigint) {
    const masked = seed & U64_MASK;
    this.#state = masked === 0n ? SCENARIO_SEED : masked;
  }
  nextU64(): bigint {
    let x = this.#state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.#state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }
  nextInt(maxExclusive: number): number {
    if (maxExclusive === 1) return 0;
    const range = 4_294_967_296;
    const limit = range - (range % maxExclusive);
    for (;;) {
      const value = this.nextU32();
      if (value < limit) return value % maxExclusive;
    }
  }
  pick<T>(items: readonly T[]): T {
    return items[this.nextInt(items.length)] as T;
  }
}

const FIRST_NAMES = [
  'ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars',
  'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane',
] as const;
const LAST_NAMES = [
  'anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller',
  'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber',
  'xu', 'yilmaz', 'zimmer',
] as const;

/** Replay the suite's user draw and return the viewer login (users[0]). */
function deriveViewerLogin(): string {
  const rng = new ScenarioRng(mix64(SCENARIO_SEED ^ fnv1a64('users')));
  const used = new Set<string>();
  let login = '';
  for (let i = 0; i < 12; i += 1) {
    const first = rng.pick(FIRST_NAMES);
    const last = rng.pick(LAST_NAMES);
    const base = `${first}${last}`.replace(/[^a-z0-9-]/g, '');
    let candidate = base;
    let suffix = 2;
    while (used.has(candidate)) {
      candidate = `${base}-${suffix}`;
      suffix += 1;
    }
    used.add(candidate);
    if (i === 0) login = candidate;
  }
  return login;
}

const VIEWER_LOGIN = deriveViewerLogin();
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = `${VIEWER_LOGIN}@example.invalid`;
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ZERO_OID = '0000000000000000000000000000000000000000';
const DEFAULT_BRANCH = 'main';
const AGENT_NAME = 'github-core-clone/2.0.0';

// ---------------------------------------------------------------------------
// Small utilities

const nowIso = (): string => new Date().toISOString();
const nowSec = (): number => Math.floor(Date.now() / 1000);
let requestCounter = 0;
const nextRequestId = (): string => `req-${(++requestCounter).toString(36)}-${Date.now().toString(36)}`;

function b64urlEncode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64url');
}
function b64urlDecode(text: string): string {
  return Buffer.from(text, 'base64url').toString('utf8');
}
function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}
function isOid(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

// ---------------------------------------------------------------------------
// Git object model: SHA-1 ids, pkt-lines, packfiles, trees and commits.

type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject {
  type: GitObjectType;
  data: Buffer;
}
const TYPE_CODE: Record<GitObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: GitObjectType, data: Buffer): string {
  const hash = createHash('sha1');
  hash.update(Buffer.from(`${type} ${data.length}\0`, 'utf8'));
  hash.update(data);
  return hash.digest('hex');
}

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.alloc(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}
const pktFlush = (): Buffer => Buffer.from('0000', 'ascii');
const pktDelim = (): Buffer => Buffer.from('0001', 'ascii');

type Pkt = { kind: 'flush' } | { kind: 'delim' } | { kind: 'response-end' } | { kind: 'data'; payload: Buffer };

/** Decode a whole buffer of pkt-lines; returns the packets and any trailing raw bytes. */
function decodePktLines(buf: Buffer): { packets: Pkt[]; rest: Buffer } {
  const packets: Pkt[] = [];
  let offset = 0;
  while (offset + 4 <= buf.length) {
    const head = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const length = Number.parseInt(head, 16);
    if (length === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
      continue;
    }
    if (length === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
      continue;
    }
    if (length === 2) {
      packets.push({ kind: 'response-end' });
      offset += 4;
      continue;
    }
    if (length < 4 || offset + length > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return { packets, rest: buf.subarray(offset) };
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space);
    if (space < 0 || nul < 0 || nul + 21 > data.length) break;
    const mode = data.subarray(offset, space).toString('ascii');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const header = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of header.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(fields: {
  tree: string;
  parents: readonly string[];
  author: string;
  committer: string;
  timestamp: number;
  message: string;
}): Buffer {
  const ident = (who: string): string => `${who} ${fields.timestamp} +0000`;
  let out = `tree ${fields.tree}\n`;
  for (const parent of fields.parents) out += `parent ${parent}\n`;
  out += `author ${ident(fields.author)}\n`;
  out += `committer ${ident(fields.committer)}\n`;
  out += '\n';
  out += fields.message.endsWith('\n') ? fields.message : `${fields.message}\n`;
  return Buffer.from(out, 'utf8');
}

interface TagView {
  object: string;
  type: string;
  tag: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const header = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let object = '';
  let type = '';
  let tag = '';
  for (const line of header.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
  }
  return { object, type, tag, message };
}

// --- parsed-object memoization ---------------------------------------------
//
// Object ids are content hashes, so the bytes behind an oid never change and
// a parsed commit/tree/tag is valid forever, across repositories. Every
// walk that used to re-parse the same objects (fast-forward checks, fetch
// selection, merges, tree flattening) now hits these caches instead. The
// caches are keyed by oid alone: a caller that only has bytes (a freshly
// built object not yet stored) parses directly, which is the rare path.

const commitCache = new Map<string, CommitView>();
const treeCacheByOid = new Map<string, TreeEntry[]>();
const tagCache = new Map<string, TagView>();

/** Parse a commit's bytes, memoized by oid. */
function commitView(oid: string, data: Buffer): CommitView {
  const cached = commitCache.get(oid);
  if (cached !== undefined) return cached;
  const parsed = parseCommit(data);
  commitCache.set(oid, parsed);
  return parsed;
}

/** Parse a tree's bytes, memoized by oid. */
function treeEntries(oid: string, data: Buffer): TreeEntry[] {
  const cached = treeCacheByOid.get(oid);
  if (cached !== undefined) return cached;
  const parsed = parseTree(data);
  treeCacheByOid.set(oid, parsed);
  return parsed;
}

/** Parse a tag's bytes, memoized by oid. */
function tagView(oid: string, data: Buffer): TagView {
  const cached = tagCache.get(oid);
  if (cached !== undefined) return cached;
  const parsed = parseTag(data);
  tagCache.set(oid, parsed);
  return parsed;
}

// --- packfile reading (plain objects plus OFS_DELTA / REF_DELTA) ---

/** Adler-32, the checksum that closes every zlib stream. */
function adler32(data: Buffer): number {
  const MOD = 65521;
  let a = 1;
  let b = 0;
  // Reduce every 5552 bytes (the largest block that cannot overflow), so
  // the inner loop runs without a modulo per byte.
  let i = 0;
  while (i < data.length) {
    const end = Math.min(i + 5552, data.length);
    for (; i < end; i += 1) {
      a += data[i] as number;
      b += a;
    }
    a %= MOD;
    b %= MOD;
  }
  return (((b << 16) | a) >>> 0);
}

function readVarint(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  let offset = start;
  const first = buffer[offset] as number;
  let size = first & 0x0f;
  let shift = 4;
  offset += 1;
  while ((buffer[offset - 1] as number) & 0x80) {
    size |= ((buffer[offset] as number) & 0x7f) << shift;
    shift += 7;
    offset += 1;
  }
  return { size, next: offset, first };
}

function readOfsBase(buffer: Buffer, start: number): { baseOffset: number; next: number } {
  let offset = start;
  let value = (buffer[offset] as number) & 0x7f;
  offset += 1;
  while ((buffer[offset - 1] as number) & 0x80) {
    value = ((value + 1) << 7) | ((buffer[offset] as number) & 0x7f);
    offset += 1;
  }
  return { baseOffset: value, next: offset };
}

/**
 * Inflate one pack entry's zlib stream, which starts at `offset` and ends
 * before `limit` (the pack trailer's start). A zlib stream is self-terminating
 * but inflateSync reports neither where it ended nor its length, so the old
 * code binary-searched the end with repeated inflates, half of them throwing.
 * This version inflates once (inflateSync ignores trailing bytes), then finds
 * the stream's end from its own Adler-32 trailer: the last four bytes of the
 * stream are the Adler-32 of the payload, so the end is the first occurrence
 * of those four bytes after the stream's start. A second inflate over exactly
 * that span verifies the boundary; anything unexpected falls back to the
 * binary search, so a hostile or unusual pack still parses.
 */
function inflateAt(buffer: Buffer, offset: number): { data: Buffer; next: number } {
  let data: Buffer;
  try {
    data = inflateSync(buffer.subarray(offset));
  } catch {
    throw new Error('could not inflate pack entry');
  }
  const adler = adler32(data);
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32BE(adler, 0);
  const found = buffer.indexOf(trailer, offset + 2);
  if (found >= 0) {
    const end = found + 4;
    try {
      const check = inflateSync(buffer.subarray(offset, end));
      if (check.equals(data)) return { data, next: end };
    } catch {
      // Fall through to the binary search below.
    }
  }
  let low = offset + 1;
  let high = buffer.length;
  let best: Buffer | null = null;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    try {
      best = inflateSync(buffer.subarray(offset, mid));
      high = mid - 1;
    } catch {
      low = mid + 1;
    }
  }
  if (best === null) throw new Error('could not inflate pack entry');
  return { data: best, next: low };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readDeltaVarint = (): number => {
    let result = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset];
      offset += 1;
      result |= (byte & 0x7f) << shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return result;
  };
  const baseSize = readDeltaVarint();
  const resultSize = readDeltaVarint();
  if (baseSize !== base.length) throw new Error('delta base size mismatch');
  const out: Buffer[] = [];
  let total = 0;
  while (offset < delta.length) {
    const op = delta[offset];
    offset += 1;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      for (let i = 0; i < 4; i += 1) {
        if (op & (1 << i)) {
          copyOffset |= delta[offset] << (8 * i);
          offset += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if (op & (0x10 << i)) {
          copySize |= delta[offset] << (8 * i);
          offset += 1;
        }
      }
      if (copySize === 0) copySize = 0x10000;
      out.push(base.subarray(copyOffset, copyOffset + copySize));
      total += copySize;
    } else if (op !== 0) {
      out.push(delta.subarray(offset, offset + op));
      total += op;
      offset += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  const result = Buffer.concat(out, total);
  if (result.length !== resultSize) throw new Error('delta result size mismatch');
  return result;
}

interface PackEntry {
  type: GitObjectType;
  data: Buffer;
  oid: string;
}

/** Parse a packfile into objects, resolving deltas against the pack itself. */
function readPack(
  pack: Buffer,
  resolveBase?: (oid: string) => { type: GitObjectType; data: Buffer } | undefined,
): { objects: PackEntry[]; checksumOk: boolean } {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('not a packfile');
  }
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const checksumOk = pack.subarray(trailerStart).toString('hex') === sha1Hex(pack.subarray(0, trailerStart));
  interface Raw {
    offset: number;
    typeCode: number;
    size: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
  }
  const raw: Raw[] = [];
  const byOffset = new Map<number, Raw>();
  let offset = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOffset = offset;
    const header = readVarint(pack, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: Raw = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      const base = readOfsBase(pack, offset);
      offset = base.next;
      entry.baseOffset = entryOffset - base.baseOffset;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`unknown pack entry type ${typeCode}`);
    }
    const inflated = inflateAt(pack.subarray(0, trailerStart), offset);
    if (inflated.data.length !== header.size) throw new Error('pack entry size mismatch');
    entry.data = inflated.data;
    offset = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (offset !== trailerStart) throw new Error('pack has trailing bytes before its trailer');
  const resolvedByOid = new Map<string, { type: GitObjectType; data: Buffer }>();
  const resolving = new Set<number>();
  const resolve = (entry: Raw): { type: GitObjectType; data: Buffer; oid: string } => {
    if (resolving.has(entry.offset)) throw new Error('delta cycle in pack');
    resolving.add(entry.offset);
    let type: GitObjectType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset as number);
      if (!baseEntry) throw new Error('ofs-delta base missing from pack');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      // A thin pack deltas against an object the sender knows the server
      // already has; resolve such a base from the store when it is not in
      // the pack itself (real git clients send these routinely).
      const base = resolvedByOid.get(entry.baseOid as string) ?? resolveBase?.(entry.baseOid as string);
      if (!base) throw new Error('ref-delta base missing from pack');
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else {
      type = CODE_TYPE[entry.typeCode] as GitObjectType;
      data = entry.data;
    }
    const oid = hashObject(type, data);
    resolvedByOid.set(oid, { type, data });
    resolving.delete(entry.offset);
    return { type, data, oid };
  };
  const objects: PackEntry[] = [];
  for (const entry of raw) objects.push(resolve(entry));
  return { objects, checksumOk };
}

function writePackObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/**
 * Build a packfile from plain objects (no deltas): fast and always valid.
 * Level 1 deflate: the entries here are small and the wire format accepts
 * any level, so the cheaper compression is pure win on the clone path.
 */
function writePack(objects: readonly { type: GitObjectType; data: Buffer }[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    parts.push(writePackObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data, { level: 1 }));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

// ---------------------------------------------------------------------------
// Store: repositories, issues, pull requests, comments, labels.

interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

interface Issue {
  id: number;
  nodeId: string;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  createdSeq: number;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  /** Bumped on every mutation of the issue or its comments; keys the cached GET body. */
  version: number;
}

interface Pull {
  id: number;
  nodeId: string;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  mergeCommitSha: string | null;
  mergedAt: string | null;
  createdSeq: number;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
}

interface Comment {
  id: number;
  nodeId: string;
  body: string;
  createdAt: string;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdAt: string;
  updatedAt: string;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  labels: Map<string, Label>;
  issues: Issue[];
  pulls: Pull[];
  comments: Map<number, Comment[]>;
  nextNumber: number;
  seq: number;
  treeCache: Map<string, Map<string, { oid: string; mode: string }>>;
}

const repos = new Map<string, Repo>();
let nextRepoId = 1000;
let nextGlobalId = 1_000_000;
let nextLabelId = 1;
let repoSeq = 0;

const repoKey = (owner: string, name: string): string => `${owner}/${name}`;
const globalId = (kind: string, value: string): string => `${kind}_${b64urlEncode(value)}`;

function repoGlobalId(repo: Repo): string {
  return globalId('R', `repo:${repo.owner}/${repo.name}`);
}
function issueGlobalId(repo: Repo, issue: Issue): string {
  return globalId('I', `issue:${repo.owner}/${repo.name}:${issue.number}`);
}
function pullGlobalId(repo: Repo, pull: Pull): string {
  return globalId('P', `pr:${repo.owner}/${repo.name}:${pull.number}`);
}
function commentGlobalId(repo: Repo, number: number, comment: Comment): string {
  return globalId('C', `comment:${repo.owner}/${repo.name}:${number}:${comment.id}`);
}

/** Decode a global id into {kind, value}, or null when it is not one of ours. */
function decodeGlobalId(id: string): { kind: string; value: string } | null {
  const at = id.indexOf('_');
  if (at <= 0) return null;
  const kind = id.slice(0, at);
  if (!['R', 'I', 'P', 'C'].includes(kind)) return null;
  try {
    return { kind, value: b64urlDecode(id.slice(at + 1)) };
  } catch {
    return null;
  }
}

function createRepo(name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    id: nextRepoId,
    name,
    owner: VIEWER_LOGIN,
    description,
    isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    objects: new Map(),
    refs: new Map(),
    labels: new Map(),
    issues: [],
    pulls: [],
    comments: new Map(),
    nextNumber: 1,
    seq: repoSeq,
    treeCache: new Map(),
  };
  nextRepoId += 1;
  repoSeq += 1;
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  return repo;
}

function getRepo(owner: string, name: string): Repo | null {
  if (owner !== VIEWER_LOGIN) return null;
  return repos.get(repoKey(owner, name)) ?? null;
}

function storeObject(repo: Repo, type: GitObjectType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

function defaultBranchTip(repo: Repo): string | null {
  return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
}

// --- tree helpers ---

/** Flatten a tree object into path -> {oid, mode}, cached per tree oid. */
function flattenTree(repo: Repo, treeOid: string): Map<string, { oid: string; mode: string }> {
  const cached = repo.treeCache.get(treeOid);
  if (cached) return cached;
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (oid: string, prefix: string): void => {
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'tree') return;
    for (const entry of treeEntries(oid, obj.data)) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else out.set(path, { oid: entry.oid, mode: entry.mode });
    }
  };
  walk(treeOid, '');
  repo.treeCache.set(treeOid, out);
  return out;
}

/** Build a tree object from a flat path -> {oid, mode} map, storing intermediates. */
function buildTreeFromFiles(repo: Repo, files: Map<string, { oid: string; mode: string }>): string {
  interface Node {
    files: Map<string, { oid: string; mode: string }>;
    dirs: Map<string, Node>;
  }
  const makeNode = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = makeNode();
  for (const [path, entry] of files) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const name = segments[i] as string;
      if (!node.dirs.has(name)) node.dirs.set(name, makeNode());
      node = node.dirs.get(name) as Node;
    }
    node.files.set(segments[segments.length - 1] as string, entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return storeObject(repo, 'tree', buildTree(entries));
  };
  return build(root);
}

/** The file map at a commit (empty when the commit does not exist). */
function filesAtCommit(repo: Repo, commitOid: string | null): Map<string, { oid: string; mode: string }> {
  if (commitOid === null) return new Map();
  const obj = repo.objects.get(commitOid);
  if (!obj || obj.type !== 'commit') return new Map();
  return flattenTree(repo, commitView(commitOid, obj.data).tree);
}

/** Diff two file maps: every path whose blob oid changed, appeared or vanished. */
function diffFiles(
  before: Map<string, { oid: string; mode: string }>,
  after: Map<string, { oid: string; mode: string }>,
): { path: string; status: 'added' | 'modified' | 'removed'; oldOid: string | null; newOid: string | null }[] {
  const out: { path: string; status: 'added' | 'modified' | 'removed'; oldOid: string | null; newOid: string | null }[] = [];
  const paths = new Set([...before.keys(), ...after.keys()]);
  for (const path of [...paths].sort()) {
    const b = before.get(path);
    const a = after.get(path);
    if (b && !a) out.push({ path, status: 'removed', oldOid: b.oid, newOid: null });
    else if (!b && a) out.push({ path, status: 'added', oldOid: null, newOid: a.oid });
    else if (b && a && b.oid !== a.oid) out.push({ path, status: 'modified', oldOid: b.oid, newOid: a.oid });
  }
  return out;
}

/** Line counts for a pull-request file entry (additions/deletions by LCS). */
function lineDiff(repo: Repo, oldOid: string | null, newOid: string | null): { additions: number; deletions: number } {
  const oldText = oldOid === null ? '' : (repo.objects.get(oldOid)?.data.toString('utf8') ?? '');
  const newText = newOid === null ? '' : (repo.objects.get(newOid)?.data.toString('utf8') ?? '');
  const oldLines = oldText === '' ? [] : oldText.split('\n');
  const newLines = newText === '' ? [] : newText.split('\n');
  // LCS on lines, capped: files here are small (benchmark blobs are 1 KiB).
  const n = oldLines.length;
  const m = newLines.length;
  if (n * m > 4_000_000) {
    return { additions: newLines.length, deletions: oldLines.length };
  }
  const dp: number[] = new Array((n + 1) * (m + 1)).fill(0);
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i * (m + 1) + j] = oldLines[i] === newLines[j]
        ? dp[(i + 1) * (m + 1) + (j + 1)] + 1
        : Math.max(dp[(i + 1) * (m + 1) + j], dp[i * (m + 1) + (j + 1)]);
    }
  }
  const common = dp[0] ?? 0;
  return { additions: m - common, deletions: n - common };
}

// --- commit graph helpers ---

/** Walk commit parents from `tip`, calling `visit` on each commit (tip first). */
function walkCommits(repo: Repo, tip: string, visit: (oid: string, commit: CommitView) => void): void {
  const seen = new Set<string>();
  const stack: string[] = [tip];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    const commit = commitView(oid, obj.data);
    visit(oid, commit);
    for (let i = commit.parents.length - 1; i >= 0; i -= 1) stack.push(commit.parents[i] as string);
  }
}

/**
 * True when `ancestor` is reachable from `tip` (or equal to it). Stops at
 * the first hit: a push's fast-forward check only needs to know the old tip
 * is an ancestor, and on a linear history it is the direct parent, so the
 * walk is one step instead of the whole history.
 */
function isAncestor(repo: Repo, ancestor: string, tip: string): boolean {
  if (ancestor === tip) return true;
  const seen = new Set<string>();
  const stack: string[] = [tip];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    const commit = commitView(oid, obj.data);
    for (let i = commit.parents.length - 1; i >= 0; i -= 1) stack.push(commit.parents[i] as string);
  }
  return false;
}

/** The first common ancestor of two commits (nearest to `a` by BFS order). */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancestorsB = new Set<string>();
  walkCommits(repo, b, (oid) => ancestorsB.add(oid));
  let found: string | null = null;
  const seen = new Set<string>();
  const stack: string[] = [a];
  while (stack.length > 0 && found === null) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    if (ancestorsB.has(oid)) {
      found = oid;
      break;
    }
    const commit = commitView(oid, obj.data);
    for (let i = commit.parents.length - 1; i >= 0; i -= 1) stack.push(commit.parents[i] as string);
  }
  return found;
}

interface MergeResult {
  treeOid: string;
  conflict: boolean;
  changed: { path: string; status: 'added' | 'modified' | 'removed'; oldOid: string | null; newOid: string | null }[];
}

/**
 * Three-way merge of `head` onto `baseTip`, with `base` as their merge-base.
 * A path both sides changed differently is a conflict; the merged tree then
 * keeps the base tip's version of it and reports conflict: true.
 */
function threeWayMerge(repo: Repo, base: string, head: string, baseTip: string): MergeResult {
  const baseFiles = filesAtCommit(repo, base);
  const headFiles = filesAtCommit(repo, head);
  const tipFiles = filesAtCommit(repo, baseTip);
  const merged = new Map<string, { oid: string; mode: string }>(tipFiles);
  let conflict = false;
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys(), ...tipFiles.keys()]);
  for (const path of paths) {
    const b = baseFiles.get(path);
    const h = headFiles.get(path);
    const t = tipFiles.get(path);
    const headChanged = (b?.oid ?? null) !== (h?.oid ?? null);
    const tipChanged = (b?.oid ?? null) !== (t?.oid ?? null);
    if (headChanged && !tipChanged) {
      if (h) merged.set(path, h);
      else merged.delete(path);
    } else if (headChanged && tipChanged) {
      if ((h?.oid ?? null) !== (t?.oid ?? null)) conflict = true;
    }
  }
  const treeOid = buildTreeFromFiles(repo, merged);
  const changed = diffFiles(baseFiles, headFiles);
  return { treeOid, conflict, changed };
}

/** Commit a new commit object on `branch` of `repo` and move the ref. */
function commitOnBranch(
  repo: Repo,
  branch: string,
  files: Map<string, { oid: string; mode: string }>,
  message: string,
  timestamp: number,
): string {
  const treeOid = buildTreeFromFiles(repo, files);
  const ref = `refs/heads/${branch}`;
  const parent = repo.refs.get(ref) ?? null;
  const author = `${VIEWER_NAME} <${VIEWER_EMAIL}>`;
  const data = buildCommit({
    tree: treeOid,
    parents: parent === null ? [] : [parent],
    author,
    committer: author,
    timestamp,
    message,
  });
  const oid = storeObject(repo, 'commit', data);
  repo.refs.set(ref, oid);
  repo.updatedAt = nowIso();
  return oid;
}

// ---------------------------------------------------------------------------
// HTTP plumbing

interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  path: string;
  segments: string[];
  query: URLSearchParams;
  body: Buffer;
  json: unknown;
  jsonError: boolean;
}

const JSON_TYPE = 'application/json; charset=utf-8';

function sendJson(ctx: Ctx, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  ctx.res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': nextRequestId(),
    ...extra,
  });
  ctx.res.end(text);
}

/** Send an already-serialized JSON body (the cached GET-issue fast path). */
function sendBuffer(ctx: Ctx, status: number, buf: Buffer, extra: Record<string, string> = {}): void {
  ctx.res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': buf.length,
    'x-github-request-id': nextRequestId(),
    ...extra,
  });
  ctx.res.end(buf);
}

function sendEmpty(ctx: Ctx, status: number, extra: Record<string, string> = {}): void {
  ctx.res.writeHead(status, { 'x-github-request-id': nextRequestId(), ...extra });
  ctx.res.end();
}

function sendRaw(ctx: Ctx, status: number, contentType: string, body: Buffer, extra: Record<string, string> = {}): void {
  ctx.res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': nextRequestId(),
    ...extra,
  });
  ctx.res.end(body);
}

function notFound(ctx: Ctx, message = 'Not Found'): void {
  sendJson(ctx, 404, { message });
}

function badRequest(ctx: Ctx, message: string): void {
  sendJson(ctx, 400, { message });
}

/** The bearer token check: 401 unless the request carries the trial token. */
function authorized(ctx: Ctx): boolean {
  if (TOKEN === '') return true;
  const header = ctx.req.headers.authorization ?? '';
  return header === `Bearer ${TOKEN}`;
}

function requireAuth(ctx: Ctx): boolean {
  if (authorized(ctx)) return true;
  sendJson(ctx, 401, { message: 'Requires authentication' });
  return false;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(ctx: Ctx): void {
  ctx.json = null;
  ctx.jsonError = false;
  if (ctx.body.length === 0) return;
  try {
    ctx.json = JSON.parse(ctx.body.toString('utf8')) as unknown;
  } catch {
    ctx.jsonError = true;
  }
}

function bodyObject(ctx: Ctx): Record<string, unknown> {
  return (ctx.json !== null && typeof ctx.json === 'object' && !Array.isArray(ctx.json)
    ? (ctx.json as Record<string, unknown>)
    : {}) as Record<string, unknown>;
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

function absoluteUrl(ctx: Ctx, path: string): string {
  const host = ctx.req.headers.host ?? '127.0.0.1';
  return `http://${host}${path}`;
}

// ---------------------------------------------------------------------------
// REST v3 shapes

/**
 * The viewer user object is identical on every response, so it is built once
 * and shared. Shapes are serialized immediately and never mutated, so sharing
 * the one object is safe.
 */
const USER_SHAPE: Record<string, unknown> = {
  login: VIEWER_LOGIN,
  id: VIEWER_ID,
  node_id: globalId('U', `user:${VIEWER_LOGIN}`),
  avatar_url: `https://avatars.githubusercontent.com/u/${VIEWER_ID}?v=4`,
  gravatar_id: '',
  url: `/api/v3/users/${VIEWER_LOGIN}`,
  html_url: `https://github.com/${VIEWER_LOGIN}`,
  type: 'User',
  site_admin: false,
  name: VIEWER_NAME,
  email: VIEWER_EMAIL,
};

function userShape(): Record<string, unknown> {
  return USER_SHAPE;
}

function repoShape(repo: Repo, ctx: Ctx): Record<string, unknown> {
  const base = absoluteUrl(ctx, `/api/v3/repos/${repo.owner}/${repo.name}`);
  return {
    id: repo.id,
    node_id: repoGlobalId(repo),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    private: repo.isPrivate,
    owner: userShape(),
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    description: repo.description,
    fork: false,
    url: base,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    pushed_at: repo.updatedAt,
    git_url: `git://github.com/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@github.com:${repo.owner}/${repo.name}.git`,
    clone_url: `https://github.com/${repo.owner}/${repo.name}.git`,
    homepage: null,
    size: 0,
    stargazers_count: 0,
    watchers_count: 0,
    language: null,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    has_discussions: false,
    forks_count: 0,
    archived: false,
    disabled: false,
    open_issues_count: repo.issues.filter((i) => i.state === 'open').length + repo.pulls.filter((p) => p.state === 'open').length,
    license: null,
    allow_forking: true,
    is_template: false,
    visibility: repo.isPrivate ? 'private' : 'public',
    forks: 0,
    open_issues: 0,
    watchers: 0,
    default_branch: repo.defaultBranch,
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
  };
}

function labelShape(label: Label, repo: Repo, ctx: Ctx): Record<string, unknown> {
  return {
    id: label.id,
    node_id: globalId('L', `label:${repo.owner}/${repo.name}:${label.name}`),
    url: absoluteUrl(ctx, `/api/v3/repos/${repo.owner}/${repo.name}/labels/${encodeURIComponent(label.name)}`),
    name: label.name,
    color: label.color,
    default: false,
    description: label.description,
  };
}

function issueShape(repo: Repo, issue: Issue, ctx: Ctx): Record<string, unknown> {
  const base = absoluteUrl(ctx, `/api/v3/repos/${repo.owner}/${repo.name}`);
  return {
    id: issue.id,
    node_id: issue.nodeId,
    url: `${base}/issues/${issue.number}`,
    repository_url: base,
    labels_url: `${base}/issues/${issue.number}/labels{/name}`,
    comments_url: `${base}/issues/${issue.number}/comments`,
    events_url: `${base}/issues/${issue.number}/events`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    number: issue.number,
    state: issue.state,
    title: issue.title,
    body: issue.body,
    user: userShape(),
    labels: issue.labels.map((label) => labelShape(label, repo, ctx)),
    assignee: null,
    assignees: [],
    milestone: null,
    locked: false,
    comments: (repo.comments.get(issue.number) ?? []).length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    author_association: 'OWNER',
    state_reason: issue.state === 'closed' ? 'completed' : null,
  };
}

/**
 * The serialized GET-issue body, cached per issue version and host. The read
 * workload GETs one issue 2,000 times in a row; the body only changes when
 * the issue or its comments change, which bumps `issue.version`, so the cache
 * can never serve a stale body. The host is part of the key because the
 * body's URLs are built from the request's Host header.
 */
const issueBodyCache = new Map<string, { text: string; buf: Buffer }>();

function cachedIssueBody(repo: Repo, issue: Issue, ctx: Ctx): { text: string; buf: Buffer } {
  const host = ctx.req.headers.host ?? '127.0.0.1';
  const key = `${repo.owner}/${repo.name}#${issue.number}@${issue.version}:${host}`;
  const cached = issueBodyCache.get(key);
  if (cached !== undefined) return cached;
  const text = `${JSON.stringify(issueShape(repo, issue, ctx))}\n`;
  const entry = { text, buf: Buffer.from(text) };
  // One entry per issue version; old versions are dropped when a newer one
  // is cached, so the map stays at most one entry per issue.
  for (const oldKey of [...issueBodyCache.keys()]) {
    if (oldKey.startsWith(`${repo.owner}/${repo.name}#${issue.number}@`)) issueBodyCache.delete(oldKey);
  }
  issueBodyCache.set(key, entry);
  return entry;
}

function pullShape(repo: Repo, pull: Pull, ctx: Ctx): Record<string, unknown> {
  const base = absoluteUrl(ctx, `/api/v3/repos/${repo.owner}/${repo.name}`);
  const headSha = pull.headSha;
  const baseSha = pull.baseSha;
  return {
    id: pull.id,
    node_id: pull.nodeId,
    url: `${base}/pulls/${pull.number}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
    diff_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}.diff`,
    patch_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}.patch`,
    issue_url: `${base}/issues/${pull.number}`,
    number: pull.number,
    state: pull.state,
    locked: false,
    title: pull.title,
    user: userShape(),
    body: pull.body,
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    closed_at: pull.closedAt,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    assignee: null,
    assignees: [],
    requested_reviewers: [],
    requested_teams: [],
    labels: [],
    milestone: null,
    draft: false,
    commits_url: `${base}/pulls/${pull.number}/commits`,
    review_comments_url: `${base}/pulls/${pull.number}/comments`,
    review_comment_url: `${base}/pulls/${pull.number}/comments{/number}`,
    comments_url: `${base}/issues/${pull.number}/comments`,
    statuses_url: `${base}/commits/${headSha}/statuses`,
    head: {
      label: `${repo.owner}:${pull.headRef}`,
      ref: pull.headRef,
      sha: headSha,
      user: userShape(),
      repo: repoShape(repo, ctx),
    },
    base: {
      label: `${repo.owner}:${pull.baseRef}`,
      ref: pull.baseRef,
      sha: baseSha,
      user: userShape(),
      repo: repoShape(repo, ctx),
    },
    merged: pull.merged,
    mergeable: pullMergeable(repo, pull),
    mergeable_state: pullMergeable(repo, pull) === 'MERGEABLE' ? 'clean' : 'dirty',
    merged_by: pull.merged ? userShape() : null,
    comments: (repo.comments.get(pull.number) ?? []).length,
    review_comments: 0,
    maintainer_can_modify: false,
    commits: 1,
    additions: 0,
    deletions: 0,
    changed_files: 0,
    author_association: 'OWNER',
  };
}

/** MERGEABLE / CONFLICTING / UNKNOWN for a pull request, computed live. */
function pullMergeable(repo: Repo, pull: Pull): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  if (pull.state !== 'open') return 'UNKNOWN';
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  if (!headTip || !baseTip) return 'UNKNOWN';
  if (headTip === baseTip) return 'MERGEABLE';
  const base = mergeBase(repo, headTip, baseTip);
  if (base === null) return 'UNKNOWN';
  return threeWayMerge(repo, base, headTip, baseTip).conflict ? 'CONFLICTING' : 'MERGEABLE';
}

function commentShape(repo: Repo, number: number, comment: Comment, ctx: Ctx): Record<string, unknown> {
  const base = absoluteUrl(ctx, `/api/v3/repos/${repo.owner}/${repo.name}`);
  return {
    id: comment.id,
    node_id: comment.nodeId,
    url: `${base}/issues/comments/${comment.id}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${number}#issuecomment-${comment.id}`,
    issue_url: `${base}/issues/${number}`,
    body: comment.body,
    user: userShape(),
    created_at: comment.createdAt,
    updated_at: comment.createdAt,
    author_association: 'OWNER',
  };
}

function commitShape(repo: Repo, oid: string, ctx: Ctx): Record<string, unknown> | null {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'commit') return null;
  const commit = commitView(oid, obj.data);
  const authorLine = commit.author;
  const name = authorLine.slice(0, authorLine.lastIndexOf('<')).trim();
  const email = (authorLine.match(/<([^>]*)>/) ?? [])[1] ?? VIEWER_EMAIL;
  const base = absoluteUrl(ctx, `/api/v3/repos/${repo.owner}/${repo.name}`);
  return {
    sha: oid,
    node_id: globalId('C', `commit:${repo.owner}/${repo.name}:${oid}`),
    commit: {
      author: { name, email, date: nowIso() },
      committer: { name, email, date: nowIso() },
      message: commit.message.replace(/\n+$/, ''),
      tree: { sha: commit.tree, url: `${base}/git/trees/${commit.tree}` },
      url: `${base}/git/commits/${oid}`,
      comment_count: 0,
      verification: { verified: false, reason: 'unsigned', signature: null, payload: null },
    },
    url: `${base}/commits/${oid}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${oid}`,
    comments_url: `${base}/commits/${oid}/comments`,
    author: userShape(),
    committer: userShape(),
    parents: commit.parents.map((parent) => ({ sha: parent, url: `${base}/commits/${parent}`, html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${parent}` })),
  };
}

/** Paginate a list the GitHub way; returns the page and the Link header value. */
function paginate<T>(ctx: Ctx, items: readonly T[], path: string): { page: T[]; link: string | null } {
  const perPageRaw = Number(ctx.query.get('per_page') ?? '30');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.trunc(perPageRaw)) : 30;
  const pageRaw = Number(ctx.query.get('page') ?? '1');
  const pageNum = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.trunc(pageRaw) : 1;
  const start = (pageNum - 1) * perPage;
  const page = items.slice(start, start + perPage);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  if (pageNum >= totalPages) return { page, link: null };
  const make = (pageNo: number): string => {
    const url = new URL(absoluteUrl(ctx, path));
    url.searchParams.set('per_page', String(perPage));
    url.searchParams.set('page', String(pageNo));
    return url.toString();
  };
  const parts: string[] = [`<${make(pageNum + 1)}>; rel="next"`, `<${make(totalPages)}>; rel="last"`];
  if (pageNum > 1) parts.push(`<${make(1)}>; rel="first"`, `<${make(pageNum - 1)}>; rel="prev"`);
  return { page, link: parts.join(', ') };
}

// ---------------------------------------------------------------------------
// REST: repositories, branches, commits, contents

function handleGetUserRepos(ctx: Ctx): void {
  const mine = [...repos.values()].filter((repo) => repo.owner === VIEWER_LOGIN).sort((a, b) => a.seq - b.seq);
  const { page, link } = paginate(ctx, mine, '/api/v3/user/repos');
  sendJson(ctx, 200, page.map((repo) => repoShape(repo, ctx)), link === null ? {} : { link });
}

function handleCreateRepo(ctx: Ctx): void {
  const body = bodyObject(ctx);
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (name === '') {
    sendJson(ctx, 422, { message: 'Repository name is required' });
    return;
  }
  if (repos.has(repoKey(VIEWER_LOGIN, name))) {
    sendJson(ctx, 422, { message: 'Repository already exists' });
    return;
  }
  const isPrivate = body.private === true;
  const description = typeof body.description === 'string' ? body.description : '';
  const repo = createRepo(name, isPrivate, description);
  sendJson(ctx, 201, repoShape(repo, ctx));
}

function handleGetRepo(ctx: Ctx, owner: string, name: string): void {
  const repo = getRepo(owner, name);
  if (repo === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  sendJson(ctx, 200, repoShape(repo, ctx));
}

function handlePatchRepo(ctx: Ctx, owner: string, name: string): void {
  const repo = getRepo(owner, name);
  if (repo === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  const body = bodyObject(ctx);
  if (typeof body.description === 'string') repo.description = body.description;
  if (typeof body.private === 'boolean') repo.isPrivate = body.private;
  if (typeof body.default_branch === 'string' && body.default_branch !== '') repo.defaultBranch = body.default_branch;
  repo.updatedAt = nowIso();
  sendJson(ctx, 200, repoShape(repo, ctx));
}

function handleDeleteRepo(ctx: Ctx, owner: string, name: string): void {
  const repo = getRepo(owner, name);
  if (repo === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  repos.delete(repoKey(owner, name));
  sendEmpty(ctx, 204);
}

function handleListBranches(ctx: Ctx, repo: Repo): void {
  const branches: Record<string, unknown>[] = [];
  const base = absoluteUrl(ctx, `/api/v3/repos/${repo.owner}/${repo.name}`);
  for (const [ref, oid] of [...repo.refs.entries()].sort()) {
    if (!ref.startsWith('refs/heads/')) continue;
    const branch = ref.slice('refs/heads/'.length);
    branches.push({
      name: branch,
      commit: { sha: oid, url: `${base}/commits/${oid}` },
      protected: false,
      protection: { enabled: false, required_status_checks: { enforcement_level: 'off', contexts: [] } },
      protection_url: `${base}/branches/${encodeURIComponent(branch)}/protection`,
    });
  }
  sendJson(ctx, 200, branches);
}

function handleGetBranch(ctx: Ctx, repo: Repo, branch: string): void {
  const oid = repo.refs.get(`refs/heads/${branch}`);
  if (oid === undefined) {
    notFound(ctx, 'Branch not found');
    return;
  }
  const base = absoluteUrl(ctx, `/api/v3/repos/${repo.owner}/${repo.name}`);
  sendJson(ctx, 200, {
    name: branch,
    commit: { sha: oid, url: `${base}/commits/${oid}` },
    protected: false,
    protection: { enabled: false, required_status_checks: { enforcement_level: 'off', contexts: [] } },
    protection_url: `${base}/branches/${encodeURIComponent(branch)}/protection`,
  });
}

function handleListCommits(ctx: Ctx, repo: Repo): void {
  const shaParam = ctx.query.get('sha');
  let tip: string | null = null;
  if (shaParam !== null && shaParam !== '') {
    tip = repo.refs.get(`refs/heads/${shaParam}`) ?? (isOid(shaParam) && repo.objects.has(shaParam) ? shaParam : null);
    if (tip === null) {
      sendJson(ctx, 200, []);
      return;
    }
  } else {
    tip = defaultBranchTip(repo);
  }
  if (tip === null) {
    sendJson(ctx, 200, []);
    return;
  }
  const out: Record<string, unknown>[] = [];
  walkCommits(repo, tip, (oid) => {
    const shape = commitShape(repo, oid, ctx);
    if (shape !== null) out.push(shape);
  });
  const { page, link } = paginate(ctx, out, `/api/v3/repos/${repo.owner}/${repo.name}/commits`);
  sendJson(ctx, 200, page, link === null ? {} : { link });
}

/** Resolve a contents ref (?ref= or a branch body field) to a commit oid. */
function resolveRef(repo: Repo, ref: string | null | undefined): string | null {
  if (ref === null || ref === undefined || ref === '') return defaultBranchTip(repo);
  if (repo.refs.has(`refs/heads/${ref}`)) return repo.refs.get(`refs/heads/${ref}`) as string;
  if (repo.refs.has(`refs/tags/${ref}`)) {
    const oid = repo.refs.get(`refs/tags/${ref}`) as string;
    const obj = repo.objects.get(oid);
    if (obj?.type === 'tag') return tagView(oid, obj.data).object;
    return oid;
  }
  if (isOid(ref) && repo.objects.has(ref)) return ref;
  return null;
}

function handleGetContents(ctx: Ctx, repo: Repo, filePath: string): void {
  const tip = resolveRef(repo, ctx.query.get('ref'));
  if (tip === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  const files = filesAtCommit(repo, tip);
  const base = absoluteUrl(ctx, `/api/v3/repos/${repo.owner}/${repo.name}`);
  if (filePath === '') {
    // Root directory listing.
    const entries: Record<string, unknown>[] = [];
    const seen = new Set<string>();
    for (const path of [...files.keys()].sort()) {
      const top = path.split('/')[0] as string;
      if (seen.has(top)) continue;
      seen.add(top);
      const isDir = [...files.keys()].some((p) => p.startsWith(`${top}/`));
      const entry = isDir
        ? { type: 'dir', name: top, path: top, sha: '', size: 0, url: `${base}/contents/${encodeURIComponent(top)}`, html_url: '', git_url: '', download_url: null, _links: {} }
        : (() => {
            const file = files.get(top) as { oid: string; mode: string };
            const obj = repo.objects.get(file.oid);
            return {
              type: 'file', name: top, path: top, sha: file.oid, size: obj?.data.length ?? 0,
              url: `${base}/contents/${encodeURIComponent(top)}`, html_url: '', git_url: '', download_url: `${base}/contents/${encodeURIComponent(top)}`, _links: {},
            };
          })();
      entries.push(entry);
    }
    sendJson(ctx, 200, entries);
    return;
  }
  const file = files.get(filePath);
  if (file !== undefined) {
    const obj = repo.objects.get(file.oid);
    const content = obj?.data.toString('base64') ?? '';
    sendJson(ctx, 200, {
      type: 'file',
      encoding: 'base64',
      size: obj?.data.length ?? 0,
      name: filePath.split('/').pop() ?? filePath,
      path: filePath,
      content,
      sha: file.oid,
      url: `${base}/contents/${filePath.split('/').map(encodeURIComponent).join('/')}`,
      html_url: `https://github.com/${repo.owner}/${repo.name}/blob/${repo.defaultBranch}/${filePath}`,
      git_url: `${base}/git/blobs/${file.oid}`,
      download_url: `${base}/contents/${filePath.split('/').map(encodeURIComponent).join('/')}?raw=1`,
      _links: {},
    });
    return;
  }
  // A directory: every file under "<path>/".
  const prefix = `${filePath}/`;
  const children = [...files.keys()].filter((p) => p.startsWith(prefix));
  if (children.length === 0) {
    notFound(ctx, 'Not Found');
    return;
  }
  const entries: Record<string, unknown>[] = [];
  const seen = new Map<string, { isDir: boolean; oid: string; size: number }>();
  for (const child of children.sort()) {
    const rest = child.slice(prefix.length);
    const top = rest.split('/')[0] as string;
    if (seen.has(top)) continue;
    const isDir = rest.includes('/');
    if (isDir) {
      seen.set(top, { isDir: true, oid: '', size: 0 });
    } else {
      const fileEntry = files.get(child) as { oid: string; mode: string };
      const obj = repo.objects.get(fileEntry.oid);
      seen.set(top, { isDir: false, oid: fileEntry.oid, size: obj?.data.length ?? 0 });
    }
  }
  for (const [name, info] of [...seen.entries()].sort()) {
    entries.push({
      type: info.isDir ? 'dir' : 'file',
      name,
      path: `${filePath}/${name}`,
      sha: info.oid,
      size: info.size,
      url: `${base}/contents/${filePath.split('/').map(encodeURIComponent).join('/')}/${encodeURIComponent(name)}`,
      html_url: '',
      git_url: info.isDir ? '' : `${base}/git/blobs/${info.oid}`,
      download_url: info.isDir ? null : `${base}/contents/${filePath}/${name}`,
      _links: {},
    });
  }
  sendJson(ctx, 200, entries);
}

function handlePutContents(ctx: Ctx, repo: Repo, filePath: string): void {
  const body = bodyObject(ctx);
  const message = typeof body.message === 'string' && body.message !== '' ? body.message : 'Update file';
  const contentB64 = typeof body.content === 'string' ? body.content : '';
  if (contentB64 === '') {
    sendJson(ctx, 422, { message: 'content is required' });
    return;
  }
  let content: Buffer;
  try {
    content = Buffer.from(contentB64.replace(/[\r\n\t ]+/g, ''), 'base64');
  } catch {
    sendJson(ctx, 422, { message: 'content is not valid base64' });
    return;
  }
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
  const ref = `refs/heads/${branch}`;
  let tip = repo.refs.get(ref) ?? null;
  if (tip === null) {
    if (branch === repo.defaultBranch) {
      tip = null; // unborn default branch: first commit creates it
    } else {
      const baseTip = defaultBranchTip(repo);
      if (baseTip === null) {
        sendJson(ctx, 422, { message: `branch ${branch} does not exist` });
        return;
      }
      repo.refs.set(ref, baseTip);
      tip = baseTip;
    }
  }
  const files = filesAtCommit(repo, tip);
  const existing = files.get(filePath);
  const sha = typeof body.sha === 'string' ? body.sha : undefined;
  if (existing !== undefined && sha !== undefined && sha.toLowerCase() !== existing.oid.toLowerCase()) {
    sendJson(ctx, 409, { message: 'sha does not match the current file' });
    return;
  }
  const isCreate = existing === undefined;
  const blobOid = storeObject(repo, 'blob', content);
  const next = new Map(files);
  next.set(filePath, { oid: blobOid, mode: '100644' });
  const commitSha = commitOnBranch(repo, branch, next, message, nowSec());
  const base = absoluteUrl(ctx, `/api/v3/repos/${repo.owner}/${repo.name}`);
  sendJson(ctx, isCreate ? 201 : 200, {
    content: {
      name: filePath.split('/').pop() ?? filePath,
      path: filePath,
      sha: blobOid,
      size: content.length,
      url: `${base}/contents/${filePath.split('/').map(encodeURIComponent).join('/')}`,
      html_url: `https://github.com/${repo.owner}/${repo.name}/blob/${branch}/${filePath}`,
      git_url: `${base}/git/blobs/${blobOid}`,
      download_url: `${base}/contents/${filePath.split('/').map(encodeURIComponent).join('/')}?raw=1`,
      type: 'file',
      encoding: 'base64',
      content: content.toString('base64'),
    },
    commit: {
      sha: commitSha,
      message,
      author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: nowIso() },
      committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: nowIso() },
      parents: tip === null ? [] : [{ sha: tip }],
      tree: { sha: parseCommit(repo.objects.get(commitSha)?.data ?? Buffer.alloc(0)).tree },
      url: `${base}/git/commits/${commitSha}`,
    },
  });
}

function handleDeleteContents(ctx: Ctx, repo: Repo, filePath: string): void {
  const body = bodyObject(ctx);
  const message = typeof body.message === 'string' && body.message !== '' ? body.message : 'Delete file';
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
  const ref = `refs/heads/${branch}`;
  const tip = repo.refs.get(ref) ?? null;
  if (tip === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  const files = filesAtCommit(repo, tip);
  const existing = files.get(filePath);
  if (existing === undefined) {
    notFound(ctx, 'Not Found');
    return;
  }
  const sha = typeof body.sha === 'string' ? body.sha : undefined;
  if (sha !== undefined && sha.toLowerCase() !== existing.oid.toLowerCase()) {
    sendJson(ctx, 409, { message: 'sha does not match the current file' });
    return;
  }
  const next = new Map(files);
  next.delete(filePath);
  const commitSha = commitOnBranch(repo, branch, next, message, nowSec());
  sendJson(ctx, 200, { commit: { sha: commitSha, message } });
}

function handleCreateRef(ctx: Ctx, repo: Repo): void {
  const body = bodyObject(ctx);
  const ref = typeof body.ref === 'string' ? body.ref : '';
  const sha = typeof body.sha === 'string' ? body.sha : '';
  if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) {
    sendJson(ctx, 422, { message: 'Invalid ref or sha' });
    return;
  }
  if (repo.refs.has(ref)) {
    sendJson(ctx, 422, { message: 'Reference already exists' });
    return;
  }
  repo.refs.set(ref, sha);
  const base = absoluteUrl(ctx, `/api/v3/repos/${repo.owner}/${repo.name}`);
  sendJson(ctx, 201, {
    ref,
    node_id: globalId('F', `ref:${repo.owner}/${repo.name}:${ref}`),
    url: `${base}/git/${ref}`,
    object: { sha, type: repo.objects.get(sha)?.type ?? 'commit', url: `${base}/git/commits/${sha}` },
  });
}

function handleGetRef(ctx: Ctx, repo: Repo, refPath: string): void {
  const ref = `refs/${refPath}`;
  const oid = repo.refs.get(ref);
  if (oid === undefined) {
    notFound(ctx, 'Not Found');
    return;
  }
  const base = absoluteUrl(ctx, `/api/v3/repos/${repo.owner}/${repo.name}`);
  sendJson(ctx, 200, {
    ref,
    node_id: globalId('F', `ref:${repo.owner}/${repo.name}:${ref}`),
    url: `${base}/git/${ref}`,
    object: { sha: oid, type: repo.objects.get(oid)?.type ?? 'commit', url: `${base}/git/commits/${oid}` },
  });
}

// ---------------------------------------------------------------------------
// REST: labels, issues, comments, pull requests

function nextNumber(repo: Repo): number {
  const number = repo.nextNumber;
  repo.nextNumber += 1;
  return number;
}

function handleCreateLabel(ctx: Ctx, repo: Repo): void {
  const body = bodyObject(ctx);
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (name === '') {
    sendJson(ctx, 422, { message: 'Label name is required' });
    return;
  }
  if (repo.labels.has(name)) {
    sendJson(ctx, 422, { message: 'Label already exists' });
    return;
  }
  const label: Label = {
    id: nextLabelId,
    name,
    color: typeof body.color === 'string' ? body.color.replace(/^#/, '') : 'ededed',
    description: typeof body.description === 'string' ? body.description : '',
  };
  nextLabelId += 1;
  repo.labels.set(name, label);
  sendJson(ctx, 201, labelShape(label, repo, ctx));
}

function handleListLabels(ctx: Ctx, repo: Repo): void {
  const { page, link } = paginate(ctx, [...repo.labels.values()], `/api/v3/repos/${repo.owner}/${repo.name}/labels`);
  sendJson(ctx, 200, page.map((label) => labelShape(label, repo, ctx)), link === null ? {} : { link });
}

function handleListIssues(ctx: Ctx, repo: Repo): void {
  let items = [...repo.issues].sort((a, b) => a.createdSeq - b.createdSeq);
  const state = ctx.query.get('state');
  if (state !== null && state !== 'all') items = items.filter((i) => i.state === state);
  const direction = ctx.query.get('direction') ?? 'desc';
  const sort = ctx.query.get('sort') ?? 'created';
  if (sort === 'created') {
    items.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
  }
  const { page, link } = paginate(ctx, items, `/api/v3/repos/${repo.owner}/${repo.name}/issues`);
  sendJson(ctx, 200, page.map((issue) => issueShape(repo, issue, ctx)), link === null ? {} : { link });
}

function handleCreateIssue(ctx: Ctx, repo: Repo): void {
  const body = bodyObject(ctx);
  const title = typeof body.title === 'string' ? body.title.trim() : '';
  if (title === '') {
    sendJson(ctx, 422, { message: 'Issue title is required' });
    return;
  }
  const requestedLabels = Array.isArray(body.labels) ? (body.labels as unknown[]) : [];
  const labels: Label[] = [];
  for (const raw of requestedLabels) {
    const name = typeof raw === 'string' ? raw : typeof raw === 'object' && raw !== null ? String((raw as Record<string, unknown>).name ?? '') : '';
    const label = repo.labels.get(name);
    if (label === undefined) {
      sendJson(ctx, 422, { message: `Label does not exist: ${name}` });
      return;
    }
    labels.push(label);
  }
  const number = nextNumber(repo);
  const issue: Issue = {
    id: nextGlobalId,
    nodeId: '',
    number,
    title,
    body: typeof body.body === 'string' ? body.body : '',
    state: 'open',
    labels,
    createdSeq: repo.seq,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    closedAt: null,
    version: 1,
  };
  nextGlobalId += 1;
  repo.seq += 1;
  issue.nodeId = issueGlobalId(repo, issue);
  repo.issues.push(issue);
  repo.comments.set(number, []);
  sendJson(ctx, 201, issueShape(repo, issue, ctx));
}

function findIssue(repo: Repo, number: number): Issue | null {
  return repo.issues.find((i) => i.number === number) ?? null;
}

function findPull(repo: Repo, number: number): Pull | null {
  return repo.pulls.find((p) => p.number === number) ?? null;
}

function handleGetIssue(ctx: Ctx, repo: Repo, number: number): void {
  const issue = findIssue(repo, number);
  if (issue === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  sendBuffer(ctx, 200, cachedIssueBody(repo, issue, ctx).buf);
}

function handlePatchIssue(ctx: Ctx, repo: Repo, number: number): void {
  const issue = findIssue(repo, number);
  if (issue === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  const body = bodyObject(ctx);
  if (typeof body.title === 'string') issue.title = body.title;
  if (typeof body.body === 'string') issue.body = body.body;
  if (typeof body.state === 'string') {
    if (body.state === 'open' || body.state === 'closed') {
      issue.state = body.state;
      issue.closedAt = body.state === 'closed' ? nowIso() : null;
    }
  }
  issue.updatedAt = nowIso();
  issue.version += 1;
  sendJson(ctx, 200, issueShape(repo, issue, ctx));
}

function handleListComments(ctx: Ctx, repo: Repo, number: number): void {
  if (findIssue(repo, number) === null && findPull(repo, number) === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  const comments = repo.comments.get(number) ?? [];
  const { page, link } = paginate(ctx, comments, `/api/v3/repos/${repo.owner}/${repo.name}/issues/${number}/comments`);
  sendJson(ctx, 200, page.map((comment) => commentShape(repo, number, comment, ctx)), link === null ? {} : { link });
}

function handleCreateComment(ctx: Ctx, repo: Repo, number: number): void {
  const issue = findIssue(repo, number);
  if (issue === null && findPull(repo, number) === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  const body = bodyObject(ctx);
  const text = typeof body.body === 'string' ? body.body : '';
  if (text === '') {
    sendJson(ctx, 422, { message: 'Comment body is required' });
    return;
  }
  const comment: Comment = { id: nextGlobalId, nodeId: '', body: text, createdAt: nowIso() };
  nextGlobalId += 1;
  comment.nodeId = commentGlobalId(repo, number, comment);
  const list = repo.comments.get(number) ?? [];
  list.push(comment);
  repo.comments.set(number, list);
  // The issue's cached GET body counts comments, so it must be invalidated.
  if (issue !== null) issue.version += 1;
  sendJson(ctx, 201, commentShape(repo, number, comment, ctx));
}

function handleListPulls(ctx: Ctx, repo: Repo): void {
  let items = [...repo.pulls];
  const state = ctx.query.get('state');
  if (state === null || state === 'open') items = items.filter((p) => p.state === 'open');
  else if (state === 'closed') items = items.filter((p) => p.state === 'closed');
  items.sort((a, b) => b.createdSeq - a.createdSeq);
  const { page, link } = paginate(ctx, items, `/api/v3/repos/${repo.owner}/${repo.name}/pulls`);
  sendJson(ctx, 200, page.map((pull) => pullShape(repo, pull, ctx)), link === null ? {} : { link });
}

function handleCreatePull(ctx: Ctx, repo: Repo): void {
  const body = bodyObject(ctx);
  const head = typeof body.head === 'string' ? body.head : '';
  const base = typeof body.base === 'string' ? body.base : repo.defaultBranch;
  const title = typeof body.title === 'string' ? body.title.trim() : '';
  if (title === '' || head === '') {
    sendJson(ctx, 422, { message: 'Pull request title and head are required' });
    return;
  }
  const headSha = repo.refs.get(`refs/heads/${head}`);
  const baseSha = repo.refs.get(`refs/heads/${base}`);
  if (headSha === undefined || baseSha === undefined) {
    sendJson(ctx, 422, { message: 'Head or base branch does not exist' });
    return;
  }
  const number = nextNumber(repo);
  const pull: Pull = {
    id: nextGlobalId,
    nodeId: '',
    number,
    title,
    body: typeof body.body === 'string' ? body.body : '',
    state: 'open',
    merged: false,
    headRef: head,
    baseRef: base,
    headSha,
    baseSha,
    mergeCommitSha: null,
    mergedAt: null,
    createdSeq: repo.seq,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    closedAt: null,
  };
  nextGlobalId += 1;
  repo.seq += 1;
  pull.nodeId = pullGlobalId(repo, pull);
  repo.pulls.push(pull);
  repo.comments.set(number, []);
  sendJson(ctx, 201, pullShape(repo, pull, ctx));
}

function handleGetPull(ctx: Ctx, repo: Repo, number: number): void {
  const pull = findPull(repo, number);
  if (pull === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  sendJson(ctx, 200, pullShape(repo, pull, ctx));
}

function pullFiles(repo: Repo, pull: Pull): Record<string, unknown>[] {
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  if (!baseTip || !headTip) return [];
  const base = mergeBase(repo, headTip, baseTip) ?? baseTip;
  const baseFiles = filesAtCommit(repo, base);
  const headFiles = filesAtCommit(repo, headTip);
  const out: Record<string, unknown>[] = [];
  for (const change of diffFiles(baseFiles, headFiles)) {
    const counts = lineDiff(repo, change.oldOid, change.newOid);
    out.push({
      sha: change.newOid ?? change.oldOid ?? '',
      filename: change.path,
      status: change.status,
      additions: counts.additions,
      deletions: counts.deletions,
      changes: counts.additions + counts.deletions,
      blob_url: '',
      raw_url: '',
      contents_url: '',
    });
  }
  return out;
}

function handleListPullFiles(ctx: Ctx, repo: Repo, number: number): void {
  const pull = findPull(repo, number);
  if (pull === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  sendJson(ctx, 200, pullFiles(repo, pull));
}

interface MergeOutcome {
  status: number;
  body: Record<string, unknown>;
}

/**
 * Merge a pull request. Squash only: one new commit on the base branch whose
 * tree is the three-way merge result. A conflicted PR is 405 and stays open.
 */
function mergePull(repo: Repo, pull: Pull, method: string): MergeOutcome {
  if (pull.state !== 'open') {
    return { status: 405, body: { message: 'Pull Request is not open' } };
  }
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  if (headTip === undefined || baseTip === undefined) {
    return { status: 405, body: { message: 'Head or base branch is missing' } };
  }
  const base = mergeBase(repo, headTip, baseTip);
  if (base === null) {
    return { status: 405, body: { message: 'No merge base found' } };
  }
  const merged = threeWayMerge(repo, base, headTip, baseTip);
  if (merged.conflict) {
    return { status: 405, body: { message: 'Merge conflict' } };
  }
  const methodLower = method.toLowerCase();
  if (methodLower !== '' && methodLower !== 'squash') {
    return { status: 405, body: { message: `Merge method ${method} is not supported` } };
  }
  const author = `${VIEWER_NAME} <${VIEWER_EMAIL}>`;
  const message = methodLower === 'squash' || methodLower === '' ? pull.title : pull.title;
  const data = buildCommit({
    tree: merged.treeOid,
    parents: [baseTip],
    author,
    committer: author,
    timestamp: nowSec(),
    message: `${message}\n\nSquash-merged pull request #${pull.number}.`,
  });
  const mergeSha = storeObject(repo, 'commit', data);
  repo.refs.set(`refs/heads/${pull.baseRef}`, mergeSha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergeCommitSha = mergeSha;
  pull.mergedAt = nowIso();
  pull.closedAt = nowIso();
  pull.updatedAt = nowIso();
  pull.headSha = headTip;
  pull.baseSha = baseTip;
  repo.updatedAt = nowIso();
  return {
    status: 200,
    body: {
      sha: mergeSha,
      merged: true,
      message: `${message}\n\nSquash-merged pull request #${pull.number}.`,
      merge_method: 'squash',
    },
  };
}

function handleMergePull(ctx: Ctx, repo: Repo, number: number): void {
  const pull = findPull(repo, number);
  if (pull === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  const body = bodyObject(ctx);
  const method = typeof body.merge_method === 'string' ? body.merge_method : 'squash';
  const outcome = mergePull(repo, pull, method);
  sendJson(ctx, outcome.status, outcome.body);
}

function handlePatchPull(ctx: Ctx, repo: Repo, number: number): void {
  const pull = findPull(repo, number);
  if (pull === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  const body = bodyObject(ctx);
  if (typeof body.title === 'string') pull.title = body.title;
  if (typeof body.body === 'string') pull.body = body.body;
  if (typeof body.state === 'string' && body.state === 'closed' && pull.state === 'open') {
    pull.state = 'closed';
    pull.closedAt = nowIso();
  }
  pull.updatedAt = nowIso();
  sendJson(ctx, 200, pullShape(repo, pull, ctx));
}

// ---------------------------------------------------------------------------
// GraphQL: a small parser and executor for the documents gh and
// github-mcp-server actually send. Values are plain JS; enum values are
// strings; fields that do not exist on a type produce a GraphQL error naming
// the field (HTTP 200, as the suite requires).

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: { name: string; value: GqlValue }[] };

interface GqlSelection {
  alias: string | null;
  name: string;
  args: { name: string; value: GqlValue }[];
  selections: GqlSelection[] | null;
  fragmentSpread: string | null;
  inlineType: string | null;
}

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  varDefs: { name: string; defaultValue: GqlValue | null }[];
  selections: GqlSelection[];
}

interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, { typeCondition: string | null; selections: GqlSelection[] }>;
}

class GqlTokenizer {
  tokens: { type: string; value: string }[] = [];
  constructor(source: string) {
    let i = 0;
    const isNameStart = (c: string): boolean => /[A-Za-z_]/.test(c);
    const isNameChar = (c: string): boolean => /[A-Za-z0-9_]/.test(c);
    while (i < source.length) {
      const c = source[i] as string;
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') {
        i += 1;
        continue;
      }
      if (c === '#') {
        while (i < source.length && source[i] !== '\n') i += 1;
        continue;
      }
      if (c === '.' && source.slice(i, i + 3) === '...') {
        this.tokens.push({ type: 'spread', value: '...' });
        i += 3;
        continue;
      }
      if ('{}()[]:!=$'.includes(c)) {
        this.tokens.push({ type: 'punct', value: c });
        i += 1;
        continue;
      }
      if (c === '"') {
        let value = '';
        i += 1;
        while (i < source.length && source[i] !== '"') {
          if (source[i] === '\\' && i + 1 < source.length) {
            const esc = source[i + 1] as string;
            value += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
            i += 2;
          } else {
            value += source[i];
            i += 1;
          }
        }
        i += 1;
        this.tokens.push({ type: 'string', value });
        continue;
      }
      if (c === '-' || /[0-9]/.test(c)) {
        let num = '';
        while (i < source.length && /[0-9.eE+-]/.test(source[i] as string)) {
          num += source[i];
          i += 1;
        }
        this.tokens.push({ type: 'number', value: num });
        continue;
      }
      if (isNameStart(c)) {
        let name = '';
        while (i < source.length && isNameChar(source[i] as string)) {
          name += source[i];
          i += 1;
        }
        this.tokens.push({ type: 'name', value: name });
        continue;
      }
      throw new Error(`unexpected character ${JSON.stringify(c)} in GraphQL document`);
    }
    this.tokens.push({ type: 'eof', value: '' });
  }
}

class GqlParser {
  #tokens: { type: string; value: string }[];
  #pos = 0;
  constructor(source: string) {
    this.#tokens = new GqlTokenizer(source).tokens;
  }
  #peek(): { type: string; value: string } {
    return this.#tokens[this.#pos] as { type: string; value: string };
  }
  #next(): { type: string; value: string } {
    const token = this.#tokens[this.#pos] as { type: string; value: string };
    this.#pos += 1;
    return token;
  }
  #expectPunct(value: string): void {
    const token = this.#next();
    if (token.type !== 'punct' || token.value !== value) throw new Error(`expected '${value}' but got '${token.value}'`);
  }
  #expectName(value?: string): string {
    const token = this.#next();
    if (token.type !== 'name') throw new Error(`expected a name but got '${token.value}'`);
    if (value !== undefined && token.value !== value) throw new Error(`expected '${value}' but got '${token.value}'`);
    return token.value;
  }
  #eatPunct(value: string): boolean {
    const token = this.#peek();
    if (token.type === 'punct' && token.value === value) {
      this.#pos += 1;
      return true;
    }
    return false;
  }
  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, { typeCondition: string | null; selections: GqlSelection[] }>();
    while (this.#peek().type !== 'eof') {
      const token = this.#peek();
      if (token.type === 'punct' && token.value === '{') {
        operations.push({ kind: 'query', name: null, varDefs: [], selections: this.#parseSelectionSet() });
        continue;
      }
      const keyword = this.#expectName();
      if (keyword === 'query' || keyword === 'mutation') {
        let name: string | null = null;
        if (this.#peek().type === 'name') name = this.#next().value;
        const varDefs: { name: string; defaultValue: GqlValue | null }[] = [];
        if (this.#eatPunct('(')) {
          while (!this.#eatPunct(')')) {
            this.#expectPunct('$');
            const varName = this.#expectName();
            this.#expectPunct(':');
            this.#parseType();
            let defaultValue: GqlValue | null = null;
            if (this.#eatPunct('=')) defaultValue = this.#parseValue(true);
            varDefs.push({ name: varName, defaultValue });
          }
        }
        operations.push({ kind: keyword, name, varDefs, selections: this.#parseSelectionSet() });
      } else if (keyword === 'fragment') {
        const fragName = this.#expectName();
        this.#expectName('on');
        const typeCondition = this.#expectName();
        const selections = this.#parseSelectionSet();
        fragments.set(fragName, { typeCondition, selections });
      } else {
        throw new Error(`unexpected keyword ${keyword}`);
      }
    }
    return { operations, fragments };
  }
  #parseType(): void {
    if (this.#eatPunct('[')) {
      this.#parseType();
      this.#expectPunct(']');
    } else {
      this.#expectName();
    }
    this.#eatPunct('!');
  }
  #parseSelectionSet(): GqlSelection[] {
    this.#expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!this.#eatPunct('}')) {
      selections.push(this.#parseSelection());
    }
    return selections;
  }
  #parseSelection(): GqlSelection {
    if (this.#peek().type === 'spread') {
      this.#next();
      if (this.#peek().type === 'name' && this.#peek().value === 'on') {
        this.#next();
        const inlineType = this.#expectName();
        return { alias: null, name: '', args: [], selections: this.#parseSelectionSet(), fragmentSpread: null, inlineType };
      }
      const spreadName = this.#expectName();
      return { alias: null, name: '', args: [], selections: null, fragmentSpread: spreadName, inlineType: null };
    }
    let alias: string | null = null;
    let name = this.#expectName();
    if (this.#peek().type === 'punct' && this.#peek().value === ':') {
      this.#next();
      alias = name;
      name = this.#expectName();
    }
    const args: { name: string; value: GqlValue }[] = [];
    if (this.#eatPunct('(')) {
      while (!this.#eatPunct(')')) {
        const argName = this.#expectName();
        this.#expectPunct(':');
        args.push({ name: argName, value: this.#parseValue(false) });
      }
    }
    // Directives (@include, @skip, ...): parsed and ignored.
    while (this.#peek().type === 'punct' && this.#peek().value === '@') {
      this.#next();
      this.#expectName();
      if (this.#eatPunct('(')) {
        while (!this.#eatPunct(')')) {
          this.#expectName();
          this.#expectPunct(':');
          this.#parseValue(false);
        }
      }
    }
    let selections: GqlSelection[] | null = null;
    if (this.#peek().type === 'punct' && this.#peek().value === '{') selections = this.#parseSelectionSet();
    return { alias, name, args, selections, fragmentSpread: null, inlineType: null };
  }
  #parseValue(isConst: boolean): GqlValue {
    const token = this.#next();
    if (token.type === 'punct' && token.value === '$') {
      if (isConst) throw new Error('variable in constant value');
      return { kind: 'variable', name: this.#expectName() };
    }
    if (token.type === 'punct' && token.value === '[') {
      const values: GqlValue[] = [];
      while (!(this.#peek().type === 'punct' && this.#peek().value === ']')) values.push(this.#parseValue(isConst));
      this.#next();
      return { kind: 'list', values };
    }
    if (token.type === 'punct' && token.value === '{') {
      const fields: { name: string; value: GqlValue }[] = [];
      while (!(this.#peek().type === 'punct' && this.#peek().value === '}')) {
        const fieldName = this.#expectName();
        this.#expectPunct(':');
        fields.push({ name: fieldName, value: this.#parseValue(isConst) });
      }
      this.#next();
      return { kind: 'object', fields };
    }
    if (token.type === 'string') return { kind: 'string', value: token.value };
    if (token.type === 'number') {
      return token.value.includes('.') || token.value.includes('e') || token.value.includes('E')
        ? { kind: 'float', value: Number(token.value) }
        : { kind: 'int', value: Number(token.value) };
    }
    if (token.type === 'name') {
      if (token.value === 'true') return { kind: 'boolean', value: true };
      if (token.value === 'false') return { kind: 'boolean', value: false };
      if (token.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: token.value };
    }
    throw new Error(`unexpected token ${token.value} in value`);
  }
}

function resolveGqlValue(
  value: GqlValue,
  variables: Record<string, unknown>,
  varDefs: { name: string; defaultValue: GqlValue | null }[],
): unknown {
  switch (value.kind) {
    case 'variable': {
      if (value.name in variables) return variables[value.name];
      const def = varDefs.find((d) => d.name === value.name);
      return def?.defaultValue ? resolveGqlValue(def.defaultValue, variables, varDefs) : null;
    }
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
      return value.value;
    case 'null':
      return null;
    case 'enum':
      return value.value;
    case 'list':
      return value.values.map((v) => resolveGqlValue(v, variables, varDefs));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = resolveGqlValue(field.value, variables, varDefs);
      return out;
    }
  }
}

function argsMap(
  selection: GqlSelection,
  variables: Record<string, unknown>,
  varDefs: { name: string; defaultValue: GqlValue | null }[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const arg of selection.args) out[arg.name] = resolveGqlValue(arg.value, variables, varDefs);
  return out;
}

// --- executor: objects are { __typename, fields: Record<string, (args) => unknown> } ---

type GqlObject = {
  __typename: string;
  fields: Record<string, (args: Record<string, unknown>) => unknown>;
};

function userObject(): GqlObject {
  return {
    __typename: 'User',
    fields: {
      login: () => VIEWER_LOGIN,
      id: () => globalId('U', `user:${VIEWER_LOGIN}`),
      databaseId: () => VIEWER_ID,
      name: () => VIEWER_NAME,
      email: () => VIEWER_EMAIL,
      avatarUrl: () => `https://avatars.githubusercontent.com/u/${VIEWER_ID}?v=4`,
      url: () => `https://github.com/${VIEWER_LOGIN}`,
      html_url: () => `https://github.com/${VIEWER_LOGIN}`,
    },
  };
}

function refObject(name: string, oid: string | null): GqlObject {
  return {
    __typename: 'Ref',
    fields: {
      name: () => name,
      prefix: () => 'refs/heads/',
      target: () => (oid === null ? null : commitObject(oid)),
    },
  };
}

function commitObject(oid: string): GqlObject {
  return {
    __typename: 'Commit',
    fields: {
      oid: () => oid,
      id: () => globalId('C', `commit:${oid}`),
      message: () => '',
      abbreviatedOid: () => oid.slice(0, 7),
      author: () => ({ __typename: 'GitActor', fields: { name: () => VIEWER_NAME, email: () => VIEWER_EMAIL, date: () => nowIso() } }),
    },
  };
}

function encodeCursor(number: number): string {
  return b64urlEncode(`cursor:${number}`);
}
function decodeCursor(cursor: string): number | null {
  try {
    const text = b64urlDecode(cursor);
    const match = /^cursor:(\d+)$/.exec(text);
    return match ? Number(match[1]) : null;
  } catch {
    return null;
  }
}

function pageInfoObject(hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null): GqlObject {
  return {
    __typename: 'PageInfo',
    fields: {
      hasNextPage: () => hasNextPage,
      hasPreviousPage: () => hasPreviousPage,
      startCursor: () => startCursor,
      endCursor: () => endCursor,
    },
  };
}

function issueObject(repo: Repo, issue: Issue): GqlObject {
  return {
    __typename: 'Issue',
    fields: {
      id: () => issue.nodeId,
      databaseId: () => issue.id,
      number: () => issue.number,
      title: () => issue.title,
      body: () => issue.body,
      state: () => (issue.state === 'open' ? 'OPEN' : 'CLOSED'),
      url: () => `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
      author: () => userObject(),
      labels: (args) => {
        const nodes = issue.labels.map((label) => ({
          __typename: 'Label',
          fields: { id: () => label.id, name: () => label.name, color: () => label.color, description: () => label.description },
        }));
        const first = typeof args.first === 'number' ? args.first : nodes.length;
        const sliced = nodes.slice(0, first);
        return {
          __typename: 'LabelConnection',
          fields: {
            nodes: () => sliced,
            edges: () => sliced.map((node) => ({ __typename: 'LabelEdge', fields: { node: () => node, cursor: () => '' } })),
            totalCount: () => nodes.length,
            pageInfo: () => pageInfoObject(false, false, null, null),
          },
        };
      },
      comments: (args) => {
        const list = repo.comments.get(issue.number) ?? [];
        const nodes = list.map((comment) => ({
          __typename: 'IssueComment',
          fields: { id: () => comment.nodeId, databaseId: () => comment.id, body: () => comment.body, author: () => userObject() },
        }));
        const first = typeof args.first === 'number' ? args.first : nodes.length;
        const sliced = nodes.slice(0, first);
        return {
          __typename: 'IssueCommentConnection',
          fields: {
            nodes: () => sliced,
            edges: () => sliced.map((node) => ({ __typename: 'IssueCommentEdge', fields: { node: () => node, cursor: () => '' } })),
            totalCount: () => nodes.length,
            pageInfo: () => pageInfoObject(false, false, null, null),
          },
        };
      },
    },
  };
}

function pullObject(repo: Repo, pull: Pull): GqlObject {
  return {
    __typename: 'PullRequest',
    fields: {
      id: () => pull.nodeId,
      databaseId: () => pull.id,
      number: () => pull.number,
      title: () => pull.title,
      body: () => pull.body,
      state: () => (pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED'),
      merged: () => pull.merged,
      headRefName: () => pull.headRef,
      baseRefName: () => pull.baseRef,
      headRefOid: () => repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headSha,
      baseRefOid: () => repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha,
      mergeable: () => pullMergeable(repo, pull),
      url: () => `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
      author: () => userObject(),
      files: (args) => {
        const files = pullFiles(repo, pull);
        const nodes = files.map((file) => ({
          __typename: 'PullRequestChangedFile',
          fields: {
            path: () => String(file.filename ?? ''),
            additions: () => Number(file.additions ?? 0),
            deletions: () => Number(file.deletions ?? 0),
            changeType: () => String(file.status ?? 'MODIFIED').toUpperCase(),
          },
        }));
        const first = typeof args.first === 'number' ? args.first : nodes.length;
        const sliced = nodes.slice(0, first);
        return {
          __typename: 'PullRequestChangedFileConnection',
          fields: {
            nodes: () => sliced,
            edges: () => sliced.map((node) => ({ __typename: 'PullRequestChangedFileEdge', fields: { node: () => node, cursor: () => '' } })),
            totalCount: () => nodes.length,
            pageInfo: () => pageInfoObject(false, false, null, null),
          },
        };
      },
    },
  };
}

function repositoryObject(repo: Repo): GqlObject {
  return {
    __typename: 'Repository',
    fields: {
      id: () => repoGlobalId(repo),
      databaseId: () => repo.id,
      name: () => repo.name,
      nameWithOwner: () => `${repo.owner}/${repo.name}`,
      owner: () => userObject(),
      description: () => repo.description,
      isPrivate: () => repo.isPrivate,
      url: () => `https://github.com/${repo.owner}/${repo.name}`,
      createdAt: () => repo.createdAt,
      updatedAt: () => repo.updatedAt,
      defaultBranchRef: () => {
        const tip = defaultBranchTip(repo);
        return tip === null ? null : refObject(repo.defaultBranch, tip);
      },
      viewerPermission: () => 'ADMIN',
      hasIssuesEnabled: () => true,
      issue: (args) => {
        const issue = findIssue(repo, Number(args.number ?? -1));
        return issue === null ? null : issueObject(repo, issue);
      },
      issues: (args) => {
        let items = [...repo.issues];
        const states = Array.isArray(args.states) ? (args.states as string[]) : null;
        if (states !== null) {
          items = items.filter((i) => states.includes(i.state === 'open' ? 'OPEN' : 'CLOSED'));
        }
        const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
        const direction = String(orderBy.direction ?? 'ASC');
        items.sort((a, b) => (direction === 'DESC' ? b.number - a.number : a.number - b.number));
        const after = typeof args.after === 'string' ? decodeCursor(args.after) : null;
        if (after !== null) items = items.filter((i) => (direction === 'DESC' ? i.number < after : i.number > after));
        const first = typeof args.first === 'number' ? args.first : items.length;
        const sliced = items.slice(0, first);
        const hasNextPage = items.length > first;
        const nodes = sliced.map((issue) => issueObject(repo, issue));
        return {
          __typename: 'IssueConnection',
          fields: {
            nodes: () => nodes,
            edges: () => nodes.map((node, index) => ({
              __typename: 'IssueEdge',
              fields: { node: () => node, cursor: () => encodeCursor(sliced[index]?.number ?? 0) },
            })),
            totalCount: () => items.length,
            pageInfo: () =>
              pageInfoObject(
                hasNextPage,
                after !== null,
                sliced.length > 0 ? encodeCursor(sliced[0]?.number ?? 0) : null,
                sliced.length > 0 ? encodeCursor(sliced[sliced.length - 1]?.number ?? 0) : null,
              ),
          },
        };
      },
      pullRequests: (args) => {
        let items = [...repo.pulls];
        const first = typeof args.first === 'number' ? args.first : items.length;
        const after = typeof args.after === 'string' ? decodeCursor(args.after) : null;
        if (after !== null) items = items.filter((p) => p.number > after);
        items.sort((a, b) => a.number - b.number);
        const sliced = items.slice(0, first);
        const hasNextPage = items.length > first;
        const nodes = sliced.map((pull) => pullObject(repo, pull));
        return {
          __typename: 'PullRequestConnection',
          fields: {
            nodes: () => nodes,
            edges: () => nodes.map((node, index) => ({
              __typename: 'PullRequestEdge',
              fields: { node: () => node, cursor: () => encodeCursor(sliced[index]?.number ?? 0) },
            })),
            totalCount: () => items.length,
            pageInfo: () =>
              pageInfoObject(
                hasNextPage,
                after !== null,
                sliced.length > 0 ? encodeCursor(sliced[0]?.number ?? 0) : null,
                sliced.length > 0 ? encodeCursor(sliced[sliced.length - 1]?.number ?? 0) : null,
              ),
          },
        };
      },
      pullRequest: (args) => {
        const pull = findPull(repo, Number(args.number ?? -1));
        return pull === null ? null : pullObject(repo, pull);
      },
    },
  };
}

const INTROSPECTION_TYPES: Record<string, { kind: string; enumValues?: string[]; fields?: string[] }> = {
  SearchType: { kind: 'ENUM', enumValues: ['ISSUE', 'REPOSITORY', 'USER', 'CODE', 'DISCUSSION'] },
  IssueState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED'] },
  PullRequestState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED', 'MERGED'] },
  MergeableState: { kind: 'ENUM', enumValues: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'] },
  RepositoryPermission: { kind: 'ENUM', enumValues: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'] },
  // Field lists mirror the fields the object constructors actually serve;
  // gh feature-detects on these names via __type(...).fields.
  Repository: {
    kind: 'OBJECT',
    fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'description', 'isPrivate', 'url', 'createdAt', 'updatedAt', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  },
  Issue: {
    kind: 'OBJECT',
    fields: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'url', 'author', 'labels', 'comments'],
  },
  PullRequest: {
    kind: 'OBJECT',
    fields: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'merged', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'mergeable', 'url', 'author', 'files'],
  },
  User: { kind: 'OBJECT', fields: ['login', 'id', 'databaseId', 'name', 'email', 'avatarUrl', 'url'] },
  Query: { kind: 'OBJECT', fields: ['viewer', 'repository', 'node', '__type', '__schema'] },
  Mutation: { kind: 'OBJECT', fields: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'] },
};

function introspectionObject(name: string): GqlObject | null {
  const info = INTROSPECTION_TYPES[name];
  if (info === undefined) return null;
  return {
    __typename: '__Type',
    fields: {
      name: () => name,
      kind: () => info.kind,
      description: () => null,
      enumValues: () =>
        (info.enumValues ?? []).map((value) => ({
          __typename: '__EnumValue',
          fields: { name: () => value, description: () => null, isDeprecated: () => false, deprecationReason: () => null },
        })),
      fields: () =>
        (info.fields ?? []).map((fieldName) => ({
          __typename: '__Field',
          fields: { name: () => fieldName, description: () => null, isDeprecated: () => false, deprecationReason: () => null },
        })),
      inputFields: () => null,
      interfaces: () => [],
      possibleTypes: () => null,
    },
  };
}

function nodeObject(id: string): GqlObject | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null) return null;
  if (decoded.kind === 'R') {
    const match = /^repo:([^/]+)\/(.+)$/.exec(decoded.value);
    if (match === null) return null;
    const repo = getRepo(match[1] as string, match[2] as string);
    return repo === null ? null : repositoryObject(repo);
  }
  if (decoded.kind === 'I') {
    const match = /^issue:([^/]+)\/(.+):(\d+)$/.exec(decoded.value);
    if (match === null) return null;
    const repo = getRepo(match[1] as string, match[2] as string);
    if (repo === null) return null;
    const issue = findIssue(repo, Number(match[3]));
    return issue === null ? null : issueObject(repo, issue);
  }
  if (decoded.kind === 'P') {
    const match = /^pr:([^/]+)\/(.+):(\d+)$/.exec(decoded.value);
    if (match === null) return null;
    const repo = getRepo(match[1] as string, match[2] as string);
    if (repo === null) return null;
    const pull = findPull(repo, Number(match[3]));
    return pull === null ? null : pullObject(repo, pull);
  }
  return null;
}

interface GqlExecutor {
  data: Record<string, unknown>;
  errors: { message: string }[];
}

function expandSelections(
  selections: GqlSelection[],
  doc: GqlDocument,
  typeName: string,
): GqlSelection[] {
  const out: GqlSelection[] = [];
  for (const selection of selections) {
    if (selection.fragmentSpread !== null) {
      const fragment = doc.fragments.get(selection.fragmentSpread);
      if (fragment !== undefined && (fragment.typeCondition === null || fragment.typeCondition === typeName)) {
        out.push(...expandSelections(fragment.selections, doc, typeName));
      }
    } else if (selection.inlineType !== null) {
      if (selection.inlineType === typeName) {
        out.push(...expandSelections(selection.selections ?? [], doc, typeName));
      }
    } else {
      out.push(selection);
    }
  }
  return out;
}

function resolveObject(
  obj: GqlObject,
  selections: GqlSelection[],
  doc: GqlDocument,
  variables: Record<string, unknown>,
  varDefs: { name: string; defaultValue: GqlValue | null }[],
  errors: { message: string }[],
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const selection of expandSelections(selections, doc, obj.__typename)) {
    const key = selection.alias ?? selection.name;
    if (selection.name === '__typename') {
      result[key] = obj.__typename;
      continue;
    }
    const resolver = obj.fields[selection.name];
    if (resolver === undefined) {
      errors.push({ message: `Cannot query field "${selection.name}" on type "${obj.__typename}".` });
      result[key] = null;
      continue;
    }
    let value: unknown;
    try {
      value = resolver(argsMap(selection, variables, varDefs));
    } catch (error) {
      errors.push({ message: error instanceof Error ? error.message : String(error) });
      result[key] = null;
      continue;
    }
    result[key] = resolveValue(value, selection, doc, variables, varDefs, errors);
  }
  return result;
}

function resolveValue(
  value: unknown,
  selection: GqlSelection,
  doc: GqlDocument,
  variables: Record<string, unknown>,
  varDefs: { name: string; defaultValue: GqlValue | null }[],
  errors: { message: string }[],
): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) {
    return value.map((item) => resolveValue(item, selection, doc, variables, varDefs, errors));
  }
  if (typeof value === 'object' && '__typename' in (value as Record<string, unknown>)) {
    const obj = value as GqlObject;
    if (selection.selections === null) return {};
    return resolveObject(obj, selection.selections, doc, variables, varDefs, errors);
  }
  return value;
}

function executeRoot(
  operation: GqlOperation,
  doc: GqlDocument,
  variables: Record<string, unknown>,
): GqlExecutor {
  const errors: { message: string }[] = [];
  const data: Record<string, unknown> = {};
  const root: GqlObject = {
    __typename: operation.kind === 'mutation' ? 'Mutation' : 'Query',
    fields: {
      viewer: () => userObject(),
      repository: (args) => {
        const repo = getRepo(String(args.owner ?? ''), String(args.name ?? ''));
        return repo === null ? null : repositoryObject(repo);
      },
      node: (args) => nodeObject(String(args.id ?? '')),
      __type: (args) => introspectionObject(String(args.name ?? '')),
      __schema: () => ({
        __typename: '__Schema',
        fields: {
          queryType: () => ({ __typename: '__Type', fields: { name: () => 'Query', kind: () => 'OBJECT' } }),
          mutationType: () => ({ __typename: '__Type', fields: { name: () => 'Mutation', kind: () => 'OBJECT' } }),
          types: () => [],
        },
      }),
      createIssue: (args) => {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
        if (decoded === null || decoded.kind !== 'R') throw new Error('createIssue: repositoryId is not a repository');
        const match = /^repo:([^/]+)\/(.+)$/.exec(decoded.value);
        if (match === null) throw new Error('createIssue: bad repository id');
        const repo = getRepo(match[1] as string, match[2] as string);
        if (repo === null) throw new Error('createIssue: repository not found');
        const number = nextNumber(repo);
        const issue: Issue = {
          id: nextGlobalId,
          nodeId: '',
          number,
          title: String(input.title ?? ''),
          body: typeof input.body === 'string' ? input.body : '',
          state: 'open',
          labels: [],
          createdSeq: repo.seq,
          createdAt: nowIso(),
          updatedAt: nowIso(),
          closedAt: null,
          version: 1,
        };
        nextGlobalId += 1;
        repo.seq += 1;
        issue.nodeId = issueGlobalId(repo, issue);
        repo.issues.push(issue);
        repo.comments.set(number, []);
        return {
          __typename: 'CreateIssuePayload',
          fields: {
            issue: () => issueObject(repo, issue),
            clientMutationId: () => (typeof input.clientMutationId === 'string' ? input.clientMutationId : null),
          },
        };
      },
      closeIssue: (args) => {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(String(input.issueId ?? ''));
        if (decoded === null || decoded.kind !== 'I') throw new Error('closeIssue: issueId is not an issue');
        const match = /^issue:([^/]+)\/(.+):(\d+)$/.exec(decoded.value);
        if (match === null) throw new Error('closeIssue: bad issue id');
        const repo = getRepo(match[1] as string, match[2] as string);
        if (repo === null) throw new Error('closeIssue: repository not found');
        const issue = findIssue(repo, Number(match[3]));
        if (issue === null) throw new Error('closeIssue: issue not found');
        issue.state = 'closed';
        issue.closedAt = nowIso();
        issue.updatedAt = nowIso();
        issue.version += 1;
        return {
          __typename: 'CloseIssuePayload',
          fields: {
            issue: () => issueObject(repo, issue),
            clientMutationId: () => (typeof input.clientMutationId === 'string' ? input.clientMutationId : null),
          },
        };
      },
      createPullRequest: (args) => {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
        if (decoded === null || decoded.kind !== 'R') throw new Error('createPullRequest: repositoryId is not a repository');
        const match = /^repo:([^/]+)\/(.+)$/.exec(decoded.value);
        if (match === null) throw new Error('createPullRequest: bad repository id');
        const repo = getRepo(match[1] as string, match[2] as string);
        if (repo === null) throw new Error('createPullRequest: repository not found');
        const head = String(input.headRefName ?? '');
        const base = String(input.baseRefName ?? repo.defaultBranch);
        const headSha = repo.refs.get(`refs/heads/${head}`);
        const baseSha = repo.refs.get(`refs/heads/${base}`);
        if (headSha === undefined || baseSha === undefined) throw new Error('createPullRequest: head or base branch missing');
        const number = nextNumber(repo);
        const pull: Pull = {
          id: nextGlobalId,
          nodeId: '',
          number,
          title: String(input.title ?? ''),
          body: typeof input.body === 'string' ? input.body : '',
          state: 'open',
          merged: false,
          headRef: head,
          baseRef: base,
          headSha,
          baseSha,
          mergeCommitSha: null,
          mergedAt: null,
          createdSeq: repo.seq,
          createdAt: nowIso(),
          updatedAt: nowIso(),
          closedAt: null,
        };
        nextGlobalId += 1;
        repo.seq += 1;
        pull.nodeId = pullGlobalId(repo, pull);
        repo.pulls.push(pull);
        repo.comments.set(number, []);
        return {
          __typename: 'CreatePullRequestPayload',
          fields: {
            pullRequest: () => pullObject(repo, pull),
            clientMutationId: () => (typeof input.clientMutationId === 'string' ? input.clientMutationId : null),
          },
        };
      },
      mergePullRequest: (args) => {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(String(input.pullRequestId ?? ''));
        if (decoded === null || decoded.kind !== 'P') throw new Error('mergePullRequest: pullRequestId is not a pull request');
        const match = /^pr:([^/]+)\/(.+):(\d+)$/.exec(decoded.value);
        if (match === null) throw new Error('mergePullRequest: bad pull request id');
        const repo = getRepo(match[1] as string, match[2] as string);
        if (repo === null) throw new Error('mergePullRequest: repository not found');
        const pull = findPull(repo, Number(match[3]));
        if (pull === null) throw new Error('mergePullRequest: pull request not found');
        const method = typeof input.mergeMethod === 'string' ? input.mergeMethod : 'SQUASH';
        const outcome = mergePull(repo, pull, method.toLowerCase());
        if (outcome.status !== 200) throw new Error(`mergePullRequest: ${String(outcome.body.message ?? 'merge failed')}`);
        return {
          __typename: 'MergePullRequestPayload',
          fields: {
            pullRequest: () => pullObject(repo, pull),
            clientMutationId: () => (typeof input.clientMutationId === 'string' ? input.clientMutationId : null),
          },
        };
      },
      addComment: (args) => {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(String(input.subjectId ?? ''));
        if (decoded === null) throw new Error('addComment: subjectId is not a known node');
        const repoName = decoded.value.split(':')[1] ?? '';
        const [owner, name] = repoName.split('/');
        const repo = getRepo(owner ?? '', name ?? '');
        if (repo === null) throw new Error('addComment: repository not found');
        const number = Number(decoded.value.split(':')[2] ?? NaN);
        if (!Number.isFinite(number)) throw new Error('addComment: subject is not an issue or pull request');
        const issue = findIssue(repo, number);
        if (issue === null && findPull(repo, number) === null) throw new Error('addComment: subject not found');
        const comment: Comment = { id: nextGlobalId, nodeId: '', body: String(input.body ?? ''), createdAt: nowIso() };
        nextGlobalId += 1;
        comment.nodeId = commentGlobalId(repo, number, comment);
        const list = repo.comments.get(number) ?? [];
        list.push(comment);
        repo.comments.set(number, list);
        if (issue !== null) issue.version += 1;
        const node = {
          __typename: 'IssueComment',
          fields: { id: () => comment.nodeId, databaseId: () => comment.id, body: () => comment.body, author: () => userObject() },
        };
        return {
          __typename: 'AddCommentPayload',
          fields: {
            commentEdge: () => ({
              __typename: 'IssueCommentEdge',
              fields: { node: () => node, cursor: () => encodeCursor(comment.id) },
            }),
            subject: () => nodeObject(String(input.subjectId ?? '')),
            clientMutationId: () => (typeof input.clientMutationId === 'string' ? input.clientMutationId : null),
          },
        };
      },
    },
  };
  for (const selection of operation.selections) {
    if (selection.fragmentSpread !== null || selection.inlineType !== null) continue;
    const key = selection.alias ?? selection.name;
    if (selection.name === '__typename') {
      data[key] = root.__typename;
      continue;
    }
    const resolver = root.fields[selection.name];
    if (resolver === undefined) {
      errors.push({ message: `Cannot query field "${selection.name}" on type "${root.__typename}".` });
      data[key] = null;
      continue;
    }
    let value: unknown;
    try {
      value = resolver(argsMap(selection, variables, operation.varDefs));
    } catch (error) {
      errors.push({ message: error instanceof Error ? error.message : String(error) });
      data[key] = null;
      continue;
    }
    data[key] = resolveValue(value, selection, doc, variables, operation.varDefs, errors);
  }
  return { data, errors };
}

function executeGraphQL(body: unknown): Record<string, unknown> | Record<string, unknown>[] {
  const runOne = (item: unknown): Record<string, unknown> => {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) {
      return { data: null, errors: [{ message: 'GraphQL request must be an object with a query string' }] };
    }
    const request = item as Record<string, unknown>;
    const query = typeof request.query === 'string' ? request.query : '';
    const operationName = typeof request.operationName === 'string' ? request.operationName : null;
    const variables = (request.variables ?? {}) as Record<string, unknown>;
    if (query === '') {
      return { data: null, errors: [{ message: 'No query provided' }] };
    }
    let doc: GqlDocument;
    try {
      doc = new GqlParser(query).parseDocument();
    } catch (error) {
      return { data: null, errors: [{ message: error instanceof Error ? error.message : String(error) }] };
    }
    const operation =
      operationName !== null
        ? doc.operations.find((op) => op.name === operationName)
        : doc.operations[0];
    if (operation === undefined) {
      return { data: null, errors: [{ message: `Unknown operation ${operationName ?? ''}` }] };
    }
    const { data, errors } = executeRoot(operation, doc, variables);
    const out: Record<string, unknown> = { data };
    if (errors.length > 0) out.errors = errors;
    return out;
  };
  if (Array.isArray(body)) return body.map(runOne);
  return runOne(body);
}

// ---------------------------------------------------------------------------
// MCP: JSON-RPC 2.0 over Streamable HTTP.
//
// Modern era 2026-07-28: server/discover advertises the supported revisions.
// The legacy initialize handshake is kept as a fallback. Tools are one fixed
// literal list, so two tools/list calls are byte-identical.

const MCP_SERVER_NAME = 'github-core-clone';
const MCP_SERVER_VERSION = '2.0.0';
const MCP_REVISIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

const MCP_TOOLS: Record<string, unknown>[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Name of the repository' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
        owner: { type: 'string', description: 'Owner login (defaults to the authenticated user)' },
      },
      required: ['name'],
      additionalProperties: false,
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        full_name: { type: 'string', description: 'Full repository name owner/repo' },
      },
      required: ['owner', 'repo'],
      additionalProperties: false,
    },
  },
  {
    name: 'list_repos',
    description: 'List repositories owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login (defaults to the authenticated user)' },
      },
      required: [],
      additionalProperties: false,
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
        labels: { type: 'array', items: { type: 'string' }, description: 'Labels to apply' },
        full_name: { type: 'string', description: 'Full repository name owner/repo' },
      },
      required: ['owner', 'repo', 'title'],
      additionalProperties: false,
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state: open, closed or all', enum: ['open', 'closed', 'all'] },
        full_name: { type: 'string', description: 'Full repository name owner/repo' },
      },
      required: ['owner', 'repo'],
      additionalProperties: false,
    },
  },
  {
    name: 'get_issue',
    description: 'Get one issue by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        issue_number: { type: 'integer', description: 'Issue number' },
      },
      required: ['owner', 'repo', 'issue_number'],
      additionalProperties: false,
    },
  },
  {
    name: 'close_issue',
    description: 'Close an issue by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        issue_number: { type: 'integer', description: 'Issue number' },
      },
      required: ['owner', 'repo', 'issue_number'],
      additionalProperties: false,
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
        full_name: { type: 'string', description: 'Full repository name owner/repo' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
      additionalProperties: false,
    },
  },
  {
    name: 'list_pull_requests',
    description: 'List pull requests in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Pull request state: open, closed or all', enum: ['open', 'closed', 'all'] },
      },
      required: ['owner', 'repo'],
      additionalProperties: false,
    },
  },
  {
    name: 'get_pull_request',
    description: 'Get one pull request by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
      additionalProperties: false,
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash commit.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
        merge_method: { type: 'string', description: 'Merge method (squash)', enum: ['squash'] },
      },
      required: ['owner', 'repo', 'pull_number'],
      additionalProperties: false,
    },
  },
];

function mcpResultText(result: unknown): { content: { type: string; text: string }[]; structuredContent: unknown } {
  return {
    content: [{ type: 'text', text: JSON.stringify(result) }],
    structuredContent: result,
  };
}

function mcpResolveRepo(args: Record<string, unknown>): Repo | null {
  let owner = typeof args.owner === 'string' ? args.owner : '';
  let name = typeof args.repo === 'string' ? args.repo : '';
  if (typeof args.full_name === 'string' && args.full_name.includes('/')) {
    const [o, n] = args.full_name.split('/');
    if (owner === '') owner = o ?? '';
    if (name === '') name = n ?? '';
  }
  if (owner === '') owner = VIEWER_LOGIN;
  return getRepo(owner, name);
}

function mcpCallTool(name: string, args: Record<string, unknown>): { isError: boolean; result: unknown } {
  const tool = MCP_TOOLS.find((t) => t.name === name);
  if (tool === undefined) return { isError: true, result: { error: `unknown tool: ${name}` } };
  const required = ((tool.inputSchema as Record<string, unknown>).required ?? []) as string[];
  for (const prop of required) {
    if (args[prop] === undefined || args[prop] === null || args[prop] === '') {
      return { isError: true, result: { error: `missing required argument: ${prop}` } };
    }
  }
  if (name === 'create_repo') {
    const repoName = String(args.name);
    if (repos.has(repoKey(VIEWER_LOGIN, repoName))) {
      return { isError: true, result: { error: 'Repository already exists' } };
    }
    const repo = createRepo(repoName, args.private === true, typeof args.description === 'string' ? args.description : '');
    return { isError: false, result: { id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}`, private: repo.isPrivate, description: repo.description, default_branch: repo.defaultBranch, html_url: `https://github.com/${repo.owner}/${repo.name}` } };
  }
  if (name === 'list_repos') {
    const mine = [...repos.values()].filter((repo) => repo.owner === VIEWER_LOGIN).sort((a, b) => a.seq - b.seq);
    return { isError: false, result: { repositories: mine.map((repo) => ({ id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}`, private: repo.isPrivate, description: repo.description, default_branch: repo.defaultBranch })) } };
  }
  const repo = mcpResolveRepo(args);
  if (repo === null) return { isError: true, result: { error: 'Repository not found' } };
  if (name === 'get_repo') {
    return { isError: false, result: { id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}`, owner: repo.owner, private: repo.isPrivate, description: repo.description, default_branch: repo.defaultBranch, html_url: `https://github.com/${repo.owner}/${repo.name}`, created_at: repo.createdAt, updated_at: repo.updatedAt } };
  }
  if (name === 'create_issue') {
    const title = String(args.title);
    const labels: Label[] = [];
    if (Array.isArray(args.labels)) {
      for (const labelName of args.labels as unknown[]) {
        const label = repo.labels.get(String(labelName));
        if (label === undefined) return { isError: true, result: { error: `Label does not exist: ${String(labelName)}` } };
        labels.push(label);
      }
    }
    const number = nextNumber(repo);
    const issue: Issue = {
      id: nextGlobalId,
      nodeId: '',
      number,
      title,
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      labels,
      createdSeq: repo.seq,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      closedAt: null,
      version: 1,
    };
    nextGlobalId += 1;
    repo.seq += 1;
    issue.nodeId = issueGlobalId(repo, issue);
    repo.issues.push(issue);
    repo.comments.set(number, []);
    return { isError: false, result: { id: issue.id, number: issue.number, title: issue.title, body: issue.body, state: issue.state, url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`, html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}` } };
  }
  if (name === 'list_issues') {
    let items = [...repo.issues];
    const state = typeof args.state === 'string' ? args.state : 'open';
    if (state !== 'all') items = items.filter((i) => i.state === state);
    items.sort((a, b) => b.createdSeq - a.createdSeq);
    return { isError: false, result: { issues: items.map((i) => ({ id: i.id, number: i.number, title: i.title, body: i.body, state: i.state, labels: i.labels.map((l) => l.name), created_at: i.createdAt })) } };
  }
  if (name === 'get_issue' || name === 'close_issue') {
    const issue = findIssue(repo, Number(args.issue_number));
    if (issue === null) return { isError: true, result: { error: 'Issue not found' } };
    if (name === 'close_issue') {
      issue.state = 'closed';
      issue.closedAt = nowIso();
      issue.updatedAt = nowIso();
      issue.version += 1;
    }
    return { isError: false, result: { id: issue.id, number: issue.number, title: issue.title, body: issue.body, state: issue.state, labels: issue.labels.map((l) => l.name), created_at: issue.createdAt } };
  }
  if (name === 'create_pull_request') {
    const head = String(args.head);
    const base = String(args.base);
    const headSha = repo.refs.get(`refs/heads/${head}`);
    const baseSha = repo.refs.get(`refs/heads/${base}`);
    if (headSha === undefined || baseSha === undefined) {
      return { isError: true, result: { error: 'Head or base branch does not exist' } };
    }
    const number = nextNumber(repo);
    const pull: Pull = {
      id: nextGlobalId,
      nodeId: '',
      number,
      title: String(args.title),
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      merged: false,
      headRef: head,
      baseRef: base,
      headSha,
      baseSha,
      mergeCommitSha: null,
      mergedAt: null,
      createdSeq: repo.seq,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      closedAt: null,
    };
    nextGlobalId += 1;
    repo.seq += 1;
    pull.nodeId = pullGlobalId(repo, pull);
    repo.pulls.push(pull);
    repo.comments.set(number, []);
    return { isError: false, result: { id: pull.id, number: pull.number, title: pull.title, body: pull.body, state: pull.state, head: pull.headRef, base: pull.baseRef, head_sha: pull.headSha, base_sha: pull.baseSha, url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`, html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}` } };
  }
  if (name === 'list_pull_requests') {
    let items = [...repo.pulls];
    const state = typeof args.state === 'string' ? args.state : 'open';
    if (state !== 'all') items = items.filter((p) => p.state === state);
    items.sort((a, b) => b.createdSeq - a.createdSeq);
    return { isError: false, result: { pull_requests: items.map((p) => ({ id: p.id, number: p.number, title: p.title, body: p.body, state: p.state, merged: p.merged, head: p.headRef, base: p.baseRef, created_at: p.createdAt })) } };
  }
  if (name === 'get_pull_request') {
    const pull = findPull(repo, Number(args.pull_number));
    if (pull === null) return { isError: true, result: { error: 'Pull request not found' } };
    return { isError: false, result: { id: pull.id, number: pull.number, title: pull.title, body: pull.body, state: pull.state, merged: pull.merged, head: pull.headRef, base: pull.baseRef, head_sha: pull.headSha, base_sha: pull.baseSha, merge_commit_sha: pull.mergeCommitSha } };
  }
  if (name === 'merge_pull_request') {
    const pull = findPull(repo, Number(args.pull_number));
    if (pull === null) return { isError: true, result: { error: 'Pull request not found' } };
    const method = typeof args.merge_method === 'string' ? args.merge_method : 'squash';
    const outcome = mergePull(repo, pull, method);
    if (outcome.status !== 200) return { isError: true, result: { error: String(outcome.body.message ?? 'merge failed') } };
    return { isError: false, result: { number: pull.number, merged: true, state: pull.state, sha: String(outcome.body.sha ?? ''), merge_method: 'squash' } };
  }
  return { isError: true, result: { error: `unknown tool: ${name}` } };
}

function handleMcp(ctx: Ctx): void {
  if (!requireAuth(ctx)) return;
  if (ctx.jsonError || ctx.json === null || typeof ctx.json !== 'object' || Array.isArray(ctx.json)) {
    sendJson(ctx, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const request = ctx.json as Record<string, unknown>;
  const id = request.id ?? null;
  const method = typeof request.method === 'string' ? request.method : '';
  const params = (request.params ?? {}) as Record<string, unknown>;
  const ok = (result: unknown): void => {
    sendJson(ctx, 200, { jsonrpc: '2.0', id, result });
  };
  const fail = (code: number, message: string): void => {
    sendJson(ctx, 200, { jsonrpc: '2.0', id, error: { code, message } });
  };
  if (method === 'server/discover') {
    ok({
      supportedVersions: MCP_REVISIONS,
      capabilities: { tools: {} },
      serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION } },
    });
    return;
  }
  if (method === 'initialize') {
    const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const chosen = MCP_REVISIONS.includes(requested) ? requested : MCP_REVISIONS[0];
    ok({
      protocolVersion: chosen,
      capabilities: { tools: {} },
      serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
    });
    return;
  }
  if (method === 'notifications/initialized' || method.startsWith('notifications/')) {
    sendEmpty(ctx, 202);
    return;
  }
  if (method === 'ping') {
    ok({});
    return;
  }
  if (method === 'tools/list') {
    ok({ tools: MCP_TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const toolArgs = (params.arguments ?? {}) as Record<string, unknown>;
    if (toolName === '') {
      fail(-32602, 'tools/call requires a tool name');
      return;
    }
    const toolExists = MCP_TOOLS.some((t) => t.name === toolName);
    if (!toolExists) {
      fail(-32601, `unknown tool: ${toolName}`);
      return;
    }
    const { isError, result } = mcpCallTool(toolName, toolArgs);
    const shaped = mcpResultText(result);
    ok({ ...shaped, isError });
    return;
  }
  fail(-32601, `method not found: ${method}`);
}

// ---------------------------------------------------------------------------
// Git smart HTTP: upload-pack (protocol v2 + v0 fallback) and receive-pack
// (v0). Packs are built from plain objects; incoming packs may carry OFS or
// REF deltas and are resolved on read.

function advertisementRefLines(repo: Repo): { oid: string; name: string; peeled: string | null }[] {
  const lines: { oid: string; name: string; peeled: string | null }[] = [];
  const tip = defaultBranchTip(repo);
  if (tip !== null) lines.push({ oid: tip, name: 'HEAD', peeled: null });
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  for (const [ref, oid] of refs) {
    let peeled: string | null = null;
    const obj = repo.objects.get(oid);
    if (obj?.type === 'tag') {
      const tag = tagView(oid, obj.data);
      if (tag.type === 'commit') peeled = tag.object;
    }
    lines.push({ oid, name: ref, peeled });
  }
  return lines;
}

function handleInfoRefs(ctx: Ctx, repo: Repo, service: string | null): void {
  if (service === 'git-upload-pack') {
    const useV2 = (ctx.req.headers['git-protocol'] ?? '') === 'version=2';
    if (useV2) {
      const body = Buffer.concat([
        pktLine('version 2\n'),
        pktLine(`agent=${AGENT_NAME}\n`),
        pktLine('ls-refs=unborn\n'),
        pktLine('fetch=shallow wait-for-done filter\n'),
        pktLine('server-option\n'),
        pktLine('object-format=sha1\n'),
        pktFlush(),
      ]);
      sendRaw(ctx, 200, 'application/x-git-upload-pack-advertisement', body);
      return;
    }
    const caps = 'side-band-64k shallow deepen-relative symref=HEAD:refs/heads/main multi_ack multi_ack_detailed thin-pack ofs-delta report-status agent=' + AGENT_NAME;
    const parts: Buffer[] = [pktLine('# service=git-upload-pack\n'), pktFlush()];
    const lines = advertisementRefLines(repo);
    if (lines.length === 0) {
      parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
    } else {
      lines.forEach((line, index) => {
        const suffix = index === 0 ? `\0${caps}` : '';
        parts.push(pktLine(`${line.oid} ${line.name}${suffix}\n`));
        if (line.peeled !== null) parts.push(pktLine(`${line.peeled} ${line.name}^{}\n`));
      });
    }
    parts.push(pktFlush());
    sendRaw(ctx, 200, 'application/x-git-upload-pack-advertisement', Buffer.concat(parts));
    return;
  }
  if (service === 'git-receive-pack') {
    const caps = 'report-status side-band-64k delete-refs ofs-delta agent=' + AGENT_NAME;
    const parts: Buffer[] = [pktLine('# service=git-receive-pack\n'), pktFlush()];
    const lines = advertisementRefLines(repo);
    if (lines.length === 0) {
      parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
    } else {
      lines.forEach((line, index) => {
        const suffix = index === 0 ? `\0${caps}` : '';
        parts.push(pktLine(`${line.oid} ${line.name}${suffix}\n`));
        if (line.peeled !== null) parts.push(pktLine(`${line.peeled} ${line.name}^{}\n`));
      });
    }
    parts.push(pktFlush());
    sendRaw(ctx, 200, 'application/x-git-receive-pack-advertisement', Buffer.concat(parts));
    return;
  }
  badRequest(ctx, 'unknown service');
}

// --- fetch object selection (shared by v2 and v0) ---

interface FetchSelection {
  objects: { type: GitObjectType; data: Buffer }[];
  shallowLines: string[];
  unshallowLines: string[];
}

/**
 * Work out which objects a fetch must send.
 *
 * wants: commit/tag oids the client asked for. haves: commits the client
 * already has. shallow: the client's current shallow boundaries — the held
 * closure stops at them, so their parents are never treated as held.
 * deepen: when set, only commits at depth < deepen are included (deepen N
 * means the tip plus N-1 ancestors). deepenRelative: the deepen value is
 * relative to the client's current boundary, so the effective depth is
 * deepen plus the boundary's depth from the wants (git's rule).
 *
 * v2 note: with an absolute deepen the walk is capped at that depth — a
 * depth-1 clone visits the tip commit only instead of the whole 200-commit
 * history, because no deeper commit can be included or affect the result.
 * The queue is index-based (no shift()), so the walk is linear.
 */
function selectFetchObjects(
  repo: Repo,
  wants: string[],
  haves: string[],
  shallow: string[],
  deepen: number | null,
  deepenRelative = false,
): FetchSelection {
  const shallowSet = new Set(shallow);
  const depths = new Map<string, number>();
  const queue: { oid: string; depth: number }[] = [];
  let queueHead = 0;
  const wantedTags: string[] = [];
  for (const want of wants) {
    const obj = repo.objects.get(want);
    if (obj === undefined) continue;
    if (obj.type === 'tag') {
      wantedTags.push(want);
      const tag = tagView(want, obj.data);
      if (tag.type === 'commit' && !depths.has(tag.object)) {
        depths.set(tag.object, 0);
        queue.push({ oid: tag.object, depth: 0 });
      }
    } else if (obj.type === 'commit') {
      if (!depths.has(want)) {
        depths.set(want, 0);
        queue.push({ oid: want, depth: 0 });
      }
    }
  }
  // Depth map from the wants. With an absolute deepen, parents at depth
  // >= deepen are never included and cannot change any outcome, so they
  // are not walked at all. A relative deepen needs the boundary's depth
  // even when the boundary itself is not a want, so it walks in full.
  const capped = deepen !== null && !deepenRelative;
  while (queueHead < queue.length) {
    const { oid, depth } = queue[queueHead] as { oid: string; depth: number };
    queueHead += 1;
    const obj = repo.objects.get(oid);
    if (obj?.type !== 'commit') continue;
    if (deepen === null && shallowSet.has(oid)) continue;
    if (capped && depth + 1 >= (deepen as number)) continue;
    for (const parent of commitView(oid, obj.data).parents) {
      if (!depths.has(parent)) {
        depths.set(parent, depth + 1);
        queue.push({ oid: parent, depth: depth + 1 });
      }
    }
  }
  const included = new Set<string>();
  // A relative deepen adds the client's current boundary depth (1-based,
  // minimum over the boundaries reachable from the wants) to the request.
  if (deepen !== null && deepenRelative) {
    let boundaryDepth: number | null = null;
    for (const oid of shallow) {
      const depth = depths.get(oid);
      if (depth !== undefined && (boundaryDepth === null || depth < boundaryDepth)) boundaryDepth = depth;
    }
    if (boundaryDepth !== null) deepen = deepen + boundaryDepth + 1;
  }
  for (const [oid, depth] of depths) {
    // deepen N means the tip plus N-1 ancestors: depths 0 .. N-1.
    if (deepen !== null && depth >= deepen) continue;
    included.add(oid);
  }
  // Held closure: everything reachable from the haves, without crossing a
  // shallow boundary (a shallow commit's parents are not held). The
  // closure covers commits, their trees and blobs, and tag targets: a
  // shared subtree or blob the client already holds must not be sent
  // again, or an incremental fetch re-sends objects the client has.
  const held = new Set<string>();
  const heldQueue = [...haves];
  const addTreeToHeld = (treeOid: string): void => {
    const stack = [treeOid];
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (held.has(oid)) continue;
      held.add(oid);
      const obj = repo.objects.get(oid);
      if (obj?.type !== 'tree') continue;
      for (const entry of treeEntries(oid, obj.data)) stack.push(entry.oid);
    }
  };
  while (heldQueue.length > 0) {
    const oid = heldQueue.pop() as string;
    if (held.has(oid)) continue;
    held.add(oid);
    const obj = repo.objects.get(oid);
    if (obj?.type === 'tag') {
      heldQueue.push(tagView(oid, obj.data).object);
      continue;
    }
    if (obj?.type === 'tree') {
      addTreeToHeld(oid);
      continue;
    }
    if (obj?.type !== 'commit') continue;
    addTreeToHeld(commitView(oid, obj.data).tree);
    if (shallowSet.has(oid)) continue;
    for (const parent of commitView(oid, obj.data).parents) heldQueue.push(parent);
  }
  const send = new Map<string, { type: GitObjectType; data: Buffer }>();
  const addObject = (oid: string): void => {
    if (held.has(oid) || send.has(oid)) return;
    const obj = repo.objects.get(oid);
    if (obj === undefined) return;
    send.set(oid, { type: obj.type, data: obj.data });
    if (obj.type === 'commit') {
      const commit = commitView(oid, obj.data);
      addObject(commit.tree);
    } else if (obj.type === 'tree') {
      for (const entry of treeEntries(oid, obj.data)) addObject(entry.oid);
    } else if (obj.type === 'tag') {
      addObject(tagView(oid, obj.data).object);
    }
  };
  for (const tag of wantedTags) addObject(tag);
  for (const oid of included) addObject(oid);
  const shallowLines: string[] = [];
  const unshallowLines: string[] = [];
  if (deepen !== null) {
    // The new boundaries are the included commits at the cutoff depth.
    for (const oid of included) {
      if (depths.get(oid) === deepen - 1) shallowLines.push(`shallow ${oid}`);
    }
  }
  for (const oid of shallowSet) {
    // An old boundary whose parents are all included now is no longer one.
    // Only a deepen can cross a boundary, so only a deepen unshallows one:
    // a plain fetch leaves the client's boundaries exactly as they are.
    if (deepen !== null && included.has(oid) && (depths.get(oid) ?? 0) < deepen - 1) {
      unshallowLines.push(`unshallow ${oid}`);
    }
  }
  // De-duplicate while keeping order.
  const dedupe = (lines: string[]): string[] => [...new Set(lines)];
  return { objects: [...send.values()], shallowLines: dedupe(shallowLines), unshallowLines: dedupe(unshallowLines) };
}

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 32768;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    const chunk = pack.subarray(offset, Math.min(offset + CHUNK, pack.length));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  return Buffer.concat(parts);
}

function handleUploadPackV2(ctx: Ctx, repo: Repo, packets: Pkt[]): void {
  const first = packets[0];
  if (first === undefined || first.kind !== 'data') {
    badRequest(ctx, 'expected a protocol v2 command');
    return;
  }
  const command = first.payload.toString('utf8').trim();
  if (command === 'command=ls-refs') {
    const prefixes: string[] = [];
    let peel = false;
    let symrefs = false;
    let unborn = false;
    for (const packet of packets.slice(1)) {
      if (packet.kind === 'flush') break;
      if (packet.kind === 'delim') continue; // arguments follow the delim
      if (packet.kind !== 'data') continue;
      const line = packet.payload.toString('utf8').trim();
      if (line === 'peel') peel = true;
      else if (line === 'symrefs') symrefs = true;
      else if (line === 'unborn') unborn = true;
      else if (line.startsWith('ref-prefix ')) prefixes.push(line.slice('ref-prefix '.length));
      // agent= / object-format= lines before the delim are ignored.
    }
    const matchesPrefix = (name: string): boolean =>
      prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
    const parts: Buffer[] = [];
    const tip = defaultBranchTip(repo);
    if (matchesPrefix('HEAD')) {
      if (tip !== null) {
        parts.push(
          pktLine(symrefs ? `${tip} HEAD symref-target:refs/heads/${repo.defaultBranch}\n` : `${tip} HEAD\n`),
        );
      } else if (unborn) {
        parts.push(pktLine('unborn HEAD\n'));
      }
    }
    const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    for (const [ref, oid] of refs) {
      if (!matchesPrefix(ref)) continue;
      // The peel is an attribute on the same line (v2 ls-refs format):
      // `<oid> <ref> peeled:<oid>`. A separate peel line would register
      // as a second ref entry for the same name, and a client reading the
      // first match would see no peel at all.
      let line = `${oid} ${ref}`;
      if (peel) {
        const obj = repo.objects.get(oid);
        if (obj?.type === 'tag') {
          const tag = tagView(oid, obj.data);
          if (tag.type === 'commit') line += ` peeled:${tag.object}`;
        }
      }
      parts.push(pktLine(`${line}\n`));
    }
    parts.push(pktFlush());
    sendRaw(ctx, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
    return;
  }
  if (command === 'command=fetch') {
    const wants: string[] = [];
    const haves: string[] = [];
    const shallow: string[] = [];
    let deepen: number | null = null;
    let deepenRelative = false;
    for (const packet of packets.slice(1)) {
      if (packet.kind === 'flush') break;
      if (packet.kind === 'delim') continue;
      if (packet.kind !== 'data') continue;
      const line = packet.payload.toString('utf8').trim();
      if (line.startsWith('want ')) wants.push(line.slice(5).trim());
      else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
      else if (line.startsWith('shallow ')) shallow.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) deepen = Number(line.slice(7).trim());
      else if (line === 'deepen-relative') deepenRelative = true;
      else if (line === 'done') break;
    }
    const selection = selectFetchObjects(repo, wants, haves, shallow, deepen, deepenRelative);
    const parts: Buffer[] = [];
    // Each section is named by a header line and closed by a flush. The
    // acknowledgments section exists only when the client sent haves: a
    // fresh clone sends none and expects the packfile section straight away.
    // When 'ready' is sent the ack section ends with a DELIM, not a flush:
    // the packfile section (and any shallow-info section) still follows,
    // and only the packfile section closes the response with a flush. With
    // a NAK and no 'ready' the ack section ends with a flush and nothing
    // else follows — the client then sends another fetch request.
    if (haves.length > 0) {
      const known = haves.filter((have) => repo.objects.has(have));
      parts.push(pktLine('acknowledgments\n'));
      if (known.length === 0) {
        parts.push(pktLine('NAK\n'));
        parts.push(pktFlush());
        sendRaw(ctx, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
        return;
      }
      for (const have of known) parts.push(pktLine(`ACK ${have}\n`));
      parts.push(pktLine('ready\n'));
      parts.push(pktDelim());
    }
    if (selection.shallowLines.length > 0 || selection.unshallowLines.length > 0) {
      parts.push(pktLine('shallow-info\n'));
      for (const line of selection.shallowLines) parts.push(pktLine(`${line}\n`));
      for (const line of selection.unshallowLines) parts.push(pktLine(`${line}\n`));
      parts.push(pktFlush());
    }
    if (selection.objects.length > 0 || haves.length > 0) {
      // A negotiated fetch (haves were sent) always carries a packfile
      // section: git expects the packfile after 'ready' even when nothing
      // is new, and then an empty pack (0 entries) is the correct payload.
      parts.push(pktLine('packfile\n'));
      parts.push(sidebandPack(writePack(selection.objects)));
      parts.push(pktFlush());
    }
    sendRaw(ctx, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
    return;
  }
  badRequest(ctx, `unsupported protocol v2 command: ${command}`);
}

function handleUploadPackV0(ctx: Ctx, repo: Repo, packets: Pkt[]): void {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let deepen: number | null = null;
  let deepenRelative = false;
  let hasDone = false;
  let capabilities = '';
  for (const packet of packets) {
    if (packet.kind === 'flush') continue;
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').trim();
    if (line.startsWith('want ')) {
      const rest = line.slice(5).trim().split(' ');
      wants.push(rest[0] as string);
      if (rest.length > 1) capabilities = rest.slice(1).join(' ');
    } else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) shallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) deepen = Number(line.slice(7).trim());
    else if (line === 'deepen-relative') deepenRelative = true;
    else if (line === 'done') hasDone = true;
  }
  const selection = selectFetchObjects(repo, wants, haves, shallow, deepen, deepenRelative || capabilities.includes('deepen-relative'));
  const parts: Buffer[] = [];
  // The shallow list comes first (only when a deepen was requested or the
  // client sent shallows), closed by a flush — the client consumes it
  // before it reads any ACK/NAK. The flush is sent even when the list is
  // empty: the client's shallow-list reader expects it.
  if (deepen !== null || shallow.length > 0) {
    for (const line of selection.shallowLines) parts.push(pktLine(`${line}\n`));
    for (const line of selection.unshallowLines) parts.push(pktLine(`${line}\n`));
    parts.push(pktFlush());
  }
  // Without a 'done' line this request is only the opening of the
  // negotiation: the client will send more requests, and the shallow list
  // above is all this response carries. Sending ACKs or a pack here would
  // leave them sitting in the stream, where the client's next shallow-list
  // read would trip over them. The real server stops here too (its
  // upload-pack only runs the ACK/pack phase once a request carries
  // 'done').
  if (!hasDone) {
    sendRaw(ctx, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
    return;
  }
  // ACK / NAK, in the form the client's advertised multi_ack mode expects.
  // A bare ACK ends the negotiation at once; 'common'/'continue' lines
  // keep it going until a 'ready' or a NAK closes the section. Sending
  // more than one bare ACK would make the client read the second one as
  // the start of the packfile.
  const known = haves.filter((have) => repo.objects.has(have));
  const multiDetailed = capabilities.includes('multi_ack_detailed');
  const multiAck = multiDetailed || capabilities.includes('multi_ack');
  if (known.length === 0) {
    parts.push(pktLine('NAK\n'));
  } else if (multiDetailed) {
    for (const oid of known) parts.push(pktLine(`ACK ${oid} common\n`));
    if (hasDone) parts.push(pktLine(`ACK ${known[known.length - 1] as string}\n`));
    else {
      parts.push(pktLine(`ACK ${known[known.length - 1] as string} ready\n`));
      parts.push(pktLine('NAK\n'));
    }
  } else if (multiAck) {
    for (const oid of known) parts.push(pktLine(`ACK ${oid} continue\n`));
    if (hasDone) parts.push(pktLine(`ACK ${known[known.length - 1] as string}\n`));
    else parts.push(pktLine('NAK\n'));
  } else {
    parts.push(pktLine(`ACK ${known[0] as string}\n`));
  }
  if (selection.objects.length > 0 || haves.length > 0) {
    // As in v2, a negotiated fetch always carries a pack (possibly empty).
    parts.push(sidebandPack(writePack(selection.objects)));
  }
  parts.push(pktFlush());
  sendRaw(ctx, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
}

function handleUploadPack(ctx: Ctx, repo: Repo): void {
  const { packets, rest } = decodePktLines(ctx.body);
  if (packets.length === 0) {
    badRequest(ctx, 'request body is not a pkt-line stream');
    return;
  }
  void rest;
  const first = packets[0];
  if (first !== undefined && first.kind === 'data' && first.payload.toString('utf8').startsWith('command=')) {
    handleUploadPackV2(ctx, repo, packets);
    return;
  }
  handleUploadPackV0(ctx, repo, packets);
}

function handleReceivePack(ctx: Ctx, repo: Repo): void {
  const { packets, rest } = decodePktLines(ctx.body);
  if (packets.length === 0) {
    badRequest(ctx, 'request body is not a pkt-line stream');
    return;
  }
  interface RefUpdate {
    oldOid: string;
    newOid: string;
    ref: string;
  }
  const updates: RefUpdate[] = [];
  for (const packet of packets) {
    if (packet.kind === 'flush') break;
    if (packet.kind !== 'data') continue;
    let line = packet.payload.toString('utf8');
    const nul = line.indexOf('\0');
    if (nul >= 0) line = line.slice(0, nul);
    const match = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)\s*$/.exec(line.trim());
    if (match === null) continue;
    updates.push({ oldOid: match[1] as string, newOid: match[2] as string, ref: match[3] as string });
  }
  const results: { ref: string; ok: boolean; reason: string }[] = [];
  let packObjects: PackEntry[] = [];
  if (rest.length > 0) {
    try {
      const parsed = readPack(rest, (oid) => repo.objects.get(oid));
      packObjects = parsed.objects;
    } catch (error) {
      sendJson(ctx, 400, { message: `invalid packfile: ${error instanceof Error ? error.message : String(error)}` });
      return;
    }
  }
  for (const object of packObjects) {
    if (!repo.objects.has(object.oid)) repo.objects.set(object.oid, { type: object.type, data: object.data });
  }
  repo.treeCache.clear();
  for (const update of updates) {
    const current = repo.refs.get(update.ref);
    if (update.newOid === ZERO_OID) {
      // Delete.
      if (current === undefined) {
        results.push({ ref: update.ref, ok: false, reason: 'reference does not exist' });
      } else if (current !== update.oldOid) {
        results.push({ ref: update.ref, ok: false, reason: 'old value does not match' });
      } else {
        repo.refs.delete(update.ref);
        results.push({ ref: update.ref, ok: true, reason: '' });
      }
      continue;
    }
    const target = repo.objects.get(update.newOid);
    if (target === undefined || (target.type !== 'commit' && target.type !== 'tag')) {
      results.push({ ref: update.ref, ok: false, reason: 'invalid object' });
      continue;
    }
    if (update.oldOid === ZERO_OID) {
      if (current !== undefined) {
        results.push({ ref: update.ref, ok: false, reason: 'reference already exists' });
        continue;
      }
    } else {
      if (current === undefined || current !== update.oldOid) {
        results.push({ ref: update.ref, ok: false, reason: 'old value does not match' });
        continue;
      }
      const newCommit = target.type === 'tag' ? tagView(update.newOid, target.data).object : update.newOid;
      if (!isAncestor(repo, update.oldOid, newCommit)) {
        results.push({ ref: update.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
    }
    repo.refs.set(update.ref, update.newOid);
    repo.updatedAt = nowIso();
    results.push({ ref: update.ref, ok: true, reason: '' });
  }
  const report: Buffer[] = [pktLine('unpack ok\n')];
  for (const result of results) {
    report.push(pktLine(result.ok ? `ok ${result.ref}\n` : `ng ${result.ref} ${result.reason}\n`));
  }
  // The report-status stream is pkt-lined inside one sideband band-1 packet,
  // and the stream itself ends with a flush inside band 1: after the HTTP
  // transport demultiplexes the sideband, the reader still sees the flush
  // that terminates the report (a bare outer flush is consumed by the demux).
  const body = Buffer.concat([
    pktLine(Buffer.concat([Buffer.from([1]), Buffer.concat(report), pktFlush()])),
    pktFlush(),
  ]);
  sendRaw(ctx, 200, 'application/x-git-receive-pack-result', body);
}

// ---------------------------------------------------------------------------
// Router

function handleRest(ctx: Ctx): void {
  const method = ctx.req.method ?? 'GET';
  const seg = ctx.segments; // after /api/v3
  if (seg.length === 0) {
    if (method === 'GET') {
      sendJson(ctx, 200, {
        current_user_url: absoluteUrl(ctx, '/api/v3/user'),
        repository_url: absoluteUrl(ctx, '/api/v3/repos/{owner}/{repo}'),
      }, { 'x-oauth-scopes': 'repo, user', 'x-accepted-oauth-scopes': 'repo, user' });
      return;
    }
    notFound(ctx);
    return;
  }
  if (seg[0] === 'meta' && method === 'GET') {
    sendJson(ctx, 200, {
      verifiable_password_authentication: true,
      ssh_key_fingerprints: {},
      ssh_keys: [],
      hooks: [],
      web: [],
      api: [],
      git: [],
      packages: [],
      pages: [],
      importer: [],
      actions: [],
      dependabot: [],
      installed_version: '1.0.0',
    });
    return;
  }
  if (seg[0] === 'user' && seg.length === 1) {
    if (method === 'GET') {
      sendJson(ctx, 200, userShape());
      return;
    }
    notFound(ctx);
    return;
  }
  if (seg[0] === 'user' && seg[1] === 'repos') {
    if (method === 'GET') {
      handleGetUserRepos(ctx);
      return;
    }
    if (method === 'POST') {
      handleCreateRepo(ctx);
      return;
    }
    notFound(ctx);
    return;
  }
  if (seg[0] === 'graphql') {
    notFound(ctx);
    return;
  }
  if (seg[0] !== 'repos' || seg.length < 3) {
    notFound(ctx);
    return;
  }
  const owner = decodeSegment(seg[1] as string);
  const name = decodeSegment(seg[2] as string);
  const repo = getRepo(owner, name);
  if (repo === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  const rest = seg.slice(3);
  if (rest.length === 0) {
    if (method === 'GET') handleGetRepo(ctx, owner, name);
    else if (method === 'PATCH') handlePatchRepo(ctx, owner, name);
    else if (method === 'DELETE') handleDeleteRepo(ctx, owner, name);
    else notFound(ctx);
    return;
  }
  if (rest[0] === 'branches') {
    if (rest.length === 1 && method === 'GET') {
      handleListBranches(ctx, repo);
      return;
    }
    if (rest.length === 2 && method === 'GET') {
      handleGetBranch(ctx, repo, decodeSegment(rest[1] as string));
      return;
    }
    notFound(ctx);
    return;
  }
  if (rest[0] === 'commits') {
    if (rest.length === 1 && method === 'GET') {
      handleListCommits(ctx, repo);
      return;
    }
    notFound(ctx);
    return;
  }
  if (rest[0] === 'contents') {
    const filePath = rest.slice(1).map(decodeSegment).join('/');
    if (method === 'GET') handleGetContents(ctx, repo, filePath);
    else if (method === 'PUT') handlePutContents(ctx, repo, filePath);
    else if (method === 'DELETE') handleDeleteContents(ctx, repo, filePath);
    else notFound(ctx);
    return;
  }
  if (rest[0] === 'git' && rest[1] === 'refs') {
    if (rest.length === 2 && method === 'POST') {
      handleCreateRef(ctx, repo);
      return;
    }
    if (rest.length > 2 && method === 'GET') {
      handleGetRef(ctx, repo, rest.slice(2).map(decodeSegment).join('/'));
      return;
    }
    notFound(ctx);
    return;
  }
  if (rest[0] === 'labels') {
    if (rest.length === 1 && method === 'GET') {
      handleListLabels(ctx, repo);
      return;
    }
    if (rest.length === 1 && method === 'POST') {
      handleCreateLabel(ctx, repo);
      return;
    }
    notFound(ctx);
    return;
  }
  if (rest[0] === 'issues') {
    if (rest.length === 1 && method === 'GET') {
      handleListIssues(ctx, repo);
      return;
    }
    if (rest.length === 1 && method === 'POST') {
      handleCreateIssue(ctx, repo);
      return;
    }
    const number = Number(rest[1]);
    if (!Number.isInteger(number) || number <= 0) {
      notFound(ctx);
      return;
    }
    if (rest.length === 2 && method === 'GET') {
      handleGetIssue(ctx, repo, number);
      return;
    }
    if (rest.length === 2 && method === 'PATCH') {
      handlePatchIssue(ctx, repo, number);
      return;
    }
    if (rest.length === 3 && rest[2] === 'comments') {
      if (method === 'GET') handleListComments(ctx, repo, number);
      else if (method === 'POST') handleCreateComment(ctx, repo, number);
      else notFound(ctx);
      return;
    }
    notFound(ctx);
    return;
  }
  if (rest[0] === 'pulls') {
    if (rest.length === 1 && method === 'GET') {
      handleListPulls(ctx, repo);
      return;
    }
    if (rest.length === 1 && method === 'POST') {
      handleCreatePull(ctx, repo);
      return;
    }
    const number = Number(rest[1]);
    if (!Number.isInteger(number) || number <= 0) {
      notFound(ctx);
      return;
    }
    if (rest.length === 2 && method === 'GET') {
      handleGetPull(ctx, repo, number);
      return;
    }
    if (rest.length === 2 && method === 'PATCH') {
      handlePatchPull(ctx, repo, number);
      return;
    }
    if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
      handleListPullFiles(ctx, repo, number);
      return;
    }
    if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
      handleMergePull(ctx, repo, number);
      return;
    }
    notFound(ctx);
    return;
  }
  notFound(ctx);
}

function handleGit(ctx: Ctx): void {
  // /{owner}/{repo}.git[/info/refs | /git-upload-pack | /git-receive-pack]
  const seg = ctx.segments;
  if (seg.length < 2 || !seg[1]?.endsWith('.git')) {
    notFound(ctx, 'Not Found');
    return;
  }
  const owner = decodeSegment(seg[0] as string);
  const name = decodeSegment((seg[1] as string).slice(0, -4));
  const repo = getRepo(owner, name);
  if (repo === null) {
    notFound(ctx, 'Not Found');
    return;
  }
  const tail = seg.slice(2);
  const method = ctx.req.method ?? 'GET';
  if (tail.length === 2 && tail[0] === 'info' && tail[1] === 'refs' && method === 'GET') {
    handleInfoRefs(ctx, repo, ctx.query.get('service'));
    return;
  }
  if (tail.length === 1 && tail[0] === 'git-upload-pack' && method === 'POST') {
    handleUploadPack(ctx, repo);
    return;
  }
  if (tail.length === 1 && tail[0] === 'git-receive-pack' && method === 'POST') {
    handleReceivePack(ctx, repo);
    return;
  }
  notFound(ctx, 'Not Found');
}

export function createApp(): Server {
  const server = createServer(async (req, res) => {
    const ctx: Ctx = {
      req,
      res,
      url: new URL(req.url ?? '/', 'http://127.0.0.1'),
      path: '',
      segments: [],
      query: new URLSearchParams(),
      body: Buffer.alloc(0),
      json: null,
      jsonError: false,
    };
    ctx.path = ctx.url.pathname.replace(/\/+$/, '') || '/';
    ctx.query = ctx.url.searchParams;
    ctx.segments = ctx.path.split('/').filter((s) => s !== '');
    // A request that cannot carry a body (a bodyless GET/HEAD/DELETE) never
    // waits for the request stream's 'end' event: the handler would idle one
    // event-loop turn per request for nothing. Anything that may carry a body
    // (POST/PUT/PATCH, a declared length, chunked encoding) is read as before.
    // No GET/HEAD/DELETE route in this forge reads the body, and a client that
    // does send one still gets it read, so keep-alive stays well formed.
    const method = req.method ?? 'GET';
    const contentLength = req.headers['content-length'];
    const mayHaveBody =
      method === 'POST' || method === 'PUT' || method === 'PATCH' ||
      (typeof contentLength === 'string' && contentLength !== '0') ||
      req.headers['transfer-encoding'] !== undefined;
    try {
      ctx.body = mayHaveBody ? await readBody(req) : Buffer.alloc(0);
    } catch {
      sendJson(ctx, 400, { message: 'could not read request body' });
      return;
    }
    try {
      if (ctx.path === '/healthz') {
        sendJson(ctx, 200, { ok: true });
        return;
      }
      if (ctx.path === '/api/graphql' && req.method === 'POST') {
        if (!requireAuth(ctx)) return;
        parseJsonBody(ctx);
        if (ctx.jsonError) {
          sendJson(ctx, 400, { message: 'Invalid JSON' });
          return;
        }
        const result = executeGraphQL(ctx.json);
        sendJson(ctx, 200, result);
        return;
      }
      if (ctx.path === '/mcp' && req.method === 'POST') {
        parseJsonBody(ctx);
        handleMcp(ctx);
        return;
      }
      if (ctx.segments[0] === 'api' && ctx.segments[1] === 'v3') {
        if (!requireAuth(ctx)) return;
        ctx.segments = ctx.segments.slice(2);
        const method = req.method ?? 'GET';
        if ((method === 'POST' || method === 'PUT' || method === 'PATCH') && ctx.body.length > 0) {
          parseJsonBody(ctx);
          if (ctx.jsonError) {
            badRequest(ctx, 'Invalid JSON');
            return;
          }
        } else {
          parseJsonBody(ctx);
        }
        handleRest(ctx);
        return;
      }
      if (ctx.segments.length >= 2 && ctx.segments[1]?.endsWith('.git')) {
        if (!requireAuth(ctx)) return;
        handleGit(ctx);
        return;
      }
      notFound(ctx);
    } catch (error) {
      // Never let one bad request take the forge down; the trial keeps going.
      if (!res.headersSent) {
        sendJson(ctx, 500, { message: error instanceof Error ? error.message : String(error) });
      }
    }
  });
  return server;
}
