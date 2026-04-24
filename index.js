/*
  ANB Connect — ATOMS GraphQL Simulator

  Goal: provide a lightweight, in-memory GraphQL service that *resembles* ATOMS
  closely enough for local dev + demos.

  Notes:
  - This is NOT a full ATOMS implementation.
  - Data is stored in memory and persisted to sim/data/atoms-sim-store.json.
  - The schema is sourced from schema/schema.graphqls (copied from the provided
    schema.graphqls.txt reference).

  Endpoints:
    GET  /health
    POST /graphql

  Env:
    PORT=4010
    HOST=0.0.0.0
    GRAPHQL_PATH=/graphql
    SEED_DEMO_DATA=true|false
*/

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const { ApolloServer } = require('@apollo/server');
const { expressMiddleware } = require('@apollo/server/express4');
const { GraphQLScalarType, Kind } = require('graphql');

const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.PORT || 4010);
const GRAPHQL_PATH = process.env.GRAPHQL_PATH || '/graphql';
const SEED_DEMO_DATA = String(process.env.SEED_DEMO_DATA || 'true').toLowerCase() === 'true';
const HTTPS_ENABLED = String(process.env.HTTPS_ENABLED || 'false').toLowerCase() === 'true';
const HTTPS_CERT_FILE = process.env.HTTPS_CERT_FILE || '';
const HTTPS_KEY_FILE = process.env.HTTPS_KEY_FILE || '';
const HTTPS_PFX_FILE = process.env.HTTPS_PFX_FILE || '';
const HTTPS_PFX_PASSWORD = process.env.HTTPS_PFX_PASSWORD || '';
const HTTPS_CA_FILE = process.env.HTTPS_CA_FILE || '';
const HTTPS_REQUEST_CLIENT_CERT = String(process.env.HTTPS_REQUEST_CLIENT_CERT || 'false').toLowerCase() === 'true';
const HTTPS_REQUIRE_CLIENT_CERT = String(process.env.HTTPS_REQUIRE_CLIENT_CERT || 'false').toLowerCase() === 'true';

// Optional public-demo authorization guard. This is intentionally simple:
// require an Authorization: Bearer <token> header for all non-health requests
// when ATOMS_SIM_REQUIRE_AUTH=true. Render health checks remain unauthenticated.
const ATOMS_SIM_REQUIRE_AUTH = String(process.env.ATOMS_SIM_REQUIRE_AUTH || 'false').toLowerCase() === 'true';
const ATOMS_SIM_AUTH_TOKEN = process.env.ATOMS_SIM_AUTH_TOKEN || '';


// Request logging (prints every request to console and appends to a log file)
// Default log dir: src/connectors/atoms/logs (sibling of this sim folder)
const DEFAULT_LOG_DIR = path.join(__dirname, '..', 'logs');
const LOG_DIR = process.env.ATOMS_SIM_LOG_DIR
  ? path.resolve(process.env.ATOMS_SIM_LOG_DIR)
  : DEFAULT_LOG_DIR;
const LOG_FILE = process.env.ATOMS_SIM_LOG_FILE
  ? path.resolve(process.env.ATOMS_SIM_LOG_FILE)
  : path.join(LOG_DIR, 'atoms-sim-requests.log');

const DEFAULT_DATA_DIR = path.join(__dirname, 'data');
const DATA_DIR = process.env.ATOMS_SIM_DATA_DIR
  ? path.resolve(process.env.ATOMS_SIM_DATA_DIR)
  : DEFAULT_DATA_DIR;
const STORE_FILE = process.env.ATOMS_SIM_STORE_FILE
  ? path.resolve(process.env.ATOMS_SIM_STORE_FILE)
  : path.join(DATA_DIR, 'atoms-sim-store.json');
const RESET_STORE_ON_START = String(process.env.RESET_ATOMS_SIM_STORE || 'false').toLowerCase() === 'true';

const schemaPath = path.join(__dirname, 'schema', 'schema.graphqls');
const typeDefs = fs.readFileSync(schemaPath, 'utf8');

function nowIso() {
  return new Date().toISOString();
}

function readTlsFile(filePath, label) {
  const resolved = String(filePath || '').trim();
  if (!resolved) return null;
  if (!fs.existsSync(resolved)) {
    throw new Error(`[atoms-sim] missing ${label}: ${resolved}`);
  }
  return fs.readFileSync(resolved);
}

function buildTlsOptions() {
  if (!HTTPS_ENABLED) return null;
  const options = {
    requestCert: HTTPS_REQUEST_CLIENT_CERT || HTTPS_REQUIRE_CLIENT_CERT,
    rejectUnauthorized: HTTPS_REQUIRE_CLIENT_CERT,
  };
  if (HTTPS_PFX_FILE) {
    options.pfx = readTlsFile(HTTPS_PFX_FILE, 'HTTPS_PFX_FILE');
    if (HTTPS_PFX_PASSWORD) options.passphrase = HTTPS_PFX_PASSWORD;
  } else {
    if (!HTTPS_CERT_FILE || !HTTPS_KEY_FILE) {
      throw new Error('[atoms-sim] HTTPS_ENABLED=true requires either HTTPS_PFX_FILE or HTTPS_CERT_FILE + HTTPS_KEY_FILE');
    }
    options.cert = readTlsFile(HTTPS_CERT_FILE, 'HTTPS_CERT_FILE');
    options.key = readTlsFile(HTTPS_KEY_FILE, 'HTTPS_KEY_FILE');
  }
  if (HTTPS_CA_FILE) {
    options.ca = readTlsFile(HTTPS_CA_FILE, 'HTTPS_CA_FILE');
  }
  return options;
}

function newUuid() {
  // Node 16+ supports crypto.randomUUID()
  return crypto.randomUUID();
}


function ensureLogDir() {
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  } catch (_err) {
    // ignore
  }
}

function redactHeaders(headers) {
  const out = {};
  if (!headers || typeof headers !== 'object') return out;
  for (const [k, v] of Object.entries(headers)) {
    const key = String(k).toLowerCase();
    if (
      key === 'authorization' ||
      key === 'cookie' ||
      key === 'set-cookie' ||
      key.includes('token') ||
      key.includes('secret') ||
      key.includes('apikey') ||
      key.includes('api-key')
    ) {
      out[key] = '[REDACTED]';
    } else {
      out[key] = v;
    }
  }
  return out;
}

function writeRequestLog(entry) {
  ensureLogDir();

  const line = JSON.stringify(entry);

  // Log to file
  try {
    fs.appendFileSync(LOG_FILE, line + '\n', 'utf8');
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[atoms-sim] unable to write request log:', err);
  }

  // And always print to screen
  // eslint-disable-next-line no-console
  console.log(`[atoms-sim] ${entry.method} ${entry.url} -> ${entry.statusCode} (${entry.durationMs}ms)`);
  // eslint-disable-next-line no-console
  console.log(line);
}

function timingSafeStringEquals(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function extractBearerToken(req) {
  const value = req.headers && req.headers.authorization ? String(req.headers.authorization) : '';
  const match = value.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

function atomsAuthGuard(req, res, next) {
  if (!ATOMS_SIM_REQUIRE_AUTH) return next();

  // Render health checks and local uptime checks must not need a bearer token.
  if (req.path === '/health' || req.originalUrl === '/health') return next();
  if (req.method === 'OPTIONS') return next();

  if (!ATOMS_SIM_AUTH_TOKEN) {
    return res.status(503).json({
      ok: false,
      error: 'ATOMS simulator auth is required but ATOMS_SIM_AUTH_TOKEN is not configured.',
    });
  }

  const supplied = extractBearerToken(req);
  if (supplied && timingSafeStringEquals(supplied, ATOMS_SIM_AUTH_TOKEN)) return next();

  return res.status(401).json({
    ok: false,
    error: 'ATOMS simulator authorization required. Send Authorization: Bearer <token>.',
  });
}

function requestLogger(req, res, next) {
  const startedAt = Date.now();
  const requestId = newUuid();

  const peerCert = req.socket && typeof req.socket.getPeerCertificate === 'function' ? req.socket.getPeerCertificate() : null;
  const entry = {
    ts: nowIso(),
    requestId,
    method: req.method,
    url: req.originalUrl || req.url,
    ip: req.ip,
    headers: redactHeaders(req.headers),
    tls: req.client && typeof req.client.authorized === 'boolean' ? {
      authorized: req.client.authorized,
      authorizationError: req.client.authorizationError || '',
      hasPeerCertificate: !!(peerCert && Object.keys(peerCert).length),
      peerSubject: peerCert && peerCert.subject ? peerCert.subject : null,
      peerIssuer: peerCert && peerCert.issuer ? peerCert.issuer : null,
      peerFingerprint256: peerCert && peerCert.fingerprint256 ? peerCert.fingerprint256 : null,
    } : null,
  };

  let finalized = false;
  function finalize(eventName) {
    if (finalized) return;
    finalized = true;

    entry.event = eventName;
    entry.statusCode = res.statusCode;
    entry.durationMs = Date.now() - startedAt;

    if (req.query && typeof req.query === 'object' && Object.keys(req.query).length) {
      entry.query = req.query;
    }
    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length) {
      entry.body = req.body;
    }

    writeRequestLog(entry);
  }

  res.on('finish', () => finalize('finish'));
  res.on('close', () => finalize('close'));

  next();
}

function astToJsValue(ast) {
  switch (ast.kind) {
    case Kind.NULL:
      return null;
    case Kind.STRING:
    case Kind.ENUM:
      return ast.value;
    case Kind.INT:
      // keep as number
      return Number(ast.value);
    case Kind.FLOAT:
      return Number(ast.value);
    case Kind.BOOLEAN:
      return ast.value;
    case Kind.LIST:
      return ast.values.map(astToJsValue);
    case Kind.OBJECT: {
      const out = {};
      for (const field of ast.fields) {
        out[field.name.value] = astToJsValue(field.value);
      }
      return out;
    }
    default:
      return null;
  }
}

function makePassThroughScalar(name, description) {
  return new GraphQLScalarType({
    name,
    description,
    serialize: (v) => v,
    parseValue: (v) => v,
    parseLiteral: (ast) => astToJsValue(ast),
  });
}

const JSONScalar = makePassThroughScalar('JSON', 'Arbitrary JSON value');
const ACMScalar = makePassThroughScalar('ACM', 'Access Control Marking (CAPCO-like)');
const PreferencesScalar = makePassThroughScalar('Preferences', 'User preferences JSON blob');
const GeoJSONScalar = makePassThroughScalar('GeoJSON', 'GeoJSON geometry');

const DateTimeScalar = new GraphQLScalarType({
  name: 'DateTime',
  description: 'ISO-8601 date-time string',
  serialize: (v) => (v == null ? null : String(v)),
  parseValue: (v) => (v == null ? null : String(v)),
  parseLiteral: (ast) => {
    const v = astToJsValue(ast);
    return v == null ? null : String(v);
  },
});

const DateScalar = new GraphQLScalarType({
  name: 'Date',
  description: 'ISO-8601 date string',
  serialize: (v) => (v == null ? null : String(v)),
  parseValue: (v) => (v == null ? null : String(v)),
  parseLiteral: (ast) => {
    const v = astToJsValue(ast);
    return v == null ? null : String(v);
  },
});

const UUIDScalar = new GraphQLScalarType({
  name: 'UUID',
  description: 'UUID string',
  serialize: (v) => (v == null ? null : String(v)),
  parseValue: (v) => (v == null ? null : String(v)),
  parseLiteral: (ast) => {
    const v = astToJsValue(ast);
    return v == null ? null : String(v);
  },
});

const LongScalar = new GraphQLScalarType({
  name: 'Long',
  description: '64-bit integer (simulated using JS Number)',
  serialize: (v) => (v == null ? null : Number(v)),
  parseValue: (v) => (v == null ? null : Number(v)),
  parseLiteral: (ast) => {
    const v = astToJsValue(ast);
    return v == null ? null : Number(v);
  },
});

function makeRollupAcm() {
  // Keep it simple for the simulator.
  return { classif: 'U', owner_prod: ['USA'], version: '0.0.0-sim' };
}

function makeVerification(userId = 'atoms-sim') {
  return { timestamp: nowIso(), userId };
}

function makeCustodyStatus() {
  return { category: 'UNKNOWN', timestamp: nowIso() };
}

function makeEmptyPage(data = []) {
  return {
    totalSize: data.length,
    totalSizeExceeded: false,
    rollupAcm: makeRollupAcm(),
    data,
  };
}

function normalizeContainsQuery(stringQuery) {
  // Many *Query inputs use nested StringQuery objects.
  // Keep the schema-compatible input shape ({ contains: "foo" }) but make the
  // simulator forgiving for field testing: case-insensitive and tolerant of
  // analyst-entered wildcard wrappers like *Federal*.
  if (!stringQuery || typeof stringQuery !== 'object') return null;
  if (typeof stringQuery.contains === 'string') {
    const raw = stringQuery.contains.trim();
    const contains = raw.replace(/^\*+/, '').replace(/\*+$/, '');
    return { contains };
  }
  return null;
}

function matchesContains(value, containsQuery) {
  if (!containsQuery) return true;
  const needle = String(containsQuery.contains ?? '').toLowerCase();
  if (!needle) return true;
  const v = String(value ?? '').toLowerCase();
  return v.includes(needle);
}

// -----------------------------
// In-memory data store
// -----------------------------

const db = {
  originators: new Map(),
  providers: new Map(),
  sources: new Map(),
  nodes: new Map(),
  attributes: new Map(),
  relationships: new Map(),
};

const STORE_COLLECTIONS = ['originators', 'providers', 'sources', 'nodes', 'attributes', 'relationships'];

function storeCounts() {
  const counts = {};
  for (const name of STORE_COLLECTIONS) counts[name] = db[name].size;
  return counts;
}

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function serializeStore(reason = 'save') {
  const data = {};
  for (const name of STORE_COLLECTIONS) {
    data[name] = Array.from(db[name].values());
  }
  return {
    schemaVersion: 1,
    savedUtc: nowIso(),
    counts: storeCounts(),
    data,
    reason,
  };
}

function saveStore(reason = 'mutation') {
  try {
    ensureDataDir();
    fs.writeFileSync(STORE_FILE, JSON.stringify(serializeStore(reason), null, 2), 'utf8');
    console.log(`[atoms-sim] saved store (${reason}) ${JSON.stringify(storeCounts())} -> ${STORE_FILE}`);
  } catch (err) {
    console.error('[atoms-sim] failed to save store:', err);
  }
}

function loadStore() {
  if (RESET_STORE_ON_START) {
    try {
      if (fs.existsSync(STORE_FILE)) fs.unlinkSync(STORE_FILE);
      console.log(`[atoms-sim] RESET_ATOMS_SIM_STORE=true; removed ${STORE_FILE}`);
    } catch (err) {
      console.error('[atoms-sim] failed to reset store:', err);
    }
    return false;
  }

  if (!fs.existsSync(STORE_FILE)) {
    console.log(`[atoms-sim] no persisted store found at ${STORE_FILE}`);
    return false;
  }

  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
    const data = parsed && parsed.data ? parsed.data : {};
    for (const name of STORE_COLLECTIONS) {
      db[name].clear();
      const rows = Array.isArray(data[name]) ? data[name] : [];
      for (const row of rows) {
        if (row && row.id) db[name].set(row.id, row);
      }
    }
    console.log(`[atoms-sim] loaded store ${JSON.stringify(storeCounts())} <- ${STORE_FILE}`);
    return true;
  } catch (err) {
    console.error('[atoms-sim] failed to load persisted store:', err);
    return false;
  }
}

function upsert(map, obj, reason = null) {
  map.set(obj.id, obj);
  if (reason) saveStore(`upsert:${reason}`);
  return obj;
}

function getById(map, id) {
  return map.get(id) || null;
}

function listAll(map) {
  return Array.from(map.values());
}

function nextVersion(existing) {
  const v = existing && typeof existing.version === 'number' ? existing.version : 0;
  return v + 1;
}

function ensureArray(v) {
  if (Array.isArray(v)) return v;
  if (v == null) return [];
  return [v];
}

function deriveNameFromIri(iri) {
  if (!iri) return 'Unknown';
  const s = String(iri);
  const parts = s.split(/[\/\\#]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : s;
}

// -----------------------------
// ATOMS-ish builders
// -----------------------------

function buildOriginatorFromInput(input, existing) {
  const id = existing?.id || newUuid();
  return {
    id,
    version: nextVersion(existing),
    acm: input.acm ?? existing?.acm ?? makeRollupAcm(),
    tags: ensureArray(input.tags ?? existing?.tags),
    name: input.name ?? existing?.name ?? 'Unnamed Originator',
    description: input.description ?? existing?.description ?? '',
  };
}

function buildProviderFromInput(input, existing) {
  const id = existing?.id || newUuid();
  return {
    id,
    version: nextVersion(existing),
    acm: input.acm ?? existing?.acm ?? makeRollupAcm(),
    tags: ensureArray(input.tags ?? existing?.tags),
    name: input.name ?? existing?.name ?? 'Unnamed Provider',
    url: input.url ?? existing?.url ?? null,
    description: input.description ?? existing?.description ?? '',
    defaultAcm: input.defaultAcm ?? existing?.defaultAcm ?? null,
    originatorId: input.originatorId ?? existing?.originatorId ?? null,
  };
}

function buildSourceFromInput(input, existing) {
  const id = existing?.id || newUuid();
  return {
    id,
    version: nextVersion(existing),
    acm: input.acm ?? existing?.acm ?? makeRollupAcm(),
    tags: ensureArray(input.tags ?? existing?.tags),
    name: input.name ?? existing?.name ?? 'Unnamed Source',
    description: input.description ?? existing?.description ?? null,
    dateOfReport: input.dateOfReport ?? existing?.dateOfReport ?? nowIso(),
    dateOfInformation: input.dateOfInformation ?? existing?.dateOfInformation ?? nowIso(),
    dateOfCreation: existing?.dateOfCreation ?? nowIso(),
    primaryTopic: input.primaryTopic ?? existing?.primaryTopic ?? null,
    secondaryTopic: input.secondaryTopic ?? existing?.secondaryTopic ?? null,
    providerId: input.providerId ?? existing?.providerId ?? null,
    identifier: input.identifier ?? existing?.identifier ?? id,
    uri: input.uri ?? existing?.uri ?? null,
    dataAcm: input.dataAcm ?? existing?.dataAcm ?? makeRollupAcm(),
    lastVerified: makeVerification(),
  };
}

function buildNodeFromInput(input, existing) {
  const id = existing?.id || newUuid();
  const classIri = input.classIri ?? existing?.classIri ?? 'https://example.invalid/Unknown';
  return {
    id,
    version: nextVersion(existing),
    acm: input.acm ?? existing?.acm ?? makeRollupAcm(),
    tags: ensureArray(input.tags ?? existing?.tags),
    labels: ensureArray(input.labels ?? existing?.labels),
    eoid: existing?.eoid ?? null,
    eoidHistory: ensureArray(existing?.eoidHistory),
    guideId: existing?.guideId ?? null,
    guideIdHistory: ensureArray(existing?.guideIdHistory),
    name: input.name ?? existing?.name ?? 'Unnamed Node',
    tier: input.tier ?? existing?.tier ?? 'UNKNOWN',
    domain: input.domain ?? existing?.domain ?? 'UNKNOWN',
    classIri,
    className: existing?.className ?? deriveNameFromIri(classIri),
    symbolIdCode: input.symbolIdCode ?? existing?.symbolIdCode ?? null,
    ifcCodes: ensureArray(input.ifcCodes ?? existing?.ifcCodes),
    allegiance: input.allegiance ?? existing?.allegiance ?? null,
    allegianceAor: existing?.allegianceAor ?? null,
    currentAor: existing?.currentAor ?? null,
    isNso: Boolean(input.isNso ?? existing?.isNso ?? false),
    trackProviderId: input.trackProviderId ?? existing?.trackProviderId ?? null,

    // Required fields
    permissions: ['CREATE', 'READ', 'UPDATE', 'DELETE'],
    lastVerified: makeVerification(),
    custodyStatus: makeCustodyStatus(),
  };
}

function buildAttributeFromInput(input, existing) {
  const id = existing?.id || newUuid();
  const iri = input.attributeIri ?? existing?.attributeIri ?? 'https://example.invalid/attr';
  return {
    id,
    version: nextVersion(existing),
    acm: input.acm ?? existing?.acm ?? makeRollupAcm(),
    tags: ensureArray(input.tags ?? existing?.tags),
    labels: ensureArray(input.labels ?? existing?.labels),
    attributeIri: iri,
    attributeName: existing?.attributeName ?? deriveNameFromIri(iri),
    attributeValue: input.attributeValue ?? existing?.attributeValue ?? '',
    attributeDisplayValue: input.attributeDisplayValue ?? existing?.attributeDisplayValue ?? null,
    attributeNormalizedValue: input.attributeNormalizedValue ?? existing?.attributeNormalizedValue ?? null,
    attributeType: input.attributeType ?? existing?.attributeType ?? 'STRING',
    geometry: input.geometry ?? existing?.geometry ?? null,
    confidence: input.confidence ?? existing?.confidence ?? 'UNKNOWN',
    sourceType: input.sourceType ?? existing?.sourceType ?? null,
    sourceId: input.sourceId ?? existing?.sourceId ?? null,
    nodeId: input.nodeId ?? existing?.nodeId ?? null,
    observationId: input.observationId ?? existing?.observationId ?? null,
    activityId: input.activityId ?? existing?.activityId ?? null,

    authorityValue: input.authorityValue ?? existing?.authorityValue ?? 'DIAP',
    authoritySetBy: existing?.authoritySetBy ?? 'atoms-sim',
    authoritySetAtTime: existing?.authoritySetAtTime ?? nowIso(),

    valueStart: input.valueStart ?? existing?.valueStart ?? null,
    valueEnd: input.valueEnd ?? existing?.valueEnd ?? null,

    isMutable: Boolean(input.isMutable ?? existing?.isMutable ?? true),
    isReviewed: Boolean(input.isReviewed ?? existing?.isReviewed ?? false),
    isAuthoritative: Boolean(input.isAuthoritative ?? existing?.isAuthoritative ?? false),
    isUserEntered: Boolean(input.isUserEntered ?? existing?.isUserEntered ?? false),
    reviewedBy: existing?.reviewedBy ?? null,
    reviewedAt: existing?.reviewedAt ?? null,

    lastVerified: makeVerification(),
  };
}

function buildRelationshipFromInput(input, existing) {
  const id = existing?.id || newUuid();
  const iri = input.objectPropertyIri ?? existing?.objectPropertyIri ?? 'https://example.invalid/rel';
  return {
    id,
    version: nextVersion(existing),
    acm: input.acm ?? existing?.acm ?? makeRollupAcm(),
    tags: ensureArray(input.tags ?? existing?.tags),
    labels: ensureArray(input.labels ?? existing?.labels),
    name: input.name ?? existing?.name ?? 'relationship',
    startNodeId: input.startNodeId ?? existing?.startNodeId ?? null,
    endNodeId: input.endNodeId ?? existing?.endNodeId ?? null,
    confidence: input.confidence ?? existing?.confidence ?? 'UNKNOWN',
    objectPropertyIri: iri,
    objectPropertyName: existing?.objectPropertyName ?? deriveNameFromIri(iri),
    sourceId: input.sourceId ?? existing?.sourceId ?? null,
    startTime: input.startTime ?? existing?.startTime ?? nowIso(),
    endTime: input.endTime ?? existing?.endTime ?? nowIso(),

    lastVerified: makeVerification(),
  };
}

function seedDemoData() {
  // Create a small chain so a developer can immediately run a few queries.
  const originator = buildOriginatorFromInput({
    name: 'ADSB',
    description: 'Automatic Dependent Surveillance–Broadcast',
    tags: ['Flight', 'Broadcast'],
    acm: makeRollupAcm(),
  });
  upsert(db.originators, originator);

  const provider = buildProviderFromInput({
    name: 'globe.adsbexchange.com',
    description: 'ADSB website',
    tags: ['web', 'map'],
    url: 'https://globe.adsbexchange.com',
    originatorId: originator.id,
    defaultAcm: makeRollupAcm(),
    acm: makeRollupAcm(),
  });
  upsert(db.providers, provider);

  const source = buildSourceFromInput({
    name: 'globe.adsbexchange.com/?icao=ade252',
    description: 'demo source',
    providerId: provider.id,
    identifier: 'external1',
    uri: 'http://external/1',
    dateOfReport: nowIso(),
    dateOfInformation: nowIso(),
    primaryTopic: 'Aircraft',
    secondaryTopic: 'Flight Path',
    tags: ['Flight', 'Aircraft'],
    acm: makeRollupAcm(),
    dataAcm: makeRollupAcm(),
  });
  upsert(db.sources, source);

  const node = buildNodeFromInput({
    name: 'A00C42',
    tier: 'PRIMARY',
    domain: 'AIR',
    classIri: 'https://foundry.ai.mil/DICO/v3.1.0/aircraft',
    tags: ['aircraft', 'commercial'],
    labels: ['demo'],
    ifcCodes: [],
    acm: makeRollupAcm(),
    isNso: false,
  });
  upsert(db.nodes, node);

  const attr = buildAttributeFromInput({
    attributeIri: 'https://foundry.ai.mil/INDOPACOM/v5/TailNumber',
    attributeValue: 'N102BG',
    attributeType: 'STRING',
    confidence: 'HIGH',
    tags: ['Flight'],
    sourceId: source.id,
    nodeId: node.id,
    acm: makeRollupAcm(),
  });
  upsert(db.attributes, attr);
}

const loadedPersistedStore = loadStore();
if (!loadedPersistedStore && SEED_DEMO_DATA) {
  seedDemoData();
  saveStore('seed');
}

// -----------------------------
// GraphQL resolvers
// -----------------------------

const resolvers = {
  // Custom scalars
  JSON: JSONScalar,
  ACM: ACMScalar,
  Preferences: PreferencesScalar,
  GeoJSON: GeoJSONScalar,
  DateTime: DateTimeScalar,
  Date: DateScalar,
  UUID: UUIDScalar,
  Long: LongScalar,

  Query: {
    greeting: () => 'ATOMS simulator is running',

    // Originators
    originator: (_, { query }) => getById(db.originators, query.id),
    originators: (_, { query }) => {
      let items = listAll(db.originators);
      if (query?.ids?.length) items = items.filter((o) => query.ids.includes(o.id));
      if (query?.tags?.length) items = items.filter((o) => o.tags?.some((t) => query.tags.includes(t)));
      const nameContains = normalizeContainsQuery(query?.name);
      if (nameContains) items = items.filter((o) => matchesContains(o.name, nameContains));
      return makeEmptyPage(items);
    },
    originatorHistory: () => makeEmptyPage([]),

    // Providers
    provider: (_, { query }) => getById(db.providers, query.id),
    providers: (_, { query }) => {
      let items = listAll(db.providers);
      if (query?.ids?.length) items = items.filter((p) => query.ids.includes(p.id));
      if (query?.originatorIds?.length) items = items.filter((p) => query.originatorIds.includes(p.originatorId));
      const nameContains = normalizeContainsQuery(query?.name);
      if (nameContains) items = items.filter((p) => matchesContains(p.name, nameContains));
      return makeEmptyPage(items);
    },
    providerHistory: () => makeEmptyPage([]),

    // Sources
    source: (_, { query }) => getById(db.sources, query.id),
    sources: (_, { query }) => {
      let items = listAll(db.sources);
      if (query?.ids?.length) items = items.filter((s) => query.ids.includes(s.id));
      if (query?.providerIds?.length) items = items.filter((s) => query.providerIds.includes(s.providerId));
      const textContains = normalizeContainsQuery(query?.text);
      if (textContains) {
        items = items.filter((s) =>
          matchesContains(s.name, textContains) ||
          matchesContains(s.description, textContains) ||
          matchesContains(s.identifier, textContains) ||
          matchesContains(s.uri, textContains) ||
          matchesContains(s.primaryTopic, textContains) ||
          matchesContains(s.secondaryTopic, textContains) ||
          (Array.isArray(s.tags) && s.tags.some((t) => matchesContains(t, textContains)))
        );
      }
      return makeEmptyPage(items);
    },
    sourceHistory: () => makeEmptyPage([]),

    // Nodes
    node: (_, { query }) => getById(db.nodes, query.id),
    nodes: (_, { query }) => {
      let items = listAll(db.nodes);
      if (query?.ids?.length) items = items.filter((n) => query.ids.includes(n.id));
      const nameContains = normalizeContainsQuery(query?.name);
      if (nameContains) items = items.filter((n) => matchesContains(n.name, nameContains));
      if (query?.classIris?.length) items = items.filter((n) => query.classIris.includes(n.classIri));
      console.log(`[atoms-sim] nodes query returned ${items.length}`);
      return makeEmptyPage(items);
    },
    nodeHistory: () => makeEmptyPage([]),

    // Attributes
    attribute: (_, { query }) => getById(db.attributes, query.id),
    attributes: (_, { query }) => {
      let items = listAll(db.attributes);
      if (query?.ids?.length) items = items.filter((a) => query.ids.includes(a.id));
      if (query?.sourceIds?.length) items = items.filter((a) => query.sourceIds.includes(a.sourceId));
      if (query?.nodeIds?.length) items = items.filter((a) => a.nodeId && query.nodeIds.includes(a.nodeId));
      const attributeNameContains = normalizeContainsQuery(query?.attributeName);
      if (attributeNameContains) items = items.filter((a) => matchesContains(a.attributeName, attributeNameContains));
      const attributeValueContains = normalizeContainsQuery(query?.attributeValue);
      if (attributeValueContains) items = items.filter((a) => matchesContains(a.attributeValue, attributeValueContains));
      const attributeDisplayValueContains = normalizeContainsQuery(query?.attributeDisplayValue);
      if (attributeDisplayValueContains) items = items.filter((a) => matchesContains(a.attributeDisplayValue, attributeDisplayValueContains));
      const attributeNormalizedValueContains = normalizeContainsQuery(query?.attributeNormalizedValue);
      if (attributeNormalizedValueContains) items = items.filter((a) => matchesContains(a.attributeNormalizedValue, attributeNormalizedValueContains));
      console.log(`[atoms-sim] attributes query returned ${items.length}`);
      return makeEmptyPage(items);
    },
    attributeHistory: () => makeEmptyPage([]),

    // Relationships
    relationship: (_, { query }) => getById(db.relationships, query.id),
    relationships: (_, { query }) => {
      let items = listAll(db.relationships);
      if (query?.ids?.length) items = items.filter((r) => query.ids.includes(r.id));
      if (query?.sourceIds?.length) items = items.filter((r) => query.sourceIds.includes(r.sourceId));
      const nameContains = normalizeContainsQuery(query?.name);
      if (nameContains) items = items.filter((r) => matchesContains(r.name, nameContains));
      const objectPropertyNameContains = normalizeContainsQuery(query?.objectPropertyName);
      if (objectPropertyNameContains) items = items.filter((r) => matchesContains(r.objectPropertyName, objectPropertyNameContains));
      console.log(`[atoms-sim] relationships query returned ${items.length}`);
      return makeEmptyPage(items);
    },
    relationshipHistory: () => makeEmptyPage([]),

    // A couple misc helpers that are handy for UI wiring later
    activityStates: () => ['UNKNOWN', 'ACTIVE', 'INACTIVE'],
    getAllCountries: () => [
      { countryCode: 'US', countryName: 'United States' },
      { countryCode: 'IT', countryName: 'Italy' },
    ],
    getAllCocoms: () => ['NORTHCOM', 'EUCOM', 'INDOPACOM'],
    groups: () => [
      { name: 'demo-group', group: 'demo-group' },
    ],
  },

  Mutation: {
    // Originators
    createOriginator: (_, { input }) => {
      const obj = buildOriginatorFromInput(input);
      return upsert(db.originators, obj, 'originators');
    },
    updateOriginator: (_, { input }) => {
      const existing = getById(db.originators, input.id);
      const obj = buildOriginatorFromInput(input, existing);
      return upsert(db.originators, obj, 'originators');
    },
    deleteOriginator: (_, { input }) => {
      const existed = db.originators.delete(input.id);
      if (existed) saveStore('delete:originators');
      return existed;
    },
    restoreOriginator: () => null,

    // Providers
    createProvider: (_, { input }) => {
      const obj = buildProviderFromInput(input);
      return upsert(db.providers, obj, 'providers');
    },
    updateProvider: (_, { input }) => {
      const existing = getById(db.providers, input.id);
      const obj = buildProviderFromInput(input, existing);
      return upsert(db.providers, obj, 'providers');
    },
    deleteProvider: (_, { input }) => {
      const existed = db.providers.delete(input.id);
      if (existed) saveStore('delete:providers');
      return existed;
    },
    restoreProvider: () => null,

    // Sources
    createSource: (_, { input }) => {
      const obj = buildSourceFromInput(input);
      return upsert(db.sources, obj, 'sources');
    },
    updateSource: (_, { input }) => {
      const existing = getById(db.sources, input.id);
      const obj = buildSourceFromInput(input, existing);
      return upsert(db.sources, obj, 'sources');
    },
    deleteSource: (_, { input }) => {
      const existed = db.sources.delete(input.id);
      if (existed) saveStore('delete:sources');
      return existed;
    },
    restoreSource: () => null,
    verifySource: () => true,

    // Nodes
    createNode: (_, { input }) => {
      const obj = buildNodeFromInput(input);
      return upsert(db.nodes, obj, 'nodes');
    },
    updateNode: (_, { input }) => {
      const existing = getById(db.nodes, input.id);
      const obj = buildNodeFromInput(input, existing);
      return upsert(db.nodes, obj, 'nodes');
    },
    deleteNode: (_, { input }) => {
      const existed = db.nodes.delete(input.id);
      if (existed) saveStore('delete:nodes');
      return existed;
    },
    restoreNode: () => null,
    verifyNode: () => true,

    // Attributes
    createAttribute: (_, { input }) => {
      const obj = buildAttributeFromInput(input);
      return upsert(db.attributes, obj, 'attributes');
    },
    updateAttribute: (_, { input }) => {
      const existing = getById(db.attributes, input.id);
      const obj = buildAttributeFromInput(input, existing);
      return upsert(db.attributes, obj, 'attributes');
    },
    deleteAttribute: (_, { input }) => {
      const existed = db.attributes.delete(input.id);
      if (existed) saveStore('delete:attributes');
      return existed;
    },
    restoreAttribute: () => null,
    verifyAttribute: () => true,

    // Relationships
    createRelationship: (_, { input }) => {
      const obj = buildRelationshipFromInput(input);
      return upsert(db.relationships, obj, 'relationships');
    },
    updateRelationship: (_, { input }) => {
      const existing = getById(db.relationships, input.id);
      const obj = buildRelationshipFromInput(input, existing);
      return upsert(db.relationships, obj, 'relationships');
    },
    deleteRelationship: (_, { input }) => {
      const existed = db.relationships.delete(input.id);
      if (existed) saveStore('delete:relationships');
      return existed;
    },
    restoreRelationship: () => null,
    verifyRelationship: () => true,

    // Misc
    cleanUpSmokeTestData: () => {
      db.originators.clear();
      db.providers.clear();
      db.sources.clear();
      db.nodes.clear();
      db.attributes.clear();
      db.relationships.clear();
      if (SEED_DEMO_DATA) seedDemoData();
      saveStore('cleanup');
      return true;
    },
    purgeTaggedData: () => true,

    // Default fallbacks for the rest of the schema (not simulated yet)
    // Returning null is OK for most mutations because return types are nullable.
  },
};

async function main() {
  const app = express();
  app.disable('x-powered-by');

  ensureLogDir();
  // eslint-disable-next-line no-console
  console.log(`[atoms-sim] request log: ${LOG_FILE}`);

  app.use(cors());
  app.use(requestLogger);
  app.use(bodyParser.json({ limit: '2mb' }));
  app.use(atomsAuthGuard);

  app.use((req, res, next) => {
    if (!HTTPS_REQUIRE_CLIENT_CERT) return next();
    if (req.client && req.client.authorized) return next();
    res.status(401).json({ ok: false, error: 'Client certificate required', authorizationError: req.client && req.client.authorizationError ? req.client.authorizationError : '' });
  });

  app.get('/health', (req, res) => {
    const peerCert = req.socket && typeof req.socket.getPeerCertificate === 'function' ? req.socket.getPeerCertificate() : null;
    res.json({
      ok: true,
      service: 'atoms-sim',
      time: nowIso(),
      auth: {
        required: ATOMS_SIM_REQUIRE_AUTH,
        tokenConfigured: !!ATOMS_SIM_AUTH_TOKEN,
      },
      tls: {
        httpsEnabled: HTTPS_ENABLED,
        requestClientCertificate: HTTPS_REQUEST_CLIENT_CERT || HTTPS_REQUIRE_CLIENT_CERT,
        requireClientCertificate: HTTPS_REQUIRE_CLIENT_CERT,
        clientAuthorized: req.client ? !!req.client.authorized : false,
        authorizationError: req.client && req.client.authorizationError ? req.client.authorizationError : '',
        peerSubject: peerCert && peerCert.subject ? peerCert.subject : null,
        peerIssuer: peerCert && peerCert.issuer ? peerCert.issuer : null,
      },
    });
  });

  const server = new ApolloServer({
    typeDefs,
    resolvers,
    // Keep introspection on for local dev.
    introspection: true,
  });

  await server.start();
  app.use(GRAPHQL_PATH, expressMiddleware(server));

  const tlsOptions = buildTlsOptions();
  const listener = HTTPS_ENABLED ? https.createServer(tlsOptions, app) : http.createServer(app);
  listener.listen(PORT, HOST, () => {
    const scheme = HTTPS_ENABLED ? 'https' : 'http';
    // eslint-disable-next-line no-console
    console.log(`[atoms-sim] listening on ${scheme}://${HOST}:${PORT}${GRAPHQL_PATH}`);
    if (HTTPS_ENABLED) {
      // eslint-disable-next-line no-console
      console.log(`[atoms-sim] mTLS requestCert=${tlsOptions.requestCert} rejectUnauthorized=${tlsOptions.rejectUnauthorized}`);
    }
  });
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('[atoms-sim] fatal error:', err);
  process.exit(1);
});
