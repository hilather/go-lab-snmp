export type Problem = {
  type: string;
  title: string;
  status: number;
  detail: string;
  code: string;
};

export type SessionCreated = {
  csrf: string;
  expiresAt: string;
};

export type SessionView = {
  id: string;
  role: string;
  scopes: string[];
  csrf?: string;
  expiresAt?: string;
};

export type RangeSpec = {
  min: number;
  max: number;
};

export type ObjectSpec = {
  oid: string;
  name?: string;
  type: string;
  access: string;
  value?: unknown;
  valueFrom?: string;
  range?: RangeSpec;
  size?: RangeSpec;
};

export type MapSpec = {
  name: string;
  objects: ObjectSpec[];
};

export type MapList = {
  items: MapSpec[];
};

export type CommunitySpec = {
  name: string;
  communityFile: string;
  versions?: string[];
  access: string;
  map: string;
};

export type CommunityList = {
  items: CommunitySpec[];
};

export type USMAuth = {
  protocol: string;
  secretFile: string;
};

export type USMPriv = {
  protocol: string;
  secretFile: string;
};

export type UserSpec = {
  name: string;
  level: string;
  auth?: USMAuth;
  priv?: USMPriv;
  access: string;
  map: string;
};

export type UserList = {
  items: UserSpec[];
};

export type OIDResult = {
  oid: string;
  type?: string;
  value?: unknown;
  exception?: string;
  overlay?: boolean;
};

export type VarBind = {
  oid: string;
  type?: string;
  integer?: number;
  unsigned?: number;
  bytes?: string;
  oidValue?: string;
};

export type Trap = {
  id: string;
  receivedAt?: string;
  version?: string;
  pduType?: string;
  community?: string;
  user?: string;
  remoteAddr?: string;
  enterprise?: string;
  notificationOID?: string;
  varBinds?: VarBind[];
  parseWarning?: string;
  size?: number;
};

export type TrapList = {
  items: Trap[];
  next?: string;
};

export type QueryEntry = {
  type: string;
  identity: string;
  decision: string;
  errorStatus: number;
};

export type QueryList = {
  items: QueryEntry[];
};

export type Feature = {
  id: string;
  apply: "live" | "reset-only" | string;
  path: string;
};

export type FeatureList = {
  items: Feature[];
};

export type Listener = {
  name: string;
  address: string;
};

export type StatusWarning = {
  Code?: string;
  Message?: string;
};

export type Status = {
  ready: boolean;
  hostTime: string;
  listeners: Listener[];
  revisions?: Record<string, unknown>;
  warnings?: StatusWarning[];
};

export type StateView = {
  bootstrapRevision: string;
  runtimeRevision: string;
  generation: number;
  storeGeneration?: number;
  drifted: boolean;
  loadedAt?: string;
  canonical?: unknown;
};

export type TrapStats = {
  messages: number;
  bytes: number;
  generation: number;
  dropped: number;
};

export type Stats = {
  traps: TrapStats;
  overlayGeneration: number;
  queries: number;
};

export type DiffEntry = {
  path: string;
  op: string;
  before?: unknown;
  after?: unknown;
};

export type Warning = {
  Code?: string;
  Message?: string;
};

export type Operation = {
  op: string;
  [key: string]: unknown;
};

export type Plan = {
  previousRevision?: string;
  candidateRevision?: string;
  drifted?: boolean;
  diff?: DiffEntry[];
  warnings?: Warning[];
  operations?: Operation[];
  applied?: boolean;
  generation?: number;
  runtimeRevision?: string;
  storeGeneration?: number;
  auditEventId?: string;
};

export type ChangeIn = {
  expectedRevision: string;
  idempotencyKey?: string;
  reason?: string;
  force?: boolean;
  operations: Operation[];
};

export type AuditEvent = {
  id: string;
  time?: string;
  actorId?: string;
  actorClass?: string;
  transport?: string;
  capability?: string;
  reason?: string;
  previous?: string;
  revision?: string;
  result?: string;
  errorCode?: string;
  diff?: DiffEntry[];
};

export type AuditList = {
  events: AuditEvent[];
};
