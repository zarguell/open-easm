// Design tokens matching DESIGN.md — single source of truth for the UI
export const colors = {
  primary: '#00d992',
  primarySoft: '#2fd6a1',
  primaryDeep: '#10b981',
  onPrimary: '#101010',
  canvas: '#101010',
  canvasSoft: '#1a1a1a',
  canvasElevated: '#222222',
  hairline: '#3d3a39',
  hairlineSoft: '#57534e',
  ink: '#f2f2f2',
  inkStrong: '#ffffff',
  body: '#bdbdbd',
  mute: '#8b949e',
  entityAsn: '#f59e0b',
  entityIpRange: '#f97316',
  entityIp: '#ef4444',
  entityHostname: '#06b6d4',
  entityDomain: '#00d992',
  entityCertificate: '#a855f7',
  entityOrg: '#94a3b8',
  statusSuccess: '#00d992',
  statusError: '#ef4444',
  statusWarning: '#f59e0b',
  statusRunning: '#3b82f6',
  statusPending: '#6b7280',
} as const

export const entityColors: Record<string, string> = {
  asn: colors.entityAsn,
  ip_range: colors.entityIpRange,
  ip: colors.entityIp,
  hostname: colors.entityHostname,
  domain: colors.entityDomain,
  certificate: colors.entityCertificate,
  org: colors.entityOrg,
}

export const statusColors: Record<string, string> = {
  completed: colors.statusSuccess,
  running: colors.statusRunning,
  pending: colors.statusPending,
  failed: colors.statusError,
}

export const ENTITY_TYPES = ['asn', 'ip_range', 'ip', 'hostname', 'domain', 'certificate', 'org'] as const
export type EntityType = (typeof ENTITY_TYPES)[number]

export const ENTITY_LABELS: Record<EntityType, string> = {
  asn: 'ASN',
  ip_range: 'IP Range',
  ip: 'IP',
  hostname: 'Hostname',
  domain: 'Domain',
  certificate: 'Certificate',
  org: 'Org',
}
