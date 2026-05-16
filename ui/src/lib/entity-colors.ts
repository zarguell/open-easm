import { colors, ENTITY_TYPES, type EntityType } from '../DESIGN_TOKENS'

export function getEntityColor(entityType: string): string {
  const normalized = entityType.toLowerCase()
  const map: Record<string, string> = {
    asn: colors.entityAsn,
    ip_range: colors.entityIpRange,
    ip: colors.entityIp,
    hostname: colors.entityHostname,
    domain: colors.entityDomain,
    certificate: colors.entityCertificate,
    org: colors.entityOrg,
  }
  return map[normalized] ?? colors.mute
}

export function getEntityBgColor(entityType: string): string {
  const color = getEntityColor(entityType)
  return `${color}1f` // 12% opacity hex
}

export function getEntityLabel(entityType: string): string {
  const normalized = entityType.toLowerCase()
  const map: Record<string, string> = {
    asn: 'ASN',
    ip_range: 'IP Range',
    ip: 'IP',
    hostname: 'Hostname',
    domain: 'Domain',
    certificate: 'Certificate',
    org: 'Org',
  }
  return map[normalized] ?? entityType
}

export { ENTITY_TYPES, type EntityType }
