import type { FC } from 'react'

type UnknownRecord = Record<string, unknown>

const isRecord = (value: unknown): value is UnknownRecord =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const readRecord = (record: UnknownRecord | undefined, key: string): UnknownRecord | undefined => {
  const value = record?.[key]
  return isRecord(value) ? value : undefined
}

const readText = (record: UnknownRecord | undefined, key: string): string | undefined => {
  const value = record?.[key]
  if (typeof value === 'string' && value.trim()) return value
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  return undefined
}

const Section: FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className="space-y-2">
    <h4 className="font-mono text-[10px] font-semibold uppercase tracking-wider text-mute">{title}</h4>
    <div className="space-y-1">{children}</div>
  </div>
)

const KV: FC<{ label: string; value: string | undefined; mono?: boolean; tone?: string }> = ({
  label, value, mono, tone,
}) => {
  if (!value) return null
  return (
    <div className="flex justify-between text-xs px-2 py-1 rounded bg-canvas-soft">
      <span className="text-mute">{label}</span>
      <span
        className={mono ? 'font-mono text-ink' : 'text-ink'}
        style={tone ? { color: tone } : undefined}
      >
        {value}
      </span>
    </div>
  )
}

const riskTone = (level: string | undefined): string | undefined => {
  if (level === 'critical' || level === 'high') return '#ef4444'
  if (level === 'medium') return '#f59e0b'
  if (level === 'low' || level === 'info') return '#00d992'
  return undefined
}

const ThreatIntelSection: FC<{ data: UnknownRecord }> = ({ data }) => {
  const sources = Object.keys(data).filter(k => isRecord(data[k]))
  if (sources.length === 0) return null

  return (
    <Section title="Threat Intelligence">
      {sources.map(source => {
        const info = data[source] as UnknownRecord
        return (
          <div key={source} className="space-y-1">
            <div className="text-xs font-semibold text-ink px-2">{source}</div>
            {Object.entries(info).map(([k, v]) => (
              <KV
                key={k}
                label={k.replace(/_/g, ' ')}
                value={typeof v === 'object' ? JSON.stringify(v) : String(v)}
                mono={typeof v === 'number' || typeof v === 'boolean'}
                tone={k === 'classification' || k === 'risk' ? riskTone(String(v)) : undefined}
              />
            ))}
          </div>
        )
      })}
    </Section>
  )
}

const TechnologiesSection: FC<{ data: unknown[] }> = ({ data }) => {
  if (!data.length) return null
  return (
    <Section title="Technologies">
      <div className="flex flex-wrap gap-1">
        {data.map((tech, i) => {
          const t = isRecord(tech) ? tech : {}
          const name = readText(t, 'name') || 'unknown'
          const version = readText(t, 'version')
          return (
            <span
              key={i}
              className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] bg-canvas-soft text-ink"
            >
              {name}{version ? ` ${version}` : ''}
            </span>
          )
        })}
      </div>
    </Section>
  )
}

const PortsSection: FC<{ data: unknown[] }> = ({ data }) => {
  if (!data.length) return null
  return (
    <Section title="Open Ports">
      <div className="space-y-1">
        {data.map((p, i) => {
          const port = isRecord(p) ? p : {}
          return (
            <div key={i} className="flex items-center gap-2 text-xs px-2 py-1 rounded bg-canvas-soft">
              <span className="font-mono text-ink font-semibold">{readText(port, 'port')}</span>
              <span className="text-mute">/</span>
              <span className="font-mono text-mute">{readText(port, 'protocol')}</span>
              <span className="text-ink">{readText(port, 'service')}</span>
            </div>
          )
        })}
      </div>
    </Section>
  )
}

const DNSRecordsSection: FC<{ data: UnknownRecord }> = ({ data }) => {
  const records = Object.entries(data)
  if (records.length === 0) return null
  return (
    <Section title="DNS Records">
      {records.map(([type, value]) => (
        <KV
          key={type}
          label={type.toUpperCase()}
          value={typeof value === 'string' ? value : JSON.stringify(value)}
          mono
        />
      ))}
    </Section>
  )
}

const GeoIPSection: FC<{ data: UnknownRecord }> = ({ data }) => (
  <Section title="Geo Location">
    <KV label="Country" value={readText(data, 'country_name')} />
    <KV label="City" value={readText(data, 'city')} />
    <KV label="Region" value={readText(data, 'region')} />
    <KV label="Org" value={readText(data, 'org')} />
    <KV label="ASN" value={readText(data, 'asn')} mono />
  </Section>
)

const RDAPSection: FC<{ data: UnknownRecord }> = ({ data }) => (
  <Section title="WHOIS / RDAP">
    <KV label="Registrar" value={readText(data, 'registrar')} />
    <KV label="Registrant" value={readText(data, 'registrant')} />
    <KV label="Nameservers" value={Array.isArray(data.nameservers) ? (data.nameservers as string[]).join(', ') : readText(data, 'nameservers')} mono />
    <KV label="Created" value={readText(data, 'created_date')} />
    <KV label="Expires" value={readText(data, 'expiration_date')} />
  </Section>
)

export const StructuredAttributes: FC<{ attributes: UnknownRecord }> = ({ attributes }) => {
  const sections: React.ReactNode[] = []

  const threatIntel = readRecord(attributes, 'threat_intel')
  if (threatIntel) sections.push(<ThreatIntelSection key="threat_intel" data={threatIntel} />)

  const techs = attributes.technologies
  if (Array.isArray(techs) && techs.length > 0) sections.push(<TechnologiesSection key="tech" data={techs} />)

  const ports = attributes.ports
  if (Array.isArray(ports) && ports.length > 0) sections.push(<PortsSection key="ports" data={ports} />)

  const portScan = attributes.port_scan
  if (isRecord(portScan) && Array.isArray((portScan as UnknownRecord).open_ports)) {
    sections.push(<PortsSection key="port_scan" data={(portScan as UnknownRecord).open_ports as unknown[]} />)
  }

  const dns = readRecord(attributes, 'dns_records') || readRecord(attributes, 'dns')
  if (dns && isRecord(dns)) sections.push(<DNSRecordsSection key="dns" data={dns} />)

  const mx = readRecord(attributes, 'mail_records')
  if (mx) sections.push(<DNSRecordsSection key="mail" data={mx} />)

  const geoip = readRecord(attributes, 'geoip')
  if (geoip) sections.push(<GeoIPSection key="geoip" data={geoip} />)

  const rdap = readRecord(attributes, 'rdap') || readRecord(attributes, 'whois')
  if (rdap) sections.push(<RDAPSection key="rdap" data={rdap} />)

  const takeover = readRecord(attributes, 'subdomain_takeover')
  if (takeover) {
    const vulnerable = readText(takeover, 'vulnerable')
    sections.push(
      <Section key="takeover" title="Subdomain Takeover">
        <KV
          label="Status"
          value={vulnerable === 'true' ? 'VULNERABLE' : vulnerable === 'false' ? 'Safe' : vulnerable}
          tone={vulnerable === 'true' ? '#ef4444' : '#00d992'}
        />
        <KV label="Service" value={readText(takeover, 'service')} />
        <KV label="CNAME" value={readText(takeover, 'cname')} mono />
        <KV label="Fingerprint" value={readText(takeover, 'fingerprint')} />
      </Section>
    )
  }

  const shodan = readRecord(attributes, 'shodan')
  if (shodan) sections.push(<ThreatIntelSection key="shodan" data={{ shodan }} />)

  if (sections.length === 0) return null

  return <div className="space-y-3">{sections}</div>
}
