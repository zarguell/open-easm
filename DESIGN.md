---
version: "1.0"
name: Open EASM
description: A self-hosted passive External Attack Surface Management monitoring platform whose surface is an unrelenting near-black canvas broken by a single electric-teal accent for discovery and status, entity-type color coding for the attack surface graph, and hairline-bordered data-dense cards — a security operations dashboard that reads like a terminal dressed as a modern SaaS tool.

colors:
  # Brand & Accent
  primary: "#00d992"
  primary-soft: "#2fd6a1"
  primary-deep: "#10b981"
  on-primary: "#101010"

  # Surface
  canvas: "#101010"
  canvas-soft: "#1a1a1a"
  canvas-elevated: "#222222"
  hairline: "#3d3a39"
  hairline-soft: "#57534e"

  # Text
  ink: "#f2f2f2"
  ink-strong: "#ffffff"
  body: "#bdbdbd"
  mute: "#8b949e"

  # Entity Type Colors
  entity-asn: "#f59e0b"
  entity-ip-range: "#f97316"
  entity-ip: "#ef4444"
  entity-hostname: "#06b6d4"
  entity-domain: "#00d992"
  entity-certificate: "#a855f7"
  entity-org: "#94a3b8"

  # Status
  status-success: "#00d992"
  status-error: "#ef4444"
  status-warning: "#f59e0b"
  status-running: "#3b82f6"
  status-pending: "#6b7280"

  # Semantic
  ring-focus: "rgba(0, 217, 146, 0.5)"

typography:
  display-xl:
    fontFamily: "Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: 60px
    fontWeight: 400
    lineHeight: 60px
    letterSpacing: -0.65px
  display-lg:
    fontFamily: "Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: 36px
    fontWeight: 400
    lineHeight: 40px
    letterSpacing: -0.9px
  display-md:
    fontFamily: "Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: 24px
    fontWeight: 700
    lineHeight: 32px
    letterSpacing: -0.6px
  display-sm:
    fontFamily: "Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: 20px
    fontWeight: 600
    lineHeight: 28px
  eyebrow-mono:
    fontFamily: "JetBrains Mono, SFMono-Regular, Menlo, Monaco, Consolas, monospace"
    fontSize: 11px
    fontWeight: 600
    lineHeight: 16px
    letterSpacing: 1.5px
  eyebrow-uppercase:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: 14px
    fontWeight: 600
    lineHeight: 20px
    letterSpacing: 0.45px
  heading-lg:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: 20px
    fontWeight: 600
    lineHeight: 28px
  heading-md:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: 16px
    fontWeight: 600
    lineHeight: 24px
  heading-sm:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: 14px
    fontWeight: 600
    lineHeight: 20px
  body-lg:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: 16px
    fontWeight: 400
    lineHeight: 26px
  body-md:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: 14px
    fontWeight: 400
    lineHeight: 22px
  body-md-strong:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: 14px
    fontWeight: 600
    lineHeight: 22px
  body-sm:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: 13px
    fontWeight: 400
    lineHeight: 18px
  body-sm-strong:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: 13px
    fontWeight: 600
    lineHeight: 18px
  caption:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: 12px
    fontWeight: 400
    lineHeight: 16px
  caption-mono:
    fontFamily: "JetBrains Mono, SFMono-Regular, Menlo, Monaco, Consolas, monospace"
    fontSize: 11px
    fontWeight: 400
    lineHeight: 16px
  code:
    fontFamily: "JetBrains Mono, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, monospace"
    fontSize: 13px
    fontWeight: 400
    lineHeight: 18px
  code-strong:
    fontFamily: "JetBrains Mono, SFMono-Regular, Menlo, Monaco, Consolas, monospace"
    fontSize: 13px
    fontWeight: 550
    lineHeight: 16px
  button-md:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: 14px
    fontWeight: 600
    lineHeight: 20px
  metric-value:
    fontFamily: "JetBrains Mono, SFMono-Regular, Menlo, Monaco, Consolas, monospace"
    fontSize: 32px
    fontWeight: 600
    lineHeight: 36px

rounded:
  none: 0px
  xs: 4px
  sm: 6px
  md: 8px
  lg: 12px
  xl: 16px
  pill: 9999px
  full: 9999px

spacing:
  xxs: 2px
  xs: 4px
  sm: 8px
  md: 12px
  lg: 16px
  xl: 20px
  2xl: 24px
  3xl: 32px
  4xl: 40px
  5xl: 48px
  6xl: 64px

components:
  # ─── Navigation ───
  sidebar:
    backgroundColor: "{colors.canvas}"
    borderColor: "{colors.hairline}"
    width-collapsed: "64px"
    width-expanded: "240px"
  sidebar-item:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.mute}"
    typography: "{typography.body-sm}"
    padding: "{spacing.md} {spacing.lg}"
  sidebar-item-active:
    backgroundColor: "{colors.canvas-soft}"
    textColor: "{colors.primary}"
    typography: "{typography.body-sm-strong}"
    leftIndicator: "{colors.primary}"
    padding: "{spacing.md} {spacing.lg}"
  sidebar-header:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.ink}"
    padding: "{spacing.lg}"

  # ─── Buttons ───
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.button-md}"
    rounded: "{rounded.sm}"
    padding: "{spacing.sm} {spacing.lg}"
  button-outline:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.ink}"
    borderColor: "{colors.hairline}"
    typography: "{typography.button-md}"
    rounded: "{rounded.sm}"
    padding: "{spacing.sm} {spacing.lg}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.primary-soft}"
    typography: "{typography.button-md}"
    rounded: "{rounded.sm}"
    padding: "{spacing.sm} {spacing.lg}"
  button-danger:
    backgroundColor: "{colors.status-error}"
    textColor: "{colors.ink-strong}"
    typography: "{typography.button-md}"
    rounded: "{rounded.sm}"
    padding: "{spacing.sm} {spacing.lg}"

  # ─── Status Badges ───
  badge-success:
    backgroundColor: "rgba(0, 217, 146, 0.12)"
    textColor: "{colors.status-success}"
    typography: "{typography.caption}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xxs} {spacing.sm}"
  badge-error:
    backgroundColor: "rgba(239, 68, 68, 0.12)"
    textColor: "{colors.status-error}"
    typography: "{typography.caption}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xxs} {spacing.sm}"
  badge-warning:
    backgroundColor: "rgba(245, 158, 11, 0.12)"
    textColor: "{colors.status-warning}"
    typography: "{typography.caption}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xxs} {spacing.sm}"
  badge-running:
    backgroundColor: "rgba(59, 130, 246, 0.12)"
    textColor: "{colors.status-running}"
    typography: "{typography.caption}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xxs} {spacing.sm}"
  badge-pending:
    backgroundColor: "rgba(107, 114, 128, 0.12)"
    textColor: "{colors.status-pending}"
    typography: "{typography.caption}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xxs} {spacing.sm}"
  badge-entity:
    backgroundColor: "rgba(0, 217, 146, 0.12)"
    textColor: "{colors.primary-soft}"
    typography: "{typography.caption-mono}"
    rounded: "{rounded.pill}"
    padding: "{spacing.xxs} {spacing.sm}"

  # ─── Cards ───
  card-feature:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.ink}"
    borderColor: "{colors.hairline}"
    rounded: "{rounded.md}"
    padding: "{spacing.2xl}"
  card-metric:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.ink}"
    borderColor: "{colors.hairline}"
    rounded: "{rounded.md}"
    padding: "{spacing.lg} {spacing.xl}"
  card-metric-value:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.ink-strong}"
    typography: "{typography.metric-value}"

  # ─── Table ───
  table-header:
    backgroundColor: "{colors.canvas-soft}"
    textColor: "{colors.mute}"
    typography: "{typography.caption}"
    padding: "{spacing.md} {spacing.lg}"
  table-row:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.body}"
    typography: "{typography.body-sm}"
    borderColor: "{colors.hairline}"
    padding: "{spacing.sm} {spacing.lg}"
  table-row-hover:
    backgroundColor: "{colors.canvas-soft}"

  # ─── Source Path / Cascade ───
  cascade-step:
    borderColor: "{colors.hairline}"
    rounded: "{rounded.md}"
    padding: "{spacing.md} {spacing.lg}"

  # ─── Slide-over Panel ───
  slide-over:
    backgroundColor: "{colors.canvas}"
    borderColor: "{colors.hairline}"
    width: "440px"
    rounded: "{rounded.none}"

  # ─── Inputs ───
  text-input:
    backgroundColor: "{colors.canvas-soft}"
    textColor: "{colors.ink}"
    borderColor: "{colors.hairline}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.sm}"
    padding: "{spacing.md} {spacing.lg}"
  search-input:
    backgroundColor: "{colors.canvas-soft}"
    textColor: "{colors.ink}"
    borderColor: "{colors.hairline}"
    typography: "{typography.body-md}"
    rounded: "{rounded.md}"
    padding: "{spacing.md} {spacing.lg}"

  # ─── Graph ───
  graph-canvas:
    backgroundColor: "{colors.canvas}"
  graph-node:
    strokeWidth: "1px"
    strokeColor: "{colors.hairline}"
  graph-edge:
    strokeColor: "{colors.hairline-soft}"
    strokeWidth: "1px"
  graph-node-label:
    typography: "{typography.caption}"
    textColor: "{colors.ink}"

  # ─── Footer / Utility ───
  green-divider:
    backgroundColor: "{colors.canvas}"
    borderColor: "{colors.primary}"
  code-inline-chip:
    backgroundColor: "{colors.canvas-soft}"
    textColor: "{colors.ink}"
    typography: "{typography.code}"
    rounded: "{rounded.sm}"
    padding: "{spacing.xxs} {spacing.sm}"

---

## Overview

Open EASM is a self-hosted passive External Attack Surface Management platform — a security-operations dashboard whose surface is an unrelenting near-black canvas broken by a single electric-teal accent (`{colors.primary}` `#00d992`) reserved for discovery, live status, and primary actions. Entity types each get their own color — amber for ASN, orange for IP ranges, red for IPs, cyan for hostnames, teal for domains, purple for certificates, slate for orgs — so that at a glance on the graph or in the inventory table, every discovered asset tells its story by hue.

The decorative system is restrained. Hairline-bordered cards on near-black are the primary chrome — no floating shadows, no gradient fills. The only depth comes from a slightly lifted canvas-soft (`#1a1a1a`) for inputs and table headers, and the occasional green accent line to mark "live" or "discovered" state. The sidebar is a dark rail of icon+label navigation items; the active state is a 2px teal left-indicator bar paired with teal text.

Typography stays calm. Inter in weights 400/600/700 carries every narrative role; JetBrains Mono (with SF Mono fallback) handles entity values, CIDR ranges, domain names, and every data-dense cell where monospace alignment matters. Uppercase eyebrows use Inter weight 600 with 1.5px tracking — a deliberate echo of the terminal prompt cadence appropriate for a security tool.

**Key Characteristics:**
- A single electric-teal accent `{colors.primary}` (`#00d992`) carries every CTA, every success indicator, and the brand identity. No second accent.
- Dark canvas (`{colors.canvas}` `#101010`) is the only surface mode — no light-mode counterpart.
- Hairline-bordered feature cards (`{colors.hairline}` `#3d3a39`, 1px solid) are the primary chrome — no box shadows, no fills, just precise hairline rectangles.
- Entity-type colors are the secondary visual vocabulary — each type (ASN, IP, hostname, domain, certificate, org) has a distinct hue that marks it in graph nodes, table badges, and cascade visualizations.
- JetBrains Mono is elevated from "code only" to "data surface" — every entity value, IP address, CIDR block, and hash is rendered in monospace because precision matters in a security tool.
- The sidebar is a persistent 64px/240px collapsible rail with icon+label items; the active state uses a 2px teal left-indicator, not background fill.
- Slide-over panels (440px) replace separate pages for entity detail, keeping graph and inventory context visible.

## Colors

### Brand & Accent
- **Electric Teal** (`{colors.primary}` — `#00d992`): The single brand accent. Every primary CTA, every "discovered" state, every live-status indicator, the sidebar active marker. Reserved — never used as body text fill.
- **Primary Soft** (`{colors.primary-soft}` — `#2fd6a1`): Slightly muted teal for ghost buttons, tooltip content, hover states on primary elements.
- **Primary Deep** (`{colors.primary-deep}` — `#10b981`): Darker teal for inline link color in body copy.

### Surface
- **Canvas** (`{colors.canvas}` — `#101010`): The default near-black page background. The only surface mode.
- **Canvas Soft** (`{colors.canvas-soft}` — `#1a1a1a`): Slightly lifted dark fill for inputs, table headers, code blocks — marks them visually distinct without breaking the dark canvas.
- **Canvas Elevated** (`{colors.canvas-elevated}` — `#222222`): Used for hover/active states on rows and items that need to feel "lifted" from canvas.
- **Hairline** (`{colors.hairline}` — `#3d3a39`): 1px solid borders on cards, buttons, dividers. The universal edge color.
- **Hairline Soft** (`{colors.hairline-soft}` — `#57534e`): Lighter divider for graph edges and secondary separators.

### Text
- **Ink** (`{colors.ink}` — `#f2f2f2`): Default text on dark canvas. Slightly off-white to reduce contrast strain.
- **Ink Strong** (`{colors.ink-strong}` — `#ffffff`): Pure white for metric values, heading emphasis, and the currently-selected sidebar item.
- **Body** (`{colors.body}` — `#bdbdbd`): Secondary text — supporting copy, table cell values.
- **Mute** (`{colors.mute}` — `#8b949e`): Lowest-priority text — captions, placeholder text, disabled states.

### Entity Type Colors
Each entity type in the EASM data model gets a distinct hue. These colors are used in graph node fill/stroke, entity type badges, and cascade step indicators.

- **ASN Amber** (`{colors.entity-asn}` — `#f59e0b`): Autonomous System Numbers — warm, attention-grabbing, sits high in the cascade.
- **IP Range Orange** (`{colors.entity-ip-range}` — `#f97316`): CIDR ranges — adjacent to ASN in the spectrum, distinguishable.
- **IP Red** (`{colors.entity-ip}` — `#ef4444`): Individual IP addresses — danger-adjacent, immediate.
- **Hostname Cyan** (`{colors.entity-hostname}` — `#06b6d4`): Hostnames — cool blue-green, distinct from teal primary.
- **Domain Teal** (`{colors.entity-domain}` — `#00d992`): Domains — matches the primary accent because domains are the most important entity type.
- **Certificate Purple** (`{colors.entity-certificate}` — `#a855f7`): TLS certificates — distinct, not confused with hostname or domain.
- **Org Slate** (`{colors.entity-org}` — `#94a3b8`): Organizations — neutral, muted; orgs are containers, not endpoints.

### Status Colors
Used for run status badges, pivot queue status, and activity indicators.

- **Success** (`{colors.status-success}` — `#00d992`): Completed runs, successful discoveries, healthy states. Same as primary — success IS the discovery.
- **Error** (`{colors.status-error}` — `#ef4444`): Failed runs, errors. Also used for the `entity-ip` type.
- **Warning** (`{colors.status-warning}` — `#f59e0b`): Pending attention, slow runs. Also used for `entity-asn` type.
- **Running** (`{colors.status-running}` — `#3b82f6`): Currently executing runs/pivots. Blue signals "in progress."
- **Pending** (`{colors.status-pending}` — `#6b7280`): Queued runs, idle pivot jobs. Gray signals "waiting."

## Typography

### Font Family
Two faces carry the system:
1. **Inter** for every display, body, button, label, and navigation role. Weights 400/600/700 are the working set. OpenType features `"calt"` and `"rlig"` enabled.
2. **JetBrains Mono** (with SF Mono / Menlo / Monaco / Consolas fallbacks) for entity values, IP addresses, CIDR ranges, domain names, hashes, and every data-dense cell where monospace alignment matters. Weight 400 for values, 550 for emphasis.

### Hierarchy

| Token | Size | Weight | Line Height | Letter Spacing | Use |
|---|---|---|---|---|---|
| `{typography.display-xl}` | 60px | 400 | 60px | -0.65px | Landing / marketing hero headline (not used in dashboard) |
| `{typography.display-lg}` | 36px | 400 | 40px | -0.9px | Dashboard title in slide-over panels |
| `{typography.display-md}` | 24px | 700 | 32px | -0.6px | Section headings, slide-over titles |
| `{typography.display-sm}` | 20px | 600 | 28px | 0 | Card titles, metric card headings |
| `{typography.eyebrow-mono}` | 11px | 600 | 16px | 1.5px | UPPERCASE entity-type labels ("ASN", "IP RANGE"), status labels |
| `{typography.eyebrow-uppercase}` | 14px | 600 | 20px | 0.45px | Section eyebrow labels above headings |
| `{typography.heading-lg}` | 20px | 600 | 28px | 0 | Slide-over section headings |
| `{typography.heading-md}` | 16px | 600 | 24px | 0 | Card sub-headings, table column headers |
| `{typography.heading-sm}` | 14px | 600 | 20px | 0 | Small labels, property keys in detail panels |
| `{typography.body-lg}` | 16px | 400 | 26px | 0 | Lead paragraphs in dashboards (not commonly used) |
| `{typography.body-md}` | 14px | 400 | 22px | 0 | Default dashboard body, sidebar labels |
| `{typography.body-md-strong}` | 14px | 600 | 22px | 0 | Emphasized entity values in tables |
| `{typography.body-sm}` | 13px | 400 | 18px | 0 | Secondary table cell values, metadata |
| `{typography.body-sm-strong}` | 13px | 600 | 18px | 0 | Bold secondary values |
| `{typography.caption}` | 12px | 400 | 16px | 0 | Fine print, timestamps |
| `{typography.caption-mono}` | 11px | 400 | 16px | 0 | Entity-type badges, short monospace labels |
| `{typography.code}` | 13px | 400 | 18px | 0 | Code blocks, entity values in detail panels |
| `{typography.code-strong}` | 13px | 550 | 16px | 0 | Emphasized inline code |
| `{typography.button-md}` | 14px | 600 | 20px | 0 | Button labels |
| `{typography.metric-value}` | 32px | 600 | 36px | 0 | Dashboard metric numbers (entity counts, run counts) |

### Principles
- **Monospace for data, sans for narrative.** Entity values (IP addresses, domain names, CIDR blocks, certificate hashes) ALWAYS render in JetBrains Mono. Labels and descriptions in Inter.
- **Uppercase eyebrows use Inter** at weight 600 with 1.5px tracking for entity-type badges (`ASN`, `DOMAIN`, `CERTIFICATE`) — not a separate mono face.
- **Metric values sit in JetBrains Mono** at 32px weight 600 — the dashboard's equivalent of a "big number" card. Smaller entity counts use `{typography.heading-md}`.

### Font Substitutes
- **Inter** — available on Google Fonts; no substitution needed for web deployment.
- **JetBrains Mono** — available on Google Fonts; best substitute for SF Mono in code/data contexts. When neither is available, fall back to `SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, monospace`.

## Layout

### Shell Architecture
The dashboard shell is a fixed sidebar + scrollable main area:

- **Sidebar**: 64px collapsed (icons only), 240px expanded (icon + label). Collapsible via hamburger toggle in the sidebar header. Sticks to left edge at all breakpoints above 768px.
- **Main area**: Fills remaining viewport width. Contains a top bar with breadcrumbs and global search, then the active view's content below.

### Spacing System
- **Base unit**: 4px
- **Tokens**: `{spacing.xxs}` 2px · `{spacing.xs}` 4px · `{spacing.sm}` 8px · `{spacing.md}` 12px · `{spacing.lg}` 16px · `{spacing.xl}` 20px · `{spacing.2xl}` 24px · `{spacing.3xl}` 32px · `{spacing.4xl}` 40px · `{spacing.5xl}` 48px · `{spacing.6xl}` 64px
- **Card interior**: `{spacing.2xl}` 24px
- **Section padding**: `{spacing.3xl}` 32px between major dashboard sections
- **Table cell padding**: `{spacing.sm} {spacing.lg}` (8px 16px)

### Grid & Container
- Dashboard content max-width: 1400px centered within main area.
- Metric cards: 4-up grid at desktop (坍 collapse to 2-up at tablet, 1-up at mobile).
- Entity table: full width of content area with horizontal scroll for overflow columns.
- Graph explorer: full viewport height minus header, full width of main area.

### Whitespace Philosophy
Dark canvas absorbs whitespace differently than light. On this surface, the hairline borders on cards create their own density — whitespace between cards can be tighter (`{spacing.lg}` 16px) because the borders mark boundaries clearly. The space between major dashboard sections opens to `{spacing.3xl}` 32px to give the eye breathing room.

## Elevation & Depth

| Level | Treatment | Use |
|---|---|---|
| 0 | Flat on canvas, no shadow | Default surface, cards |
| 1 | `1px solid {colors.hairline}` | Card borders, table row dividers, button outlines |
| 2 | `1px solid {colors.hairline-soft}` | Graph edges, secondary indicators |
| 3 | `0 0 15px rgba(92, 88, 85, 0.2)` | Hover state on cards and table rows |
| 4 | `0 20px 60px rgba(0,0,0,0.7), 0 0 0 1px rgba(148,163,184,0.1) inset` | Slide-over panels, modals |

### Depth Principles
- **No drop shadows on cards.** The brand uses hairline borders + canvas-soft backgrounds for depth, not material shadows.
- **Hover states lift gently.** A subtle outer glow (`rgba(92, 88, 85, 0.2)`) on card hover, not a shadow stack.
- **Slide-over panels use heavy shadow.** The only place with a full shadow stack is the right-edge slide-over, which needs to feel like it's floating above the dashboard.

## Shapes

### Border Radius Scale

| Token | Value | Use |
|---|---|---|
| `{rounded.none}` | 0px | Full-bleed bands, table rows |
| `{rounded.xs}` | 4px | Inline badges, code chips |
| `{rounded.sm}` | 6px | Buttons, inputs |
| `{rounded.md}` | 8px | Cards, code blocks, slide-over |
| `{rounded.lg}` | 12px | Large metric cards |
| `{rounded.xl}` | 16px | Hero sections (not commonly used in dashboard) |
| `{rounded.pill}` | 9999px | Status badges, entity-type pills |
| `{rounded.full}` | 9999px | Avatar circles, icon containers |

## Components

### Sidebar
**`sidebar`** — the persistent navigation rail.
- Background `{colors.canvas}`, 1px right border `{colors.hairline}`. Two widths: 64px (collapsed, icon-only) and 240px (expanded, icon + label). Toggle via hamburger in the sidebar header.

**`sidebar-item`** — a nav item (icon + label).
- Background `{colors.canvas}`, text `{colors.mute}`, type `{typography.body-sm}`. Left-indicator: none. On hover: background shifts to `{colors.canvas-soft}`, text to `{colors.ink}`.

**`sidebar-item-active`** — the currently-selected nav item.
- Background `{colors.canvas-soft}`, text `{colors.primary}`, type `{typography.body-sm-strong}`. Left-indicator: 2px solid `{colors.primary}` bar running the full height of the item.

**`sidebar-header`** — the top section of the sidebar containing the logo/wordmark and collapse toggle.
- Background `{colors.canvas}`, padding `{spacing.lg}`. Logo in `{typography.heading-md}` weight 700.

### Buttons

**`button-primary`** — the electric-teal CTA for triggering runs, confirming actions.
- Background `{colors.primary}`, text `{colors.on-primary}`, type `{typography.button-md}`, padding `{spacing.sm} {spacing.lg}`, shape `{rounded.sm}`.

**`button-outline`** — the hairline-on-dark secondary button for filters, cancel actions.
- Background `{colors.canvas}`, text `{colors.ink}`, 1px solid `{colors.hairline}`, same type/padding/shape.

**`button-ghost`** — text-only with teal label, for tertiary actions.
- Background transparent, text `{colors.primary-soft}`, no border.

**`button-danger`** — destructive action (rarely used; for disabling targets).
- Background `{colors.status-error}`, text `{colors.ink-strong}`, same type/padding/shape.

### Status Badges

**`badge-success`** — Completed run, discovered entity.
- Background `rgba(0, 217, 146, 0.12)`, text `{colors.status-success}`, type `{typography.caption}`, pill shape.

**`badge-error`** — Failed run, error state.
- Background `rgba(239, 68, 68, 0.12)`, text `{colors.status-error}`, pill shape.

**`badge-warning`** — Slow run, needs attention.
- Background `rgba(245, 158, 11, 0.12)`, text `{colors.status-warning}`, pill shape.

**`badge-running`** — Currently executing.
- Background `rgba(59, 130, 246, 0.12)`, text `{colors.status-running}`, pill shape.

**`badge-pending`** — Queued, waiting.
- Background `rgba(107, 114, 128, 0.12)`, text `{colors.status-pending}`, pill shape.

**`badge-entity`** — Entity type indicator.
- Background `rgba(0, 217, 146, 0.12)` (default teal; overridden per type), text follows entity-type color, type `{typography.caption-mono}`, pill shape.

### Cards & Containers

**`card-feature`** — the default dashboard card.
- Background `{colors.canvas}`, text `{colors.ink}`, 1px solid `{colors.hairline}`, padding `{spacing.2xl}`, shape `{rounded.md}`.

**`card-metric`** — a compact metric card (entity count, run status count).
- Background `{colors.canvas}`, text `{colors.ink}`, 1px solid `{colors.hairline}`, padding `{spacing.lg} {spacing.xl}`, shape `{rounded.md}`. Contains a `{typography.eyebrow-mono}` label and a `{typography.metric-value}` number.

**`slide-over`** — the entity detail panel sliding from the right edge.
- Background `{colors.canvas}`, 1px left border `{colors.hairline}`, width 440px, shape `{rounded.none}`. Contains entity metadata, relationship list, and raw-event links.

### Table

**`table-header`** — column headers in entity and run tables.
- Background `{colors.canvas-soft}`, text `{colors.mute}`, type `{typography.caption}`, padding `{spacing.md} {spacing.lg}`.

**`table-row`** — default data row.
- Background `{colors.canvas}`, text `{colors.body}`, type `{typography.body-sm}`, bottom border 1px `{colors.hairline}`, padding `{spacing.sm} {spacing.lg}`. On hover: background shifts to `{colors.canvas-soft}`.

### Inputs & Search

**`text-input`** — standard form input on dark canvas.
- Background `{colors.canvas-soft}`, text `{colors.ink}`, 1px solid `{colors.hairline}`, type `{typography.body-sm}`, padding `{spacing.md} {spacing.lg}`, shape `{rounded.sm}`.

**`search-input`** — the global search bar in the top header.
- Background `{colors.canvas-soft}`, text `{colors.ink}`, 1px solid `{colors.hairline}`, type `{typography.body-md}`, shape `{rounded.md}`, padding `{spacing.md} {spacing.lg}`. Left-icon with magnifying glass in `{colors.mute}`.

### Graph

**`graph-canvas`** — the D3-force visualization area.
- Background `{colors.canvas}`, fills the main content area below the header bar.

**`graph-node`** — an entity node in the force-directed graph.
- Fill color: entity-type color with 20% opacity. Stroke: entity-type color at 100% opacity, 1.5px. On hover: stroke width 2.5px, outer glow matching entity-type color at 30% opacity.

**`graph-edge`** — a relationship edge between nodes.
- Stroke `{colors.hairline-soft}` 1px. On node hover: connected edges brighten to `{colors.hairline}` 1.5px.

### Cascade Visualization

**`cascade-step`** — a step in the discovery cascade (e.g., "ASN → IP Ranges → Hostnames → IPs → Domains → Certificates").
- A horizontal or vertical chain of cards, each showing the entity type badge, the count discovered at this step, and a connecting line/arrow in `{colors.hairline-soft}` to the next step. Each step card has border 1px `{colors.hairline}`, rounded `{rounded.md}`, padding `{spacing.md} {spacing.lg}`.

## Do's and Don'ts

### Do
- Reserve `{colors.primary}` (`#00d992`) for primary CTAs, the "discovered" state, and the sidebar active indicator. The teal is the brand's center of gravity.
- Use entity-type colors consistently — every place an ASN appears (graph node, table badge, cascade step), it should be `{colors.entity-asn}` amber.
- Render all entity values (IP addresses, domain names, CIDR blocks, certificate hashes) in JetBrains Mono. Precision is the point.
- Use hairline borders on `{colors.hairline}` for card depth — not shadows.
- Use slide-over panels for entity detail — never navigate to a separate page.
- Use `{typography.metric-value}` for the big numbers in dashboard metric cards.
- Poll `/runs` and `/pivot_queue` endpoints every 5 seconds to update status badges without manual refresh.

### Don't
- Don't introduce a light-mode counterpart. The brand is dark-canvas only.
- Don't use `{colors.primary}` as body-text fill — it's for CTAs and status indicators only.
- Don't drop shadows on cards. Hairline borders + canvas-soft fills are the elevation system.
- Don't render entity values in Inter. Domains, IPs, and hashes must be in JetBrains Mono.
- Don't use entity-type colors for anything except entity identification — they are the secondary color vocabulary, not general-purpose accent colors.
- Don't override status badge colors — `badge-success` is always `{colors.status-success}`, `badge-error` is always `{colors.status-error}`, etc.

## Responsive Behavior

### Breakpoints

| Name | Width | Sidebar | Layout |
|---|---|---|---|
| Desktop | ≥ 1024px | Expanded 240px or collapsed 64px | 4-up metric cards, full table columns, full graph |
| Tablet | 768–1023px | Collapsed 64px only | 2-up metric cards, compressed table, full graph |
| Mobile | < 768px | Hidden (hamburger menu) | 1-up metric cards, horizontal-scroll table, graph forced-portrait |

### Touch Targets
- All buttons and interactive elements hit minimum 44×44px on mobile.
- Table rows remain tap-friendly: 48px minimum height per row at mobile.
- Graph nodes scale up to minimum 32px diameter on touch devices.

### Collapsing Strategy
- **Metric cards**: 4-up → 2-up → 1-up across breakpoints.
- **Entity table**: drops non-essential columns (e.g., `org_id`, `is_first_discovery`) at tablet; enables horizontal scroll at mobile.
- **Graph explorer**: switches from landscape to portrait orientation on mobile; pinch-to-zoom enabled.
- **Sidebar**: collapses to icons-only at tablet, hides behind hamburger at mobile.
- **Slide-over**: at desktop, 440px fixed width from right edge; at mobile, fills 100% viewport as a bottom sheet.

## Iteration Guide

1. Focus on ONE component at a time. Don't rebuild the system — extend it.
2. Reference component names and tokens directly (`{colors.primary}`, `{badge-success}`, `{rounded.md}`) — do not paraphrase.
3. Keep entity-type colors consistent — the mapping from entity type to color is the graph's primary visual encoding. Break it, and the graph becomes unreadable.
4. Default to `{typography.body-md}` for labels and descriptions, `{typography.code}` for entity values. The monospace/sans split is load-bearing.
5. Keep `{colors.primary}` scarce — one primary CTA per view. The teal only works as a signal because it's rare.
6. When adding new entity types or status states, assign them a color from the status palette before implementing any UI — don't ad-hoc colors.
7. The sidebar is persistent navigation. Never replace it with a top-tab bar. The sidebar's collapse/expand behavior is part of the brand rhythm.