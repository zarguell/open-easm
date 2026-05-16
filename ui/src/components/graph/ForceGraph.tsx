import { useRef, useEffect, forwardRef, useImperativeHandle } from 'react'
import { select } from 'd3-selection'
import { zoom, zoomIdentity } from 'd3-zoom'
import { drag } from 'd3-drag'
import { forceCenter } from 'd3-force'
import { createSimulation, type GraphNode, type GraphLink } from '../../lib/d3-force'
import { getEntityColor } from '../../lib/entity-colors'
import { colors } from '../../DESIGN_TOKENS'

export interface ForceGraphHandle {
  zoomIn: () => void
  zoomOut: () => void
  zoomReset: () => void
}

interface ForceGraphProps {
  nodes: GraphNode[]
  links: GraphLink[]
  selectedNodeId: string | null
  onNodeClick: (id: string) => void
  onNodeDoubleClick: (id: string) => void
}

function getConnectedSet(selectedNodeId: string | null, links: GraphLink[]): Set<string> {
  if (!selectedNodeId) return new Set()
  const connected = new Set<string>([selectedNodeId])
  for (const link of links) {
    const src = typeof link.source === 'object' ? (link.source as GraphNode).id : (link.source as string)
    const tgt = typeof link.target === 'object' ? (link.target as GraphNode).id : (link.target as string)
    if (src === selectedNodeId) connected.add(tgt)
    if (tgt === selectedNodeId) connected.add(src)
  }
  return connected
}

export const ForceGraph = forwardRef<ForceGraphHandle, ForceGraphProps>(
  function ForceGraph({ nodes, links, selectedNodeId, onNodeClick, onNodeDoubleClick }, ref) {
    const svgRef = useRef<SVGSVGElement>(null)
    const containerRef = useRef<HTMLDivElement>(null)
    const simulationRef = useRef<ReturnType<typeof createSimulation> | null>(null)
    const zoomBehaviorRef = useRef<ReturnType<typeof zoom<SVGSVGElement, unknown>> | null>(null)

    useImperativeHandle(ref, () => ({
      zoomIn: () => {
        const svg = svgRef.current
        if (!svg || !zoomBehaviorRef.current) return
        zoomBehaviorRef.current.scaleBy(select(svg), 1.5)
      },
      zoomOut: () => {
        const svg = svgRef.current
        if (!svg || !zoomBehaviorRef.current) return
        zoomBehaviorRef.current.scaleBy(select(svg), 1 / 1.5)
      },
      zoomReset: () => {
        const svg = svgRef.current
        if (!svg || !zoomBehaviorRef.current) return
        zoomBehaviorRef.current.transform(select(svg), zoomIdentity)
      },
    }), [])

    useEffect(() => {
      const svg = svgRef.current
      const container = containerRef.current
      if (!svg || !container || nodes.length === 0) return

      const rect = container.getBoundingClientRect()
      const width = rect.width || 800
      const height = rect.height || 600

      const svgSel = select(svg)
      svgSel.selectAll('*').remove()

      const g = svgSel.append<SVGGElement>('g').attr('class', 'graph-root')

      const zoomBehavior = zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.1, 8])
        .on('zoom', (event) => {
          g.attr('transform', event.transform.toString())
        })

      svgSel.call(zoomBehavior)
      zoomBehaviorRef.current = zoomBehavior

      const sim = createSimulation(nodes, links, width, height)
      simulationRef.current = sim

      const dragBehavior = drag<SVGGElement, GraphNode>()
        .on('start', (event, d) => {
          if (!event.active) sim.alphaTarget(0.3).restart()
          d.fx = d.x
          d.fy = d.y
        })
        .on('drag', (event, d) => {
          d.fx = event.x
          d.fy = event.y
        })
        .on('end', (event, d) => {
          if (!event.active) sim.alphaTarget(0)
          d.fx = null
          d.fy = null
        })

      const linkSel = g
        .selectAll<SVGLineElement, GraphLink>('line.edge')
        .data(links)
        .join('line')
        .attr('class', 'edge')
        .attr('stroke', colors.hairlineSoft)
        .attr('stroke-width', 1)
        .attr('stroke-opacity', 0.6)

      const nodeGroup = g
        .selectAll<SVGGElement, GraphNode>('g.node-group')
        .data(nodes, (d) => d.id)
        .join('g')
        .attr('class', 'node-group')
        .call(dragBehavior)

      nodeGroup
        .append<SVGCircleElement>('circle')
        .attr('class', 'node-circle')
        .attr('r', (d) => d.radius)
        .attr('fill', (d) => `${getEntityColor(d.entity_type)}33`)
        .attr('stroke', (d) => getEntityColor(d.entity_type))
        .attr('stroke-width', 1.5)
        .style('cursor', 'pointer')

      nodeGroup
        .append<SVGTextElement>('text')
        .attr('class', 'node-label')
        .attr('text-anchor', 'middle')
        .attr('dy', (d) => d.radius + 14)
        .attr('fill', colors.body)
        .attr('font-family', 'monospace')
        .attr('font-size', 10)
        .text((d) => (d.entity_value.length > 20 ? d.entity_value.slice(0, 17) + '…' : d.entity_value))

      nodeGroup.on('click', (_event, d) => onNodeClick(d.id))
      nodeGroup.on('dblclick', (_event, d) => onNodeDoubleClick(d.id))

      sim.on('tick', () => {
        linkSel
          .attr('x1', (d) => (d.source as GraphNode).x ?? 0)
          .attr('y1', (d) => (d.source as GraphNode).y ?? 0)
          .attr('x2', (d) => (d.target as GraphNode).x ?? 0)
          .attr('y2', (d) => (d.target as GraphNode).y ?? 0)
        nodeGroup.attr('transform', (d) => `translate(${d.x ?? 0},${d.y ?? 0})`)
      })

      return () => {
        sim.stop()
        simulationRef.current = null
      }
    }, [nodes, links, onNodeClick, onNodeDoubleClick])

    useEffect(() => {
      const svg = svgRef.current
      if (!svg) return
      const g = select(svg).select<SVGGElement>('g.graph-root')
      if (g.empty()) return

      const connected = getConnectedSet(selectedNodeId, links)

      g.selectAll<SVGLineElement, GraphLink>('line.edge')
        .attr('stroke', (d) => {
          if (!selectedNodeId) return colors.hairlineSoft
          const src = typeof d.source === 'object' ? (d.source as GraphNode).id : (d.source as string)
          const tgt = typeof d.target === 'object' ? (d.target as GraphNode).id : (d.target as string)
          return (src === selectedNodeId || tgt === selectedNodeId) ? colors.hairline : colors.hairlineSoft
        })
        .attr('stroke-opacity', (d) => {
          if (!selectedNodeId) return 0.6
          const src = typeof d.source === 'object' ? (d.source as GraphNode).id : (d.source as string)
          const tgt = typeof d.target === 'object' ? (d.target as GraphNode).id : (d.target as string)
          return (src === selectedNodeId || tgt === selectedNodeId) ? 1 : 0.15
        })
        .attr('stroke-width', (d) => {
          if (!selectedNodeId) return 1
          const src = typeof d.source === 'object' ? (d.source as GraphNode).id : (d.source as string)
          const tgt = typeof d.target === 'object' ? (d.target as GraphNode).id : (d.target as string)
          return (src === selectedNodeId || tgt === selectedNodeId) ? 2 : 1
        })

      g.selectAll<SVGGElement, GraphNode>('g.node-group')
        .select<SVGCircleElement>('circle.node-circle')
        .attr('stroke-width', (d) => (selectedNodeId && connected.has(d.id)) ? 2.5 : 1.5)
        .attr('stroke-opacity', (d) => (selectedNodeId && !connected.has(d.id)) ? 0.3 : 1)
        .attr('fill-opacity', (d) => (selectedNodeId && !connected.has(d.id)) ? 0.15 : 1)

      g.selectAll<SVGTextElement, GraphNode>('text.node-label')
        .attr('fill-opacity', (d) => (selectedNodeId && !connected.has(d.id)) ? 0.2 : 1)
    }, [selectedNodeId, links])

    useEffect(() => {
      const container = containerRef.current
      if (!container) return
      const observer = new ResizeObserver((entries) => {
        for (const entry of entries) {
          const { width, height } = entry.contentRect
          if (simulationRef.current) {
            simulationRef.current
              .force('center', forceCenter(width / 2, height / 2))
              .alpha(0.3)
              .restart()
          }
        }
      })
      observer.observe(container)
      return () => observer.disconnect()
    }, [])

    return (
      <div ref={containerRef} className="w-full h-full relative">
        <svg ref={svgRef} className="w-full h-full" />
      </div>
    )
  },
)
