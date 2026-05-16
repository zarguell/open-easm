import { useState, useRef, useMemo } from 'react'
import { useTargets } from '../../api/targets'
import { useGraph } from '../../api/graph'
import { ForceGraph, type ForceGraphHandle } from './ForceGraph'
import { GraphLegend } from './GraphLegend'
import { GraphControls } from './GraphControls'
import { SlideOver } from '../shared/SlideOver'
import { LoadingSpinner } from '../shared/LoadingSpinner'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { EntityDetail } from '../inventory/EntityDetail'
import type { GraphNode, GraphLink } from '../../lib/d3-force'

const LARGE_TYPES = new Set(['asn', 'org'])

export function GraphView() {
  const [selectedTargetId, setSelectedTargetId] = useState<string | null>(null)
  const [selectedDepth, setSelectedDepth] = useState(3)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [detailEntityId, setDetailEntityId] = useState<string | null>(null)
  const graphRef = useRef<ForceGraphHandle>(null)

  const { data: targets } = useTargets()
  const { data: graphData, isLoading, error, refetch } = useGraph(selectedTargetId, selectedDepth)

  const { nodes, links } = useMemo(() => {
    if (!graphData) return { nodes: [], links: [] }

    const graphNodes: GraphNode[] = graphData.nodes.map((n) => ({
      id: n.id,
      entity_type: n.entity_type,
      entity_value: n.entity_value,
      depth: n.depth,
      radius: LARGE_TYPES.has(n.entity_type) ? 16 : 12,
    }))

    const graphLinks: GraphLink[] = graphData.edges.map((e) => ({
      source: e.source_entity_id,
      target: e.target_entity_id,
      relationship_type: e.relationship_type,
    }))

    return { nodes: graphNodes, links: graphLinks }
  }, [graphData])

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-4 px-lg py-3 border-b border-hairline shrink-0">
        <select
          value={selectedTargetId ?? ''}
          onChange={(e) => {
            setSelectedTargetId(e.target.value || null)
            setSelectedNodeId(null)
          }}
          className="bg-canvas-soft border border-hairline rounded px-3 py-1.5 text-sm text-ink font-mono focus:outline-none focus:border-primary cursor-pointer"
        >
          <option value="">Select a target...</option>
          {targets?.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>

        {selectedTargetId && (
          <span className="text-xs text-mute">
            {nodes.length} nodes · {links.length} edges
          </span>
        )}
      </div>

      <div className="flex-1 relative overflow-hidden">
        {!selectedTargetId && (
          <div className="flex items-center justify-center h-full">
            <p className="text-sm text-mute">Select a target to explore</p>
          </div>
        )}

        {selectedTargetId && isLoading && (
          <LoadingSpinner size="lg" className="h-full" />
        )}

        {error && (
          <ErrorDisplay
            message={error.message}
            onRetry={() => refetch()}
          />
        )}

        {selectedTargetId && !isLoading && !error && nodes.length > 0 && (
          <>
            <ForceGraph
              ref={graphRef}
              nodes={nodes}
              links={links}
              selectedNodeId={selectedNodeId}
              onNodeClick={(id) =>
                setSelectedNodeId((prev) => (prev === id ? null : id))
              }
              onNodeDoubleClick={(id) => setDetailEntityId(id)}
            />
            <GraphLegend />
            <GraphControls
              depth={selectedDepth}
              onDepthChange={setSelectedDepth}
              onZoomIn={() => graphRef.current?.zoomIn()}
              onZoomOut={() => graphRef.current?.zoomOut()}
              onZoomReset={() => graphRef.current?.zoomReset()}
            />
          </>
        )}

        {selectedTargetId && !isLoading && !error && nodes.length === 0 && (
          <div className="flex items-center justify-center h-full">
            <p className="text-sm text-mute">No graph data for this target</p>
          </div>
        )}
      </div>

      <SlideOver
        open={detailEntityId !== null}
        onClose={() => setDetailEntityId(null)}
        title="Entity Detail"
      >
        {detailEntityId && <EntityDetail entityId={detailEntityId} />}
      </SlideOver>
    </div>
  )
}
