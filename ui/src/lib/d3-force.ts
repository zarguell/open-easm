import { forceSimulation, forceLink, forceManyBody, forceCenter, forceCollide } from 'd3-force'
import type { Simulation, SimulationNodeDatum, SimulationLinkDatum } from 'd3-force'

export interface GraphNode extends SimulationNodeDatum {
  id: string
  entity_type: string
  entity_value: string
  depth: number
  radius: number
}

export interface GraphLink extends SimulationLinkDatum<GraphNode> {
  relationship_type: string
}

export function createSimulation(
  nodes: GraphNode[],
  links: GraphLink[],
  width: number,
  height: number,
): Simulation<GraphNode, GraphLink> {
  return forceSimulation<GraphNode>(nodes)
    .force('link', forceLink<GraphNode, GraphLink>(links).id(d => d.id).distance(80))
    .force('charge', forceManyBody().strength(-200))
    .force('center', forceCenter(width / 2, height / 2))
    .force('collide', forceCollide<GraphNode>().radius(d => d.radius + 4))
}
