"use client";

import { useMemo, useCallback } from "react";
import ReactFlow, {
  Node,
  Edge,
  Position,
  MarkerType,
  useNodesState,
  useEdgesState,
  Controls,
  Background,
  BackgroundVariant,
} from "reactflow";
import "reactflow/dist/style.css";
import type { AttackGraphData, GraphNode, GraphEdge } from "@/types/api";

// --- Node color mapping ---

const NODE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  entry: { bg: "#1e3a5f", border: "#3b82f6", text: "#93c5fd" },
  vulnerability: { bg: "#5f1e1e", border: "#ef4444", text: "#fca5a5" },
  impact: { bg: "#3f1e5f", border: "#a855f7", text: "#d8b4fe" },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#06b6d4",
  info: "#3b82f6",
};

// --- Layout helpers ---

/**
 * Simple 3-column layout: entries on left, vulns in middle, impacts on right.
 * Each column is spaced evenly, nodes within a column are stacked vertically.
 */
function layoutNodes(data: AttackGraphData): Node[] {
  const entries: GraphNode[] = [];
  const vulns: GraphNode[] = [];
  const impacts: GraphNode[] = [];

  for (const node of data.nodes) {
    if (node.node_type === "entry") entries.push(node);
    else if (node.node_type === "vulnerability") vulns.push(node);
    else impacts.push(node);
  }

  const COL_GAP = 320;
  const ROW_GAP = 100;

  function columnNodes(nodes: GraphNode[], colIndex: number): Node[] {
    const x = colIndex * COL_GAP + 40;
    const startY = Math.max(0, (3 - nodes.length) * (ROW_GAP / 2));

    return nodes.map((n, i) => {
      const colors = NODE_COLORS[n.node_type] ?? NODE_COLORS.entry;
      return {
        id: n.id,
        position: { x, y: startY + i * ROW_GAP },
        data: {
          label: n.label,
          nodeType: n.node_type,
          riskScore: n.risk_score,
          severity: n.severity,
          corroborated: n.corroborated,
        },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        style: {
          background: colors.bg,
          border: `2px solid ${
            n.severity ? (SEVERITY_COLORS[n.severity] ?? colors.border) : colors.border
          }`,
          color: colors.text,
          borderRadius: "8px",
          padding: "10px 14px",
          fontSize: "12px",
          fontFamily: "system-ui, sans-serif",
          maxWidth: "240px",
          whiteSpace: "normal" as const,
        },
      };
    });
  }

  return [
    ...columnNodes(entries, 0),
    ...columnNodes(vulns, 1),
    ...columnNodes(impacts, 2),
  ];
}

function layoutEdges(data: AttackGraphData): Edge[] {
  return data.edges.map((e, i) => ({
    id: `edge-${i}`,
    source: e.source,
    target: e.target,
    label: e.label,
    animated: e.weight >= 0.7,
    style: {
      stroke: e.weight >= 0.7 ? "#ef4444" : "#52525b",
      strokeWidth: Math.max(1, Math.round(e.weight * 3)),
    },
    labelStyle: {
      fontSize: "10px",
      fill: "#a1a1aa",
    },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: e.weight >= 0.7 ? "#ef4444" : "#52525b",
    },
  }));
}

// --- Component ---

interface AttackGraphProps {
  data: AttackGraphData;
}

export function AttackGraph({ data }: AttackGraphProps) {
  const initialNodes = useMemo(() => layoutNodes(data), [data]);
  const initialEdges = useMemo(() => layoutEdges(data), [data]);

  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  if (data.nodes.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">⬡</div>
        <p className="empty-state-text">No attack graph data.</p>
      </div>
    );
  }

  return (
    <div className="attack-graph-container">
      {/* Top attack paths */}
      {data.top_paths.length > 0 && (
        <div className="card attack-paths-card">
          <div className="card-title">Top Attack Paths</div>
          <ol className="attack-paths-list">
            {data.top_paths.slice(0, 5).map((p, i) => (
              <li key={i} className="attack-path-item">
                <span className="attack-path-score">
                  {(p.risk_score * 100).toFixed(0)}%
                </span>
                <span className="attack-path-chain">
                  {p.path.map((step) => step.label).join(" → ")}
                </span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* Graph stats */}
      <div className="graph-stats">
        <span>{data.stats.entry_nodes} entry</span>
        <span>{data.stats.vuln_nodes} vuln</span>
        <span>{data.stats.impact_nodes} impact</span>
        <span>{data.stats.edge_count} edges</span>
      </div>

      {/* ReactFlow canvas */}
      <div className="reactflow-wrapper">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
          attributionPosition="bottom-left"
          minZoom={0.3}
          maxZoom={2}
        >
          <Controls />
          <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#27272a" />
        </ReactFlow>
      </div>
    </div>
  );
}
