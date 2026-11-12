import { FileText, GitFork, Network, Target, Crosshair, Flag } from "lucide-react";

import { kindColor } from "@/lib/graph/encoding";

export type NodeAction =
  | "paths-out"
  | "paths-in"
  | "set-start"
  | "set-end"
  | "expand"
  | "dossier";

export interface ContextNode {
  id: string;
  label: string;
  kind: string;
}

interface Props {
  node: ContextNode;
  x: number;
  y: number;
  onAction: (action: NodeAction) => void;
  onClose: () => void;
}

const ITEMS: Array<{ action: NodeAction; label: string; icon: typeof Target }> = [
  { action: "paths-out", label: "Shortest paths to Tier Zero (from here)", icon: Target },
  { action: "paths-in", label: "Who can reach this (paths to here)", icon: Crosshair },
  { action: "set-start", label: "Set as path start", icon: Flag },
  { action: "set-end", label: "Set as path end", icon: Flag },
  { action: "expand", label: "Expand neighbors", icon: GitFork },
  { action: "dossier", label: "Open dossier", icon: FileText },
];

/** Right-click node context menu (design §7.3). Click the backdrop to close. */
export function NodeContextMenu({ node, x, y, onAction, onClose }: Props) {
  // Clamp within the viewport so the menu never overflows off-screen.
  const left = Math.min(x, window.innerWidth - 272);
  const top = Math.min(y, window.innerHeight - 240);
  return (
    <div className="fixed inset-0 z-50" onClick={onClose} onContextMenu={(e) => e.preventDefault()}>
      <div
        className="absolute w-64 overflow-hidden rounded-md border border-border bg-surface-overlay shadow-overlay"
        style={{ left, top }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b border-border px-3 py-2">
          <span className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: kindColor(node.kind) }} />
          <span className="min-w-0 flex-1 truncate font-mono text-caption" title={node.label}>
            {node.label}
          </span>
          <Network className="size-3 text-muted-foreground" />
        </div>
        <ul className="py-1">
          {ITEMS.map((it) => {
            const Icon = it.icon;
            return (
              <li key={it.action}>
                <button
                  onClick={() => {
                    onAction(it.action);
                    onClose();
                  }}
                  className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-caption text-muted-foreground hover:bg-muted hover:text-foreground"
                >
                  <Icon className="size-3.5 shrink-0" />
                  {it.label}
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
