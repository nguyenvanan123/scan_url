import { useState, useEffect, useRef, useCallback } from "react";
import { Terminal, Play, Trash2, RefreshCw, X, ShieldAlert } from "lucide-react";
import { ScanFinding } from "@workspace/api-zod";

// ── Types ─────────────────────────────────────────────────────────────────────

type LineStyle = "cmd" | "output" | "success" | "error" | "info" | "warn" | "dim" | "highlight";

type TermItemData =
  | { kind: "line";     text: string; style: LineStyle }
  | { kind: "phase";    phaseNum: number; name: string }
  | { kind: "evidence"; lines: string[] };

type TermItem = TermItemData & { id: number };

interface SseEvent {
  type: "line" | "done" | "phase" | "evidence";
  // line
  text?: string;
  style?: LineStyle;
  // phase
  phaseNum?: number;
  name?: string;
  // evidence
  lines?: string[];
}

// ── Line style mapping ────────────────────────────────────────────────────────

function lineClass(style: LineStyle): string {
  switch (style) {
    case "cmd":       return "text-emerald-400 font-medium";
    case "success":   return "text-green-400 font-medium";
    case "error":     return "text-red-400 font-medium";
    case "warn":      return "text-yellow-400";
    case "info":      return "text-cyan-400";
    case "highlight": return "text-white font-bold";
    case "dim":       return "text-zinc-600";
    case "output":
    default:          return "text-zinc-300";
  }
}

// ── Item renderers ────────────────────────────────────────────────────────────

function PhaseMarker({ phaseNum, name }: { phaseNum: number; name: string }) {
  return (
    <div className="my-3 flex items-center gap-2 select-none">
      <span className="shrink-0 flex items-center justify-center w-5 h-5 rounded-full bg-cyan-500/20 border border-cyan-500/40 text-[9px] font-bold text-cyan-400 font-mono">
        {phaseNum}
      </span>
      <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-widest">
        Phase {phaseNum}: {name}
      </span>
      <span className="flex-1 border-t border-cyan-900/60" />
    </div>
  );
}

function EvidenceBlock({ lines }: { lines: string[] }) {
  return (
    <div className="my-3 rounded border border-yellow-500/40 bg-yellow-500/5 overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-1.5 bg-yellow-500/10 border-b border-yellow-500/30">
        <ShieldAlert className="w-3.5 h-3.5 text-yellow-400 shrink-0" />
        <span className="text-[10px] font-mono font-bold text-yellow-400 uppercase tracking-widest">
          [!] Exploit Evidence Exfiltrated
        </span>
      </div>
      {/* Lines */}
      <div className="px-3 py-2.5 space-y-px">
        {lines.map((line, i) => (
          <div key={i} className="font-mono text-[11px] leading-[1.7] break-all whitespace-pre-wrap">
            {line === "" ? (
              <div className="h-2" />
            ) : line.startsWith("[+]") ? (
              <span className="text-yellow-300">{line}</span>
            ) : line.startsWith("[!]") ? (
              <span className="text-red-400 font-medium">{line}</span>
            ) : line.startsWith("[~]") ? (
              <span className="text-yellow-600">{line}</span>
            ) : line.startsWith("    ") ? (
              <span className="text-yellow-200/70">{line}</span>
            ) : (
              <span className="text-yellow-100/60">{line}</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface PocTerminalProps {
  finding: ScanFinding;
  scanUrl: string;
}

export function PocTerminal({ finding, scanUrl }: PocTerminalProps) {
  const [isOpen, setIsOpen]       = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [items, setItems]         = useState<TermItem[]>([]);
  const [isDone, setIsDone]       = useState(false);
  const abortRef                  = useRef<AbortController | null>(null);
  const endRef                    = useRef<HTMLDivElement>(null);
  const counter                   = useRef(0);

  if (!finding.execution_poc) return null;

  const addItem = useCallback((item: TermItemData) => {
    setItems((prev) => [
      ...prev.slice(-699),
      { ...item, id: ++counter.current } as TermItem,
    ]);
  }, []);

  const runPoc = useCallback(async () => {
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setItems([]);
    setIsDone(false);
    setIsRunning(true);

    try {
      const resp = await fetch("/api/verify-poc", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scanUrl,
          findingId: finding.id,
          category: finding.category,
          title: finding.title,
          detail: finding.detail ?? "",
        }),
        signal: ctrl.signal,
      });

      if (!resp.ok) {
        addItem({ kind: "line", text: `✗ Server error: ${resp.status} ${resp.statusText}`, style: "error" });
        setIsRunning(false);
        setIsDone(true);
        return;
      }

      if (!resp.body) {
        addItem({ kind: "line", text: "✗ No response stream received", style: "error" });
        setIsRunning(false);
        setIsDone(true);
        return;
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";

        for (const part of parts) {
          for (const rawLine of part.split("\n")) {
            if (!rawLine.startsWith("data: ")) continue;
            try {
              const ev = JSON.parse(rawLine.slice(6)) as SseEvent;

              if (ev.type === "line") {
                addItem({ kind: "line", text: ev.text ?? "", style: ev.style ?? "output" });
              } else if (ev.type === "phase") {
                addItem({ kind: "phase", phaseNum: ev.phaseNum ?? 1, name: ev.name ?? "" });
              } else if (ev.type === "evidence") {
                addItem({ kind: "evidence", lines: ev.lines ?? [] });
              } else if (ev.type === "done") {
                setIsRunning(false);
                setIsDone(true);
              }
            } catch {
              // malformed event — skip
            }
          }
        }
      }
    } catch (err: unknown) {
      const error = err as Error;
      if (error.name !== "AbortError") {
        addItem({ kind: "line", text: `✗ Connection error: ${error.message}`, style: "error" });
      }
    } finally {
      setIsRunning(false);
      setIsDone(true);
    }
  }, [finding, scanUrl, addItem]);

  // Auto-scroll on new items
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [items]);

  const handleOpen = () => {
    setIsOpen(true);
    runPoc();
  };

  const handleClose = () => {
    abortRef.current?.abort();
    setIsOpen(false);
    setItems([]);
    setIsDone(false);
    setIsRunning(false);
  };

  const lineCount = items.filter((i) => i.kind === "line").length;

  return (
    <div className="mt-3">
      {/* Launch button */}
      {!isOpen && (
        <button
          type="button"
          onClick={handleOpen}
          className="flex items-center gap-2 px-4 py-2 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 text-xs font-mono font-medium hover:bg-emerald-500/20 hover:border-emerald-500/60 transition-all"
        >
          <Play className="w-3.5 h-3.5" />
          Execute Live Proof of Concept
        </button>
      )}

      {/* Terminal window */}
      {isOpen && (
        <div className="rounded border border-emerald-500/20 overflow-hidden shadow-xl shadow-black/40">

          {/* Title bar */}
          <div className="flex items-center gap-2 px-3 py-2 bg-[#1a1a1a] border-b border-zinc-800/60">
            <div className="flex gap-1.5">
              <button
                type="button"
                onClick={handleClose}
                className="w-3 h-3 rounded-full bg-red-500/80 hover:bg-red-500 transition-colors"
                title="Close"
              />
              <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
              <div className="w-3 h-3 rounded-full bg-green-500/80" />
            </div>
            <div className="flex-1 flex items-center justify-center gap-2">
              <Terminal className="w-3 h-3 text-zinc-500" />
              <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">
                Live PoC Terminal — {finding.title.slice(0, 48)}{finding.title.length > 48 ? "…" : ""}
              </span>
            </div>
            {isRunning && (
              <span className="flex items-center gap-1 text-[10px] font-mono text-emerald-400">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                RUNNING
              </span>
            )}
            {isDone && !isRunning && (
              <span className="text-[10px] font-mono text-zinc-500">DONE</span>
            )}
          </div>

          {/* Output area */}
          <div className="bg-[#0c0c0c] h-[520px] overflow-y-auto p-4 font-mono text-[11px] leading-[1.6]">
            {items.length === 0 && isRunning && (
              <div className="text-zinc-600 animate-pulse">Connecting to exploit engine...</div>
            )}

            {items.map((item) => {
              if (item.kind === "phase") {
                return <PhaseMarker key={item.id} phaseNum={item.phaseNum} name={item.name} />;
              }
              if (item.kind === "evidence") {
                return <EvidenceBlock key={item.id} lines={item.lines} />;
              }
              // kind === "line"
              return (
                <div key={item.id} className="flex min-w-0">
                  {item.text === "" ? (
                    <div className="h-3" />
                  ) : (
                    <span className={`break-all whitespace-pre-wrap ${lineClass(item.style)}`}>
                      {item.text}
                    </span>
                  )}
                </div>
              );
            })}

            <div ref={endRef} />
          </div>

          {/* Action bar */}
          <div className="flex items-center gap-2 px-3 py-2 bg-[#141414] border-t border-zinc-800/60">
            <button
              type="button"
              onClick={() => { setItems([]); setIsDone(false); }}
              className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-mono text-zinc-400 hover:text-zinc-200 border border-zinc-700/50 hover:border-zinc-600 rounded transition-colors"
            >
              <Trash2 className="w-3 h-3" />
              Clear
            </button>
            <button
              type="button"
              onClick={runPoc}
              disabled={isRunning}
              className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-mono text-emerald-400 hover:text-emerald-300 border border-emerald-700/50 hover:border-emerald-600 rounded transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <RefreshCw className={`w-3 h-3 ${isRunning ? "animate-spin" : ""}`} />
              Re-run Exploit
            </button>
            <div className="flex-1" />
            <span className="text-[9px] font-mono text-zinc-700 uppercase tracking-widest">
              {lineCount} lines
            </span>
            <button
              type="button"
              onClick={handleClose}
              className="flex items-center gap-1 text-[10px] font-mono text-zinc-600 hover:text-zinc-400 transition-colors"
            >
              <X className="w-3 h-3" />
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
