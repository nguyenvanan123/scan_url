import { useState, useEffect, useRef, useCallback } from "react";
import { Terminal, Play, Trash2, RefreshCw, X, ChevronDown } from "lucide-react";
import { ScanFinding } from "@workspace/api-zod";

// ── Types ─────────────────────────────────────────────────────────────────────

type LineStyle = "cmd" | "output" | "success" | "error" | "info" | "warn" | "dim" | "highlight";

interface TermLine {
  id: number;
  text: string;
  style: LineStyle;
}

interface SseEvent {
  type: "line" | "done";
  text?: string;
  style?: LineStyle;
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

// ── Main component ────────────────────────────────────────────────────────────

interface PocTerminalProps {
  finding: ScanFinding;
  scanUrl: string;
}

export function PocTerminal({ finding, scanUrl }: PocTerminalProps) {
  const [isOpen, setIsOpen]       = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [lines, setLines]         = useState<TermLine[]>([]);
  const [isDone, setIsDone]       = useState(false);
  const abortRef                  = useRef<AbortController | null>(null);
  const endRef                    = useRef<HTMLDivElement>(null);
  const lineCounter               = useRef(0);

  if (!finding.execution_poc) return null;

  const addLine = useCallback((text: string, style: LineStyle) => {
    setLines((prev) => [
      ...prev.slice(-499),
      { id: ++lineCounter.current, text, style },
    ]);
  }, []);

  const runPoc = useCallback(async () => {
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setLines([]);
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
        addLine(`✗ Server error: ${resp.status} ${resp.statusText}`, "error");
        setIsRunning(false);
        setIsDone(true);
        return;
      }

      if (!resp.body) {
        addLine("✗ No response stream received", "error");
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
                addLine(ev.text ?? "", ev.style ?? "output");
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
        addLine(`✗ Connection error: ${error.message}`, "error");
      }
    } finally {
      setIsRunning(false);
      setIsDone(true);
    }
  }, [finding, scanUrl, addLine]);

  // Auto-scroll on new lines
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines]);

  const handleOpen = () => {
    setIsOpen(true);
    runPoc();
  };

  const handleClose = () => {
    abortRef.current?.abort();
    setIsOpen(false);
    setLines([]);
    setIsDone(false);
    setIsRunning(false);
  };

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
                Live PoC Terminal — {finding.title.slice(0, 50)}{finding.title.length > 50 ? "…" : ""}
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
          <div className="bg-[#0c0c0c] h-80 overflow-y-auto p-4 font-mono text-[11px] leading-[1.6] space-y-px">
            {lines.length === 0 && isRunning && (
              <div className="text-zinc-600 animate-pulse">Connecting to exploit engine...</div>
            )}
            {lines.map((l) => (
              <div key={l.id} className="flex min-w-0">
                {l.text === "" ? (
                  <div className="h-3" />
                ) : (
                  <span className={`break-all whitespace-pre-wrap ${lineClass(l.style)}`}>
                    {l.text}
                  </span>
                )}
              </div>
            ))}
            <div ref={endRef} />
          </div>

          {/* Action bar */}
          <div className="flex items-center gap-2 px-3 py-2 bg-[#141414] border-t border-zinc-800/60">
            <button
              type="button"
              onClick={() => { setLines([]); setIsDone(false); }}
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
              {lines.length} lines
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
