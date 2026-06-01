import { useState } from "react";
import { Check, Copy, ShieldCheck } from "lucide-react";
import type { RemediationMap } from "@/lib/remediation-data";

export type { RemediationMap };

type TabKey = keyof RemediationMap;

// ── Tab metadata ──────────────────────────────────────────────────────────────

interface TabMeta {
  key: TabKey;
  label: string;
  lang: string;
}

const INFRA_TABS: TabMeta[] = [
  { key: "nginx",      label: "Nginx",           lang: "nginx" },
  { key: "apache",     label: "Apache / Tomcat",  lang: "apache" },
  { key: "nodejs",     label: "Node.js / Express",lang: "javascript" },
  { key: "iis",        label: "IIS",              lang: "xml" },
  { key: "caddy",      label: "Caddy",            lang: "caddy" },
  { key: "cloudflare", label: "Cloudflare",       lang: "text" },
];

const CODE_TABS: TabMeta[] = [
  { key: "nodejs",  label: "Node.js",        lang: "javascript" },
  { key: "php",     label: "PHP",            lang: "php" },
  { key: "python",  label: "Python / Django",lang: "python" },
  { key: "java",    label: "Java / Spring",  lang: "java" },
  { key: "ruby",    label: "Ruby on Rails",  lang: "ruby" },
];

// ── Server detection ──────────────────────────────────────────────────────────

export function detectServerTab(serverInfo: string | null | undefined): TabKey | null {
  if (!serverInfo) return null;
  const lower = serverInfo.toLowerCase();
  if (lower.includes("nginx"))   return "nginx";
  if (
    lower.includes("apache") ||
    lower.includes("httpd")  ||
    lower.includes("tomcat") ||
    lower.includes("coyote") ||
    lower.includes("jboss")  ||
    lower.includes("jetty")
  ) return "apache";
  if (lower.includes("microsoft-iis") || lower.includes("iis")) return "iis";
  if (lower.includes("caddy"))  return "caddy";
  if (lower.includes("cloudflare")) return "cloudflare";
  if (lower.includes("node")   || lower.includes("express")) return "nodejs";
  return null;
}

// ── Copy button ───────────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback: create textarea
      const el = document.createElement("textarea");
      el.value = text;
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <button
      type="button"
      onClick={copy}
      className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono transition-all ${
        copied
          ? "text-green-400 border border-green-500/40 bg-green-500/10"
          : "text-zinc-500 border border-zinc-700/50 hover:text-zinc-300 hover:border-zinc-600 bg-transparent"
      }`}
    >
      {copied ? (
        <><Check className="w-3 h-3" />Copied</>
      ) : (
        <><Copy className="w-3 h-3" />Copy</>
      )}
    </button>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface RemediationTabsProps {
  remediations: RemediationMap;
  serverInfo?: string | null;
  /** Hint: "injection" uses code tabs; otherwise infra tabs */
  category?: string;
}

export function RemediationTabs({ remediations, serverInfo, category }: RemediationTabsProps) {
  const isInjection = category === "injection";
  const tabSet = isInjection ? CODE_TABS : INFRA_TABS;

  // Only show tabs that have content
  const availableTabs = tabSet.filter((t) => remediations[t.key]);

  if (availableTabs.length === 0) return null;

  const detectedKey = !isInjection ? detectServerTab(serverInfo) : null;

  // Default to detected server if present, else first available
  const defaultTab: TabKey =
    detectedKey && availableTabs.find((t) => t.key === detectedKey)
      ? detectedKey
      : availableTabs[0].key;

  const [active, setActive] = useState<TabKey>(defaultTab);

  const activeMeta = availableTabs.find((t) => t.key === active);
  const activeCode = remediations[active] ?? "";

  return (
    <div className="rounded border border-border/40 overflow-hidden">
      {/* Tab bar */}
      <div className="flex items-center gap-0 bg-muted/30 border-b border-border/40 overflow-x-auto">
        {availableTabs.map((tab) => {
          const isDetected = tab.key === detectedKey;
          const isActive   = tab.key === active;
          return (
            <button
              key={tab.key}
              type="button"
              onClick={() => setActive(tab.key)}
              className={`relative flex items-center gap-1.5 px-3 py-2 text-[11px] font-mono whitespace-nowrap transition-colors flex-shrink-0 ${
                isActive
                  ? "bg-background text-foreground border-b-2 border-primary"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
              }`}
            >
              {tab.label}
              {isDetected && (
                <span className="flex items-center gap-0.5 px-1 py-px rounded-sm text-[8px] font-mono font-bold bg-primary/15 text-primary border border-primary/30 leading-none">
                  <ShieldCheck className="w-2 h-2" />
                  DETECTED
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Code block */}
      <div className="relative bg-[#0f0f0f]">
        <div className="absolute top-2 right-2 z-10">
          <CopyButton text={activeCode} />
        </div>
        <pre className="p-4 pr-20 text-[11px] font-mono leading-relaxed overflow-x-auto text-zinc-200 whitespace-pre">
          <code>
            {activeCode.split("\n").map((line, i) => {
              // Syntax hint colouring (lightweight, no library needed)
              if (line.startsWith("#") || line.startsWith("//") || line.startsWith("--")) {
                return <span key={i} className="text-zinc-500">{line}{"\n"}</span>;
              }
              if (line.trimStart().startsWith("add_header") || line.trimStart().startsWith("Header") || line.trimStart().startsWith("server_tokens")) {
                return <span key={i} className="text-sky-300">{line}{"\n"}</span>;
              }
              if (/^\s*(app\.|res\.|helmet|return|const|let|var|function|import|require|if )/.test(line)) {
                return <span key={i} className="text-emerald-300">{line}{"\n"}</span>;
              }
              if (line.includes("\"") || line.includes("'")) {
                // Highlight string values in amber
                const parts = line.split(/(["'][^"']*["'])/g);
                return (
                  <span key={i}>
                    {parts.map((p, j) =>
                      (p.startsWith('"') || p.startsWith("'"))
                        ? <span key={j} className="text-amber-300">{p}</span>
                        : <span key={j}>{p}</span>
                    )}
                    {"\n"}
                  </span>
                );
              }
              return <span key={i}>{line}{"\n"}</span>;
            })}
          </code>
        </pre>
      </div>
    </div>
  );
}
