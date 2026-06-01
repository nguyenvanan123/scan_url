import { useState, useEffect, useRef } from "react";
import { useRoute } from "wouter";
import { useGetScan, getGetScanQueryKey } from "@workspace/api-client-react";
import { formatDistanceToNow } from "date-fns";
import {
  ShieldAlert, ShieldCheck, AlertTriangle,
  Info, ArrowLeft, Server, Lock, Globe,
  FileCode, CheckCircle2, XCircle, Activity,
  ChevronDown, ChevronUp, Search, FolderLock, Syringe,
  Globe2, Link2, FormInput, Code2, Terminal, Download
} from "lucide-react";
import { Link } from "wouter";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScanFinding, ScanFindingCategory } from "@workspace/api-zod";
import { PocTerminal } from "@/components/poc-terminal";
import { RemediationTabs } from "@/components/remediation-tabs";
import { getClientRemediations } from "@/lib/remediation-data";
import { AttackScenariosPanel } from "@/components/attack-scenarios";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

// ── Server-Sent Events progress types ────────────────────────────────────────

type SseEvent =
  | { type: "phase";   message: string; pct: number }
  | { type: "target";  current: number; total: number; url: string; check: string }
  | { type: "finding"; severity: string; title: string }
  | { type: "done";    status: string; error?: string };

interface LogEntry {
  id: number;
  time: string;
  text: string;
  kind: "phase" | "target" | "finding" | "done" | "error";
}

// ── Live Scan Progress (SSE-powered) ─────────────────────────────────────────

function LiveScanProgress({ scanId, url }: { scanId: number; url: string }) {
  const [pct, setPct]               = useState(0);
  const [currentMsg, setCurrentMsg] = useState("Connecting to scan engine...");
  const [logs, setLogs]             = useState<LogEntry[]>([]);
  const logCounter                  = useRef(0);
  const logsEndRef                  = useRef<HTMLDivElement>(null);

  const addLog = (text: string, kind: LogEntry["kind"]) => {
    const id   = ++logCounter.current;
    const time = new Date().toLocaleTimeString("en-US", { hour12: false });
    setLogs((prev) => [...prev.slice(-299), { id, time, text, kind }]);
  };

  useEffect(() => {
    const es = new EventSource(`/api/scans/${scanId}/events`);

    es.onopen = () => {
      addLog("Connected to scan engine.", "phase");
    };

    es.onmessage = (e: MessageEvent) => {
      try {
        const ev = JSON.parse(e.data as string) as SseEvent;

        if (ev.type === "phase") {
          setPct(ev.pct);
          setCurrentMsg(ev.message);
          addLog(ev.message, "phase");

        } else if (ev.type === "target") {
          const progress = 45 + Math.round((ev.current / ev.total) * 47);
          setPct(progress);
          setCurrentMsg(`[${ev.current}/${ev.total}] ${new URL(ev.url).pathname}${new URL(ev.url).search}`);
          addLog(`[${ev.current}/${ev.total}] ${ev.url}`, "target");

        } else if (ev.type === "finding") {
          addLog(`⚑ [${ev.severity.toUpperCase()}] ${ev.title}`, "finding");

        } else if (ev.type === "done") {
          setPct(100);
          setCurrentMsg(ev.status === "completed" ? "Scan complete." : `Scan failed: ${ev.error ?? "unknown error"}`);
          addLog(ev.status === "completed" ? "✓ Scan complete." : `✗ Failed: ${ev.error ?? "unknown"}`, "done");
          es.close();
        }
      } catch {
        // ignore malformed events
      }
    };

    es.onerror = () => {
      addLog("SSE connection closed.", "error");
      es.close();
    };

    return () => es.close();
  }, [scanId]);

  // Auto-scroll logs console
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <Card className="border-primary/30 bg-card">
      <CardContent className="py-8 px-6 md:px-8">
        <div className="max-w-2xl mx-auto space-y-6">

          {/* Icon + target + current message */}
          <div className="flex items-start gap-4">
            <div className="relative flex-shrink-0 mt-0.5">
              <div className="w-11 h-11 rounded-full border border-primary/30 flex items-center justify-center">
                <Search className="w-5 h-5 text-primary animate-pulse" />
              </div>
              <div className="absolute inset-0 rounded-full border border-transparent border-t-primary animate-spin" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-0.5">Target</div>
              <div className="font-mono text-sm text-foreground truncate" title={url}>{url}</div>
              <div className="font-mono text-xs text-primary/80 truncate mt-1" title={currentMsg}>{currentMsg}</div>
            </div>
          </div>

          {/* Real-time progress bar */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[10px] font-mono text-muted-foreground">
              <span className="uppercase tracking-widest">Progress</span>
              <span className="text-primary font-bold tabular-nums">{pct}%</span>
            </div>
            <div className="h-1.5 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-primary rounded-full transition-all duration-500 ease-out"
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>

          {/* Live log console */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Terminal className="w-3 h-3 text-muted-foreground" />
              <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">Live Output</span>
              <span className="ml-auto flex items-center gap-1 text-[10px] font-mono text-primary">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                LIVE
              </span>
            </div>
            <div className="rounded border border-border/40 bg-[#0c0c0c] h-52 overflow-y-auto p-3 space-y-px font-mono text-[11px] leading-5">
              {logs.length === 0 && (
                <div className="text-zinc-600 italic">Waiting for scan events...</div>
              )}
              {logs.map((entry) => (
                <div key={entry.id} className="flex gap-2.5 min-w-0">
                  <span className="text-zinc-600 flex-shrink-0 select-none tabular-nums">{entry.time}</span>
                  <span
                    className={
                      entry.kind === "finding"
                        ? "text-red-400 break-all"
                        : entry.kind === "done"
                        ? "text-green-400"
                        : entry.kind === "error"
                        ? "text-yellow-500"
                        : entry.kind === "target"
                        ? "text-zinc-300 break-all"
                        : "text-cyan-400/80"
                    }
                  >
                    {entry.text}
                  </span>
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          </div>

        </div>
      </CardContent>
    </Card>
  );
}

// ── Finding card ──────────────────────────────────────────────────────────────

interface FindingCardProps {
  finding: ScanFinding;
  scanUrl: string;
  serverInfo?: string | null;
}

function FindingCard({ finding, scanUrl, serverInfo }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);

  const severityConfig = getSeverityConfig(finding.severity);

  return (
    <div
      className={`border-l-4 ${severityConfig.borderColor} ${severityConfig.bgColor} border border-r border-t border-b ${severityConfig.cardBorder} rounded-sm overflow-hidden transition-all`}
    >
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-black/5 dark:hover:bg-white/5 transition-colors"
      >
        <span className="flex-shrink-0">{getStatusIcon(finding.status)}</span>
        <span className="font-mono text-sm font-medium flex-1 min-w-0 truncate">{finding.title}</span>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${severityConfig.badgeBg} ${severityConfig.badgeText}`}>
            {finding.severity.toUpperCase()}
          </span>
          {expanded
            ? <ChevronUp className="w-4 h-4 text-muted-foreground" />
            : <ChevronDown className="w-4 h-4 text-muted-foreground" />
          }
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-border/30">
          <div className="pt-3 text-sm text-foreground/80 font-sans leading-relaxed">
            {finding.description}
          </div>

          {finding.detail && (
            <div>
              <div className="text-[10px] font-mono font-bold text-muted-foreground uppercase tracking-widest mb-1">Detail</div>
              <pre className="p-3 bg-background/60 dark:bg-black/30 border border-border/40 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">
                {finding.detail}
              </pre>
            </div>
          )}

          {(() => {
            const storedRem = finding.remediations && Object.values(finding.remediations).some(Boolean)
              ? finding.remediations
              : null;
            const clientRem = !storedRem
              ? getClientRemediations(finding.id, finding.category)
              : null;
            const remediations = storedRem ?? clientRem;
            return (remediations || finding.recommendation) ? (
              <div>
                <div className="text-[10px] font-mono font-bold text-muted-foreground uppercase tracking-widest mb-2">Remediation</div>
                {remediations ? (
                  <RemediationTabs
                    remediations={remediations}
                    serverInfo={serverInfo}
                    category={finding.category}
                  />
                ) : (
                  <div className={`p-3 rounded text-sm font-sans leading-relaxed ${severityConfig.remediationBg} ${severityConfig.remediationText} border ${severityConfig.remediationBorder}`}>
                    {finding.recommendation}
                  </div>
                )}
              </div>
            ) : null;
          })()}

          {finding.execution_poc && (
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <div className="text-[10px] font-mono font-bold text-amber-500 dark:text-amber-400 uppercase tracking-widest">
                  PoC / How to Exploit
                </div>
                <div className="h-px flex-1 bg-amber-500/20 dark:bg-amber-400/20" />
                <div className="text-[9px] font-mono text-amber-600/60 dark:text-amber-400/50 uppercase">
                  for authorised testing only
                </div>
              </div>
              <div className="relative rounded overflow-hidden border border-amber-500/20 dark:border-amber-400/15">
                <div className="absolute top-0 left-0 right-0 h-6 bg-[#1e1e1e] flex items-center px-3 gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
                  <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/70" />
                  <div className="w-2.5 h-2.5 rounded-full bg-green-500/70" />
                  <span className="ml-1 text-[9px] font-mono text-zinc-500">bash</span>
                </div>
                <pre className="pt-8 pb-3 px-4 bg-[#1e1e1e] text-xs font-mono overflow-x-auto whitespace-pre leading-relaxed">
                  <code className="text-zinc-200">{finding.execution_poc.split("\n").map((line: string, i: number) => {
                    if (line.startsWith("#")) {
                      return <span key={i} className="text-zinc-500">{line}{"\n"}</span>;
                    }
                    if (line.startsWith("curl") || line.startsWith("sqlmap") || line.startsWith("dig") || line.startsWith("nslookup") || line.startsWith("openssl") || line.startsWith("swaks") || line.startsWith("hashcat") || line.startsWith("git-dumper") || line.startsWith("arpspoof") || line.startsWith("mitmproxy") || line.startsWith("tcpdump") || line.startsWith("sslstrip") || line.startsWith("nc ") || line.startsWith("certbot") || line.startsWith("pip ") || line.startsWith("mysql") || line.startsWith("psql")) {
                      return <span key={i} className="text-emerald-400">{line}{"\n"}</span>;
                    }
                    return <span key={i}>{line}{"\n"}</span>;
                  })}</code>
                </pre>
              </div>

              {/* Live execution terminal */}
              <PocTerminal finding={finding} scanUrl={scanUrl} />
            </div>
          )}

          {/* Attack scenario simulator */}
          <AttackScenariosPanel findingId={finding.id} scanUrl={scanUrl} />
        </div>
      )}
    </div>
  );
}

// ── Main scan detail page ─────────────────────────────────────────────────────

export default function ScanDetail() {
  const [, params] = useRoute("/scans/:id");
  const id = params?.id ? parseInt(params.id) : 0;

  const { data: scan, isLoading } = useGetScan(id, {
    query: {
      queryKey: getGetScanQueryKey(id),
      enabled: !!id,
      refetchInterval: (query) => {
        const status = query.state.data?.status;
        return status === "pending" || status === "running" ? 2000 : false;
      },
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-6 max-w-4xl mx-auto">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-20 font-mono text-muted-foreground">
        SCAN NOT FOUND
      </div>
    );
  }

  const isRunning = scan.status === "pending" || scan.status === "running";

  const sortedFindings = [...(scan.result?.findings ?? [])].sort((a, b) => {
    return SEVERITY_ORDER.indexOf(a.severity as any) - SEVERITY_ORDER.indexOf(b.severity as any);
  });

  const groupedBySeverity = SEVERITY_ORDER.reduce<Record<string, ScanFinding[]>>((acc, sev) => {
    const items = sortedFindings.filter((f) => f.severity === sev && f.status !== "pass");
    if (items.length) acc[sev] = items;
    return acc;
  }, {});

  const passed = sortedFindings.filter((f) => f.status === "pass");

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-start gap-3">
        <Link href="/">
          <Button variant="ghost" size="icon" className="text-muted-foreground mt-0.5 flex-shrink-0">
            <ArrowLeft className="w-5 h-5" />
          </Button>
        </Link>
        <div className="min-w-0 flex-1">
          <h1 className="text-base font-mono font-bold flex flex-wrap items-center gap-2">
            <span className="truncate">{scan.url}</span>
            <Badge variant="outline" className={
              scan.status === "completed" ? "border-primary text-primary" :
              scan.status === "failed" ? "border-destructive text-destructive" :
              "border-yellow-500 text-yellow-500 animate-pulse"
            }>
              {scan.status.toUpperCase()}
            </Badge>
          </h1>
          <div className="text-xs font-mono text-muted-foreground mt-1">
            SCAN #{scan.id} &bull; {formatDistanceToNow(new Date(scan.createdAt), { addSuffix: true })}
          </div>
        </div>
        {scan.status === "completed" && scan.result && (
          <Button
            variant="outline"
            size="sm"
            className="font-mono text-xs flex-shrink-0 h-8 mt-0.5"
            onClick={() => window.open(`/api/scans/${scan.id}/export`, "_blank")}
          >
            <Download className="w-3 h-3 mr-1" />
            Export
          </Button>
        )}
      </div>

      {/* Running state — live SSE progress */}
      {isRunning && <LiveScanProgress scanId={scan.id} url={scan.url} />}

      {/* Failed state */}
      {!isRunning && !scan.result && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent className="py-8 text-center">
            <AlertTriangle className="w-10 h-10 text-destructive mx-auto mb-2" />
            <h2 className="font-mono font-bold text-destructive">SCAN FAILED</h2>
            <p className="font-mono text-sm text-muted-foreground mt-2">{scan.errorMessage || "Unknown error occurred"}</p>
          </CardContent>
        </Card>
      )}

      {/* Completed results */}
      {scan.result && (
        <>
          {/* Metadata cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <MetaCard label="Response Time" value={`${scan.result.responseTimeMs}ms`} />
            <MetaCard label="Server" value={scan.result.serverInfo || "Hidden"} />
            <MetaCard label="IP Address" value={scan.result.ipAddress || "N/A"} />
            <MetaCard
              label="SSL"
              value={scan.result.sslValid === null ? "N/A" : scan.result.sslValid ? "Valid" : "Invalid"}
              icon={scan.result.sslValid
                ? <ShieldCheck className="w-4 h-4 text-green-500" />
                : <ShieldAlert className="w-4 h-4 text-destructive" />}
            />
          </div>

          {/* Spider / Crawl summary */}
          {scan.result.crawlSummary && (
            <CrawlSummarySection crawlSummary={scan.result.crawlSummary as any} />
          )}

          {/* Summary pills */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Summary</span>
            {scan.result.summary.critical > 0 && <SummaryPill count={scan.result.summary.critical} label="Critical" color="bg-red-500/15 text-red-500 border-red-500/30" />}
            {scan.result.summary.high > 0 && <SummaryPill count={scan.result.summary.high} label="High" color="bg-orange-500/15 text-orange-500 border-orange-500/30" />}
            {scan.result.summary.medium > 0 && <SummaryPill count={scan.result.summary.medium} label="Medium" color="bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30" />}
            {scan.result.summary.low > 0 && <SummaryPill count={scan.result.summary.low} label="Low" color="bg-green-500/15 text-green-600 dark:text-green-400 border-green-500/30" />}
            {scan.result.summary.passed > 0 && <SummaryPill count={scan.result.summary.passed} label="Passed" color="bg-muted text-muted-foreground border-border" />}
          </div>

          {/* Findings grouped by severity */}
          {Object.entries(groupedBySeverity).map(([severity, findings]) => {
            const cfg = getSeverityConfig(severity);
            return (
              <section key={severity} className="space-y-2">
                <div className={`flex items-center gap-2 font-mono text-xs font-bold uppercase tracking-widest ${cfg.labelColor}`}>
                  {cfg.icon}
                  {severity} <span className="font-normal text-muted-foreground">({findings.length})</span>
                </div>
                <div className="space-y-2">
                  {findings.map((f) => <FindingCard key={f.id} finding={f} scanUrl={scan.url} serverInfo={scan.result?.serverInfo} />)}
                </div>
              </section>
            );
          })}

          {/* Passed checks */}
          {passed.length > 0 && (
            <section className="space-y-2">
              <div className="flex items-center gap-2 font-mono text-xs font-bold uppercase tracking-widest text-muted-foreground">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Passed checks <span className="font-normal">({passed.length})</span>
              </div>
              <div className="space-y-1">
                {passed.map((f) => (
                  <div key={f.id} className="flex items-center gap-3 px-4 py-2.5 border border-border/40 bg-card/50 rounded-sm">
                    <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                    <span className="font-mono text-xs text-muted-foreground">{f.title}</span>
                    <span className="ml-auto text-[10px] font-mono text-green-600 dark:text-green-400 uppercase">Pass</span>
                  </div>
                ))}
              </div>
            </section>
          )}
        </>
      )}
    </div>
  );
}

// ── Supporting components ─────────────────────────────────────────────────────

interface CrawlSummaryData {
  pagesVisited: number;
  urlsDiscovered: number;
  urlsWithParams: string[];
  urls: string[];
  jsFiles: string[];
  errors: string[];
}

function CrawlSummarySection({ crawlSummary }: { crawlSummary: CrawlSummaryData }) {
  const [expanded, setExpanded] = useState(false);
  const [showAll, setShowAll] = useState(false);

  const displayUrls = showAll ? crawlSummary.urls : crawlSummary.urls.slice(0, 10);

  return (
    <Card className="border-primary/20 bg-card/80">
      <CardContent className="pt-4 pb-4 px-4">
        {/* Header row */}
        <button
          type="button"
          className="w-full flex items-center gap-3 text-left"
          onClick={() => setExpanded((v) => !v)}
        >
          <Globe2 className="w-4 h-4 text-primary flex-shrink-0" />
          <span className="font-mono text-xs font-bold uppercase tracking-widest text-primary flex-1">
            Spider Results
          </span>
          <div className="flex items-center gap-3 text-[11px] font-mono text-muted-foreground">
            <span className="flex items-center gap-1">
              <FileCode className="w-3 h-3" />
              {crawlSummary.pagesVisited} pages
            </span>
            <span className="flex items-center gap-1">
              <Link2 className="w-3 h-3" />
              {crawlSummary.urlsDiscovered} URLs
            </span>
            {crawlSummary.urlsWithParams.length > 0 && (
              <span className="flex items-center gap-1 text-yellow-500 dark:text-yellow-400">
                <Syringe className="w-3 h-3" />
                {crawlSummary.urlsWithParams.length} injection targets
              </span>
            )}
            {crawlSummary.jsFiles.length > 0 && (
              <span className="flex items-center gap-1">
                <Code2 className="w-3 h-3" />
                {crawlSummary.jsFiles.length} JS files
              </span>
            )}
          </div>
          {expanded ? (
            <ChevronUp className="w-4 h-4 text-muted-foreground flex-shrink-0" />
          ) : (
            <ChevronDown className="w-4 h-4 text-muted-foreground flex-shrink-0" />
          )}
        </button>

        {expanded && (
          <div className="mt-4 space-y-4">
            {/* Injection targets */}
            {crawlSummary.urlsWithParams.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-2 text-[10px] font-mono text-yellow-500 dark:text-yellow-400 uppercase tracking-widest">
                  <Syringe className="w-3 h-3" />
                  Injection Targets ({crawlSummary.urlsWithParams.length} URLs with query params)
                </div>
                <div className="rounded border border-yellow-500/20 bg-yellow-500/5 p-2 max-h-40 overflow-y-auto space-y-0.5">
                  {crawlSummary.urlsWithParams.map((u, i) => (
                    <div key={i} className="font-mono text-[11px] text-yellow-700 dark:text-yellow-300 truncate" title={u}>
                      {u}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* All discovered URLs */}
            <div>
              <div className="flex items-center gap-2 mb-2 text-[10px] font-mono text-muted-foreground uppercase tracking-widest">
                <Link2 className="w-3 h-3" />
                Discovered Internal URLs ({crawlSummary.urlsDiscovered})
              </div>
              <div className="rounded border border-border/40 bg-muted/20 p-2 max-h-56 overflow-y-auto space-y-0.5">
                {displayUrls.map((u, i) => (
                  <div key={i} className="font-mono text-[11px] text-muted-foreground truncate" title={u}>
                    {u}
                  </div>
                ))}
                {!showAll && crawlSummary.urls.length > 10 && (
                  <button
                    type="button"
                    className="text-[11px] font-mono text-primary mt-1 hover:underline"
                    onClick={() => setShowAll(true)}
                  >
                    + {crawlSummary.urls.length - 10} more…
                  </button>
                )}
              </div>
            </div>

            {/* JS files */}
            {crawlSummary.jsFiles.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-2 text-[10px] font-mono text-muted-foreground uppercase tracking-widest">
                  <Code2 className="w-3 h-3" />
                  JavaScript Files ({crawlSummary.jsFiles.length})
                </div>
                <div className="rounded border border-border/40 bg-muted/20 p-2 max-h-32 overflow-y-auto space-y-0.5">
                  {crawlSummary.jsFiles.slice(0, 20).map((u, i) => (
                    <div key={i} className="font-mono text-[11px] text-muted-foreground truncate" title={u}>
                      {u}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Crawler errors */}
            {crawlSummary.errors.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-2 text-[10px] font-mono text-destructive/60 uppercase tracking-widest">
                  <XCircle className="w-3 h-3" />
                  Crawl Errors ({crawlSummary.errors.length})
                </div>
                <div className="rounded border border-destructive/20 bg-destructive/5 p-2 max-h-24 overflow-y-auto space-y-0.5">
                  {crawlSummary.errors.slice(0, 10).map((e, i) => (
                    <div key={i} className="font-mono text-[11px] text-destructive/70 truncate" title={e}>
                      {e}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function MetaCard({ label, value, icon }: { label: string; value: string; icon?: React.ReactNode }) {
  return (
    <Card className="border-border/50 bg-card/60">
      <CardContent className="pt-4 pb-3 px-4">
        <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-1">{label}</div>
        <div className="text-sm font-mono font-medium truncate flex items-center gap-1.5" title={value}>
          {icon}
          {value}
        </div>
      </CardContent>
    </Card>
  );
}

function SummaryPill({ count, label, color }: { count: number; label: string; color: string }) {
  return (
    <span className={`text-xs font-mono font-bold px-2.5 py-1 rounded border ${color}`}>
      {count} {label}
    </span>
  );
}

function getSeverityConfig(severity: string) {
  switch (severity) {
    case "critical":
      return {
        borderColor: "border-l-red-500",
        bgColor: "bg-red-500/5",
        cardBorder: "border-red-500/20",
        badgeBg: "bg-red-500/15",
        badgeText: "text-red-500",
        labelColor: "text-red-500",
        icon: <ShieldAlert className="w-3.5 h-3.5" />,
        remediationBg: "bg-red-500/5",
        remediationText: "text-foreground",
        remediationBorder: "border-red-500/20",
      };
    case "high":
      return {
        borderColor: "border-l-orange-500",
        bgColor: "bg-orange-500/5",
        cardBorder: "border-orange-500/20",
        badgeBg: "bg-orange-500/15",
        badgeText: "text-orange-500",
        labelColor: "text-orange-500",
        icon: <AlertTriangle className="w-3.5 h-3.5" />,
        remediationBg: "bg-orange-500/5",
        remediationText: "text-foreground",
        remediationBorder: "border-orange-500/20",
      };
    case "medium":
      return {
        borderColor: "border-l-yellow-500",
        bgColor: "bg-yellow-500/5",
        cardBorder: "border-yellow-500/20",
        badgeBg: "bg-yellow-500/15",
        badgeText: "text-yellow-600 dark:text-yellow-400",
        labelColor: "text-yellow-600 dark:text-yellow-400",
        icon: <AlertTriangle className="w-3.5 h-3.5" />,
        remediationBg: "bg-yellow-500/5",
        remediationText: "text-foreground",
        remediationBorder: "border-yellow-500/20",
      };
    case "low":
      return {
        borderColor: "border-l-green-500",
        bgColor: "bg-green-500/5",
        cardBorder: "border-green-500/20",
        badgeBg: "bg-green-500/15",
        badgeText: "text-green-600 dark:text-green-400",
        labelColor: "text-green-600 dark:text-green-400",
        icon: <Info className="w-3.5 h-3.5" />,
        remediationBg: "bg-green-500/5",
        remediationText: "text-foreground",
        remediationBorder: "border-green-500/20",
      };
    default:
      return {
        borderColor: "border-l-zinc-500",
        bgColor: "bg-zinc-500/5",
        cardBorder: "border-zinc-500/20",
        badgeBg: "bg-zinc-500/15",
        badgeText: "text-zinc-500",
        labelColor: "text-zinc-500",
        icon: <Info className="w-3.5 h-3.5" />,
        remediationBg: "bg-zinc-500/5",
        remediationText: "text-foreground",
        remediationBorder: "border-zinc-500/20",
      };
  }
}

function getStatusIcon(status: string) {
  switch (status) {
    case "pass":
      return <CheckCircle2 className="w-4 h-4 text-green-500" />;
    case "fail":
      return <XCircle className="w-4 h-4 text-destructive" />;
    case "warning":
      return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
    default:
      return <Info className="w-4 h-4 text-muted-foreground" />;
  }
}
