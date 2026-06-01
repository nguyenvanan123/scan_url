import { useState, useEffect } from "react";
import { useRoute } from "wouter";
import { useGetScan, getGetScanQueryKey } from "@workspace/api-client-react";
import { formatDistanceToNow } from "date-fns";
import {
  ShieldAlert, ShieldCheck, AlertTriangle,
  Info, ArrowLeft, Server, Lock, Globe,
  FileCode, CheckCircle2, XCircle, Activity,
  ChevronDown, ChevronUp, Wifi, Search
} from "lucide-react";
import { Link } from "wouter";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScanFinding, ScanFindingCategory } from "@workspace/api-zod";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

const SCAN_STAGES = [
  "Resolving DNS records...",
  "Checking SSL/TLS certificate...",
  "Probing HTTP security headers...",
  "Inspecting server information...",
  "Discovering content paths...",
  "Testing HTTP methods...",
  "Aggregating findings...",
];

function ScanningAnimation({ url }: { url: string }) {
  const [stageIndex, setStageIndex] = useState(0);
  const [dots, setDots] = useState("");

  useEffect(() => {
    const stageTimer = setInterval(() => {
      setStageIndex((i) => (i + 1) % SCAN_STAGES.length);
    }, 2000);
    const dotsTimer = setInterval(() => {
      setDots((d) => (d.length >= 3 ? "" : d + "."));
    }, 400);
    return () => { clearInterval(stageTimer); clearInterval(dotsTimer); };
  }, []);

  return (
    <Card className="border-primary/30 bg-card">
      <CardContent className="py-12 px-8">
        <div className="max-w-lg mx-auto space-y-8">
          {/* Animated scanner icon */}
          <div className="flex justify-center">
            <div className="relative">
              <div className="w-20 h-20 rounded-full border-2 border-primary/20 flex items-center justify-center">
                <div className="w-14 h-14 rounded-full border-2 border-primary/40 flex items-center justify-center">
                  <Search className="w-7 h-7 text-primary animate-pulse" />
                </div>
              </div>
              <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-primary animate-spin" />
            </div>
          </div>

          {/* Target URL */}
          <div className="text-center">
            <div className="text-xs font-mono text-muted-foreground mb-1 uppercase tracking-widest">Target</div>
            <div className="font-mono text-sm text-foreground truncate">{url}</div>
          </div>

          {/* Progress bar */}
          <div className="space-y-2">
            <div className="h-1 bg-muted rounded-full overflow-hidden">
              <div className="h-full w-1/3 bg-primary rounded-full scan-sweep" />
            </div>
            <div className="flex items-center gap-2 font-mono text-xs text-primary">
              <span className="inline-block w-2 h-2 rounded-full bg-primary animate-pulse" />
              <span>{SCAN_STAGES[stageIndex]}<span className="blink">{dots}</span></span>
            </div>
          </div>

          {/* Stage checklist */}
          <div className="space-y-2">
            {SCAN_STAGES.slice(0, -1).map((stage, i) => (
              <div key={stage} className="flex items-center gap-3 font-mono text-xs">
                {i < stageIndex ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-green-500 flex-shrink-0" />
                ) : i === stageIndex ? (
                  <div className="w-3.5 h-3.5 rounded-full border border-primary animate-pulse flex-shrink-0" />
                ) : (
                  <div className="w-3.5 h-3.5 rounded-full border border-border flex-shrink-0" />
                )}
                <span className={i < stageIndex ? "text-muted-foreground line-through" : i === stageIndex ? "text-foreground" : "text-muted-foreground/50"}>
                  {stage}
                </span>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

interface FindingCardProps {
  finding: ScanFinding;
}

function FindingCard({ finding }: FindingCardProps) {
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

          {finding.recommendation && (
            <div>
              <div className="text-[10px] font-mono font-bold text-muted-foreground uppercase tracking-widest mb-1">Remediation</div>
              <div className={`p-3 rounded text-sm font-sans leading-relaxed ${severityConfig.remediationBg} ${severityConfig.remediationText} border ${severityConfig.remediationBorder}`}>
                {finding.recommendation}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ScanDetail() {
  const [, params] = useRoute("/scans/:id");
  const id = params?.id ? parseInt(params.id) : 0;

  const { data: scan, isLoading } = useGetScan(id, {
    query: {
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
      </div>

      {/* Running state */}
      {isRunning && <ScanningAnimation url={scan.url} />}

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
                  {findings.map((f) => <FindingCard key={f.id} finding={f} />)}
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
    default: // info
      return {
        borderColor: "border-l-slate-400",
        bgColor: "bg-slate-500/5",
        cardBorder: "border-slate-500/20",
        badgeBg: "bg-slate-500/10",
        badgeText: "text-slate-500",
        labelColor: "text-muted-foreground",
        icon: <Info className="w-3.5 h-3.5" />,
        remediationBg: "bg-slate-500/5",
        remediationText: "text-foreground",
        remediationBorder: "border-slate-500/20",
      };
  }
}

function getStatusIcon(status: string) {
  switch (status) {
    case "pass":    return <CheckCircle2 className="w-4 h-4 text-green-500" />;
    case "fail":    return <XCircle className="w-4 h-4 text-red-500" />;
    case "warning": return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
    default:        return <Info className="w-4 h-4 text-slate-400" />;
  }
}
