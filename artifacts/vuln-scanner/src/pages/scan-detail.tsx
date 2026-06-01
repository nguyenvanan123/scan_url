import { useRoute } from "wouter";
import { useGetScan } from "@workspace/api-client-react";
import { formatDistanceToNow } from "date-fns";
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, 
  Info, Loader2, ArrowLeft, Server, Lock, Globe,
  FileCode, CheckCircle2, XCircle,
  Activity
} from "lucide-react";
import { Link } from "wouter";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { ScanFinding, ScanFindingCategory } from "@workspace/api-zod";

export default function ScanDetail() {
  const [, params] = useRoute("/scans/:id");
  const id = params?.id ? parseInt(params.id) : 0;

  const { data: scan, isLoading } = useGetScan(id, {
    query: {
      enabled: !!id,
      refetchInterval: (query) => {
        const status = query.state.data?.status;
        return status === 'pending' || status === 'running' ? 2000 : false;
      }
    }
  });

  if (isLoading) {
    return (
      <div className="space-y-6 max-w-5xl mx-auto">
        <Skeleton className="h-8 w-32" />
        <Skeleton className="h-32 w-full" />
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

  const isRunning = scan.status === 'pending' || scan.status === 'running';

  // Group findings
  const groupedFindings = scan.result?.findings?.reduce((acc, finding) => {
    if (!acc[finding.category]) acc[finding.category] = [];
    acc[finding.category].push(finding);
    return acc;
  }, {} as Record<string, ScanFinding[]>) || {};

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-4">
        <Link href="/">
          <Button variant="ghost" size="icon" className="text-muted-foreground">
            <ArrowLeft className="w-5 h-5" />
          </Button>
        </Link>
        <div>
          <h1 className="text-xl font-mono font-bold flex items-center gap-3">
            {scan.url}
            <Badge variant="outline" className={
              scan.status === 'completed' ? 'border-primary text-primary' :
              scan.status === 'failed' ? 'border-destructive text-destructive' :
              'border-yellow-500 text-yellow-500 animate-pulse'
            }>
              {scan.status.toUpperCase()}
            </Badge>
          </h1>
          <div className="text-xs font-mono text-muted-foreground mt-1">
            SCAN ID: #{scan.id} • {formatDistanceToNow(new Date(scan.createdAt), { addSuffix: true })}
          </div>
        </div>
      </div>

      {isRunning ? (
        <Card className="border-primary/50 bg-primary/5">
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Loader2 className="w-12 h-12 text-primary animate-spin mb-4" />
            <h2 className="font-mono font-bold text-lg mb-2 text-primary animate-pulse">SCAN IN PROGRESS</h2>
            <p className="font-mono text-sm text-muted-foreground">Analyzing target vectors. This may take a moment...</p>
          </CardContent>
        </Card>
      ) : scan.result ? (
        <>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="border-border/50">
              <CardContent className="pt-6">
                <div className="text-xs font-mono text-muted-foreground mb-1">RESPONSE TIME</div>
                <div className="text-2xl font-mono">{scan.result.responseTimeMs}ms</div>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="pt-6">
                <div className="text-xs font-mono text-muted-foreground mb-1">SERVER INFO</div>
                <div className="text-sm font-mono truncate" title={scan.result.serverInfo || "Unknown"}>
                  {scan.result.serverInfo || "N/A"}
                </div>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="pt-6">
                <div className="text-xs font-mono text-muted-foreground mb-1">IP ADDRESS</div>
                <div className="text-sm font-mono">{scan.result.ipAddress || "N/A"}</div>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="pt-6">
                <div className="text-xs font-mono text-muted-foreground mb-1">SSL STATUS</div>
                <div className="text-sm font-mono flex items-center gap-2">
                  {scan.result.sslValid ? (
                    <span className="text-primary flex items-center gap-1"><ShieldCheck className="w-4 h-4"/> VALID</span>
                  ) : (
                    <span className="text-destructive flex items-center gap-1"><ShieldAlert className="w-4 h-4"/> INVALID</span>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="flex items-center gap-2 font-mono text-sm border-b border-border/50 pb-2 mt-8">
            <span className="text-muted-foreground">SUMMARY:</span>
            {scan.result.summary.critical > 0 && <Badge variant="outline" className="border-red-500 text-red-500">{scan.result.summary.critical} CRITICAL</Badge>}
            {scan.result.summary.high > 0 && <Badge variant="outline" className="border-orange-500 text-orange-500">{scan.result.summary.high} HIGH</Badge>}
            {scan.result.summary.medium > 0 && <Badge variant="outline" className="border-yellow-500 text-yellow-500">{scan.result.summary.medium} MEDIUM</Badge>}
            {scan.result.summary.low > 0 && <Badge variant="outline" className="border-blue-400 text-blue-400">{scan.result.summary.low} LOW</Badge>}
            {scan.result.summary.info > 0 && <Badge variant="outline" className="border-gray-400 text-gray-400">{scan.result.summary.info} INFO</Badge>}
          </div>

          <div className="space-y-6">
            {Object.entries(groupedFindings).map(([category, findings]) => (
              <div key={category} className="space-y-3">
                <h3 className="font-mono text-sm font-bold flex items-center gap-2 uppercase">
                  {getCategoryIcon(category as ScanFindingCategory)}
                  {category.replace('_', ' ')}
                  <span className="text-muted-foreground ml-2 font-normal">({findings.length})</span>
                </h3>
                
                <Accordion type="multiple" className="w-full space-y-2">
                  {findings.map((finding) => (
                    <AccordionItem key={finding.id} value={finding.id} className="border border-border/50 bg-card/20 px-4 rounded-none">
                      <AccordionTrigger className="hover:no-underline py-3">
                        <div className="flex items-center gap-3 text-left w-full pr-4">
                          {getStatusIcon(finding.status)}
                          <span className="font-mono text-sm flex-1">{finding.title}</span>
                          <Badge variant="outline" className={`${getSeverityColor(finding.severity)} ml-auto font-mono text-[10px]`}>
                            {finding.severity.toUpperCase()}
                          </Badge>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent className="text-sm font-mono text-muted-foreground space-y-4 pb-4">
                        <div className="p-3 bg-background border border-border/50">
                          {finding.description}
                        </div>
                        {finding.detail && (
                          <div>
                            <span className="text-primary">DETAIL:</span>
                            <pre className="mt-1 p-3 bg-background border border-border/50 overflow-x-auto text-xs whitespace-pre-wrap">
                              {finding.detail}
                            </pre>
                          </div>
                        )}
                        {finding.recommendation && (
                          <div>
                            <span className="text-primary">RECOMMENDATION:</span>
                            <div className="mt-1 p-3 bg-primary/5 border border-primary/20 text-primary/90">
                              {finding.recommendation}
                            </div>
                          </div>
                        )}
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                </Accordion>
              </div>
            ))}
          </div>
        </>
      ) : (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent className="py-8 text-center">
            <AlertTriangle className="w-10 h-10 text-destructive mx-auto mb-2" />
            <h2 className="font-mono font-bold text-destructive">SCAN FAILED</h2>
            <p className="font-mono text-sm text-muted-foreground mt-2">{scan.errorMessage || "Unknown error occurred"}</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'critical': return 'border-red-500 text-red-500';
    case 'high': return 'border-orange-500 text-orange-500';
    case 'medium': return 'border-yellow-500 text-yellow-500';
    case 'low': return 'border-blue-400 text-blue-400';
    case 'info': return 'border-gray-500 text-gray-500';
    default: return 'border-border text-foreground';
  }
}

function getStatusIcon(status: string) {
  switch (status) {
    case 'pass': return <CheckCircle2 className="w-4 h-4 text-green-500" />;
    case 'fail': return <XCircle className="w-4 h-4 text-red-500" />;
    case 'warning': return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
    case 'info': return <Info className="w-4 h-4 text-blue-400" />;
    default: return <Info className="w-4 h-4 text-muted-foreground" />;
  }
}

function getCategoryIcon(category: ScanFindingCategory) {
  switch (category) {
    case 'dns': return <Globe className="w-4 h-4 text-muted-foreground" />;
    case 'ssl': return <Lock className="w-4 h-4 text-muted-foreground" />;
    case 'server_info': return <Server className="w-4 h-4 text-muted-foreground" />;
    case 'headers': return <FileCode className="w-4 h-4 text-muted-foreground" />;
    default: return <Activity className="w-4 h-4 text-muted-foreground" />;
  }
}
