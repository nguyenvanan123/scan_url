import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Link, useLocation } from "wouter";
import { formatDistanceToNow } from "date-fns";
import {
  ShieldAlert, ShieldCheck, Activity, Target, Clock,
  Trash2, AlertTriangle, Loader2, Scan, Globe2
} from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table, TableBody, TableCell,
  TableHead, TableHeader, TableRow,
} from "@/components/ui/table";

import {
  useListScans,
  useCreateScan,
  useDeleteScan,
  useGetScanStats,
  getListScansQueryKey,
  getGetScanStatsQueryKey,
} from "@workspace/api-client-react";

const scanFormSchema = z.object({
  url: z
    .string()
    .min(1, "URL is required")
    .refine(
      (v) => {
        try {
          const u = new URL(v);
          return u.protocol === "http:" || u.protocol === "https:";
        } catch { return false; }
      },
      "Enter a valid URL starting with http:// or https://"
    ),
});

export default function Home() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [crawlEnabled, setCrawlEnabled] = useState(false);

  const { data: stats, isLoading: statsLoading } = useGetScanStats();
  const { data: scans, isLoading: scansLoading } = useListScans();

  const createScan = useCreateScan();
  const deleteScan = useDeleteScan();

  const form = useForm<z.infer<typeof scanFormSchema>>({
    resolver: zodResolver(scanFormSchema),
    defaultValues: { url: "" },
  });

  function onSubmit(values: z.infer<typeof scanFormSchema>) {
    createScan.mutate({ data: { url: values.url, crawl_enabled: crawlEnabled } }, {
      onSuccess: (data) => {
        queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetScanStatsQueryKey() });
        setLocation(`/scans/${data.id}`);
      },
      onError: (error) => {
        toast({
          title: "Scan Failed to Start",
          description: (error as any).error ?? "An error occurred starting the scan",
          variant: "destructive",
        });
      },
    });
  }

  function handleDelete(e: React.MouseEvent, id: number) {
    e.preventDefault();
    e.stopPropagation();
    deleteScan.mutate({ id }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetScanStatsQueryKey() });
      },
    });
  }

  const isPending = createScan.isPending;

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Scan Input */}
      <section>
        <Card className="border-primary/20 bg-card shadow-sm">
          <CardContent className="pt-6 pb-6">
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="flex gap-3 items-start">
                <FormField
                  control={form.control}
                  name="url"
                  render={({ field }) => (
                    <FormItem className="flex-1">
                      <div className="relative">
                        <Target className="absolute left-3 top-3 h-5 w-5 text-muted-foreground pointer-events-none" />
                        <FormControl>
                          <Input
                            placeholder="https://example.com"
                            className="pl-10 font-mono h-11 bg-background focus-visible:ring-primary"
                            data-testid="input-target-url"
                            disabled={isPending}
                            {...field}
                          />
                        </FormControl>
                      </div>
                      <FormMessage className="font-mono text-xs" />
                    </FormItem>
                  )}
                />
                <ScanButton isPending={isPending} />
              </form>
            </Form>

            {/* Spider mode toggle */}
            <div className="mt-3 flex items-center gap-2">
              <button
                type="button"
                role="switch"
                aria-checked={crawlEnabled}
                onClick={() => setCrawlEnabled((v) => !v)}
                disabled={isPending}
                className={`relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${
                  crawlEnabled ? "bg-primary" : "bg-muted"
                }`}
              >
                <span
                  className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                    crawlEnabled ? "translate-x-4" : "translate-x-0"
                  }`}
                />
              </button>
              <div className="flex items-center gap-1.5">
                <Globe2 className={`h-3.5 w-3.5 ${crawlEnabled ? "text-primary" : "text-muted-foreground"}`} />
                <span className={`text-xs font-mono ${crawlEnabled ? "text-foreground" : "text-muted-foreground"}`}>
                  Spider Mode
                </span>
                {crawlEnabled && (
                  <span className="text-[10px] font-mono text-muted-foreground">
                    — crawls internal links first, then tests all discovered URLs for injection
                  </span>
                )}
              </div>
            </div>

            {/* Scanning progress indicator */}
            {isPending && (
              <div className="mt-4 space-y-2">
                <div className="h-1 bg-muted rounded-full overflow-hidden">
                  <div className="h-full w-1/3 bg-primary rounded-full scan-sweep" />
                </div>
                <p className="text-xs font-mono text-muted-foreground text-center">
                  {crawlEnabled
                    ? "Spidering site → discovering URLs → running injection checks…"
                    : "Initiating scan — you will be redirected automatically"}
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </section>

      {/* Stats */}
      <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {statsLoading ? (
          Array(4).fill(0).map((_, i) => <Skeleton key={i} className="h-24" />)
        ) : (
          <>
            <StatCard
              title="Total Scans"
              value={stats?.totalScans ?? 0}
              icon={<Activity className="h-4 w-4 text-primary" />}
            />
            <StatCard
              title="Critical"
              value={stats?.criticalFindings ?? 0}
              valueClass="text-red-500"
              icon={<ShieldAlert className="h-4 w-4 text-red-500" />}
            />
            <StatCard
              title="High"
              value={stats?.highFindings ?? 0}
              valueClass="text-orange-500"
              icon={<AlertTriangle className="h-4 w-4 text-orange-500" />}
            />
            <StatCard
              title="Passed"
              value={stats?.completedScans ?? 0}
              valueClass="text-green-600 dark:text-green-400"
              icon={<ShieldCheck className="h-4 w-4 text-green-500" />}
            />
          </>
        )}
      </section>

      {/* History */}
      <section>
        <Card className="border-border/60 shadow-sm">
          <CardHeader className="pb-3">
            <CardTitle className="font-mono text-xs tracking-widest text-muted-foreground uppercase flex items-center gap-2">
              <Clock className="w-4 h-4" />
              Scan History
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            {scansLoading ? (
              <div className="space-y-2">
                {Array(3).fill(0).map((_, i) => <Skeleton key={i} className="h-12" />)}
              </div>
            ) : !scans || scans.length === 0 ? (
              <div className="text-center py-10 text-muted-foreground font-mono text-sm">
                No scan history yet — enter a URL above to begin
              </div>
            ) : (
              <div className="rounded-md border border-border/50 overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent bg-muted/30">
                      <TableHead className="font-mono text-[11px] uppercase tracking-wider">Target</TableHead>
                      <TableHead className="font-mono text-[11px] uppercase tracking-wider w-28">Status</TableHead>
                      <TableHead className="font-mono text-[11px] uppercase tracking-wider w-48">Findings</TableHead>
                      <TableHead className="font-mono text-[11px] uppercase tracking-wider w-36">Time</TableHead>
                      <TableHead className="w-10" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scans.map((scan) => (
                      <TableRow
                        key={scan.id}
                        className="cursor-pointer group hover:bg-muted/30 transition-colors"
                        onClick={() => setLocation(`/scans/${scan.id}`)}
                        data-testid={`row-scan-${scan.id}`}
                      >
                        <TableCell className="font-mono text-sm max-w-xs truncate" title={scan.url}>
                          {scan.url}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={
                            scan.status === "completed" ? "border-primary text-primary text-[10px]" :
                            scan.status === "failed" ? "border-destructive text-destructive text-[10px]" :
                            "border-yellow-500 text-yellow-500 text-[10px] animate-pulse"
                          }>
                            {scan.status.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {scan.result?.summary ? (
                            <div className="flex gap-1.5 flex-wrap">
                              {scan.result.summary.critical > 0 && (
                                <span className="text-red-500 font-mono text-[11px] font-bold">C:{scan.result.summary.critical}</span>
                              )}
                              {scan.result.summary.high > 0 && (
                                <span className="text-orange-500 font-mono text-[11px] font-bold">H:{scan.result.summary.high}</span>
                              )}
                              {scan.result.summary.medium > 0 && (
                                <span className="text-yellow-500 font-mono text-[11px] font-bold">M:{scan.result.summary.medium}</span>
                              )}
                              {scan.result.summary.low > 0 && (
                                <span className="text-green-500 font-mono text-[11px] font-bold">L:{scan.result.summary.low}</span>
                              )}
                              {scan.result.summary.critical === 0 && scan.result.summary.high === 0 && scan.result.summary.medium === 0 && (
                                <span className="text-green-500 font-mono text-[11px]">Clean</span>
                              )}
                            </div>
                          ) : (
                            <span className="text-muted-foreground text-xs">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs font-mono">
                          {formatDistanceToNow(new Date(scan.createdAt), { addSuffix: true })}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="opacity-0 group-hover:opacity-100 hover:text-destructive h-7 w-7"
                            onClick={(e) => handleDelete(e, scan.id)}
                            data-testid={`button-delete-scan-${scan.id}`}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </section>
    </div>
  );
}

function ScanButton({ isPending }: { isPending: boolean }) {
  return (
    <Button
      type="submit"
      size="lg"
      className="h-11 px-6 font-mono font-bold relative overflow-hidden"
      disabled={isPending}
      data-testid="button-start-scan"
    >
      {isPending ? (
        <>
          <span className="absolute inset-0 bg-primary/20 animate-pulse rounded" />
          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          SCANNING
        </>
      ) : (
        <>
          <Scan className="mr-2 h-4 w-4" />
          SCAN
        </>
      )}
    </Button>
  );
}

function StatCard({
  title, value, icon, valueClass = "",
}: {
  title: string; value: number; icon: React.ReactNode; valueClass?: string;
}) {
  return (
    <Card className="border-border/50 bg-card/60 shadow-sm">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1 pt-4 px-4">
        <CardTitle className="text-[11px] font-mono font-medium text-muted-foreground uppercase tracking-wider">
          {title}
        </CardTitle>
        {icon}
      </CardHeader>
      <CardContent className="px-4 pb-4">
        <div className={`text-2xl font-mono font-bold ${valueClass}`}>{value}</div>
      </CardContent>
    </Card>
  );
}
