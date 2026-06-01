import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Link, useLocation } from "wouter";
import { formatDistanceToNow } from "date-fns";
import { 
  ShieldAlert, ShieldCheck, Activity, Target, Clock, 
  Trash2, AlertTriangle, ArrowRight, Loader2
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { 
  useListScans, 
  useCreateScan, 
  useDeleteScan, 
  useGetScanStats,
  getListScansQueryKey,
  getGetScanStatsQueryKey
} from "@workspace/api-client-react";

const scanFormSchema = z.object({
  url: z.string().url("Please enter a valid URL (e.g., https://example.com)"),
});

export default function Home() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: stats, isLoading: statsLoading } = useGetScanStats();
  const { data: scans, isLoading: scansLoading } = useListScans();
  
  const createScan = useCreateScan();
  const deleteScan = useDeleteScan();

  const form = useForm<z.infer<typeof scanFormSchema>>({
    resolver: zodResolver(scanFormSchema),
    defaultValues: {
      url: "",
    },
  });

  function onSubmit(values: z.infer<typeof scanFormSchema>) {
    createScan.mutate({ data: { url: values.url } }, {
      onSuccess: (data) => {
        toast({
          title: "Scan Initiated",
          description: `Target: ${values.url}`,
        });
        queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetScanStatsQueryKey() });
        setLocation(`/scans/${data.id}`);
      },
      onError: (error) => {
        toast({
          title: "Scan Failed",
          description: error.error || "An error occurred starting the scan",
          variant: "destructive",
        });
      }
    });
  }

  function handleDelete(e: React.MouseEvent, id: number) {
    e.preventDefault();
    e.stopPropagation();
    deleteScan.mutate({ id }, {
      onSuccess: () => {
        toast({
          title: "Scan Deleted",
          description: "The scan record has been removed.",
        });
        queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetScanStatsQueryKey() });
      }
    });
  }

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Target Input Section */}
      <section>
        <Card className="border-primary/20 bg-card/40 backdrop-blur">
          <CardContent className="pt-6">
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="flex gap-4 items-start">
                <FormField
                  control={form.control}
                  name="url"
                  render={({ field }) => (
                    <FormItem className="flex-1">
                      <div className="relative">
                        <Target className="absolute left-3 top-3 h-5 w-5 text-muted-foreground" />
                        <FormControl>
                          <Input 
                            placeholder="https://target-domain.com" 
                            className="pl-10 font-mono text-lg h-12 bg-background/50 focus-visible:ring-primary"
                            data-testid="input-target-url"
                            {...field} 
                          />
                        </FormControl>
                      </div>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button 
                  type="submit" 
                  size="lg"
                  className="h-12 px-8 font-mono font-bold"
                  disabled={createScan.isPending}
                  data-testid="button-start-scan"
                >
                  {createScan.isPending ? (
                    <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                  ) : (
                    <Activity className="mr-2 h-5 w-5" />
                  )}
                  INITIATE SCAN
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>
      </section>

      {/* Stats Section */}
      <section className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {statsLoading ? (
          Array(4).fill(0).map((_, i) => <Skeleton key={i} className="h-24" />)
        ) : (
          <>
            <StatCard 
              title="TOTAL SCANS" 
              value={stats?.totalScans ?? 0} 
              icon={<Activity className="h-4 w-4 text-primary" />} 
            />
            <StatCard 
              title="CRITICAL FINDINGS" 
              value={stats?.criticalFindings ?? 0} 
              valueClass="text-red-500"
              icon={<ShieldAlert className="h-4 w-4 text-red-500" />} 
            />
            <StatCard 
              title="HIGH FINDINGS" 
              value={stats?.highFindings ?? 0} 
              valueClass="text-orange-500"
              icon={<AlertTriangle className="h-4 w-4 text-orange-500" />} 
            />
            <StatCard 
              title="PASSED / SECURE" 
              value={stats?.completedScans ?? 0} 
              valueClass="text-blue-400"
              icon={<ShieldCheck className="h-4 w-4 text-blue-400" />} 
            />
          </>
        )}
      </section>

      {/* History Section */}
      <section>
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="font-mono text-sm tracking-wider text-muted-foreground flex items-center gap-2">
              <Clock className="w-4 h-4" />
              RECENT SCANS
            </CardTitle>
          </CardHeader>
          <CardContent>
            {scansLoading ? (
              <div className="space-y-2">
                {Array(3).fill(0).map((_, i) => <Skeleton key={i} className="h-12" />)}
              </div>
            ) : !scans || scans.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground font-mono text-sm">
                NO SCAN HISTORY FOUND
              </div>
            ) : (
              <div className="rounded-md border border-border/50">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="font-mono text-xs">TARGET</TableHead>
                      <TableHead className="font-mono text-xs w-[120px]">STATUS</TableHead>
                      <TableHead className="font-mono text-xs w-[200px]">FINDINGS</TableHead>
                      <TableHead className="font-mono text-xs w-[150px]">TIME</TableHead>
                      <TableHead className="w-[50px]"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scans.map((scan) => (
                      <TableRow 
                        key={scan.id}
                        className="cursor-pointer group hover:bg-muted/30"
                        onClick={() => setLocation(`/scans/${scan.id}`)}
                        data-testid={`row-scan-${scan.id}`}
                      >
                        <TableCell className="font-mono text-sm">
                          {scan.url}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={
                            scan.status === 'completed' ? 'border-primary text-primary' :
                            scan.status === 'failed' ? 'border-destructive text-destructive' :
                            'border-yellow-500 text-yellow-500 animate-pulse'
                          }>
                            {scan.status.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {scan.result?.summary ? (
                            <div className="flex gap-1">
                              {scan.result.summary.critical > 0 && <span className="text-red-500 font-mono text-xs">C:{scan.result.summary.critical}</span>}
                              {scan.result.summary.high > 0 && <span className="text-orange-500 font-mono text-xs">H:{scan.result.summary.high}</span>}
                              {scan.result.summary.medium > 0 && <span className="text-yellow-500 font-mono text-xs">M:{scan.result.summary.medium}</span>}
                              {scan.result.summary.critical === 0 && scan.result.summary.high === 0 && <span className="text-muted-foreground font-mono text-xs">CLEAN</span>}
                            </div>
                          ) : (
                            <span className="text-muted-foreground">-</span>
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs font-mono">
                          {formatDistanceToNow(new Date(scan.createdAt), { addSuffix: true })}
                        </TableCell>
                        <TableCell>
                          <Button 
                            variant="ghost" 
                            size="icon" 
                            className="opacity-0 group-hover:opacity-100 hover:text-destructive"
                            onClick={(e) => handleDelete(e, scan.id)}
                            data-testid={`button-delete-scan-${scan.id}`}
                          >
                            <Trash2 className="h-4 w-4" />
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

function StatCard({ title, value, icon, valueClass = "" }: { title: string, value: number, icon: React.ReactNode, valueClass?: string }) {
  return (
    <Card className="border-border/50 bg-card/40">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-xs font-mono font-medium text-muted-foreground">
          {title}
        </CardTitle>
        {icon}
      </CardHeader>
      <CardContent>
        <div className={`text-2xl font-mono font-bold ${valueClass}`}>{value}</div>
      </CardContent>
    </Card>
  );
}
