import { Crosshair, AlertOctagon, Zap } from "lucide-react";
import { useLocation } from "wouter";
import { SCENARIO_MAP, AttackScenario } from "@/data/attack-scenarios";

interface AttackScenariosPanelProps {
  findingId: string;
  scanUrl: string;
  scanId?: number;
}

export function AttackScenariosPanel({ findingId, scanUrl, scanId }: AttackScenariosPanelProps) {
  const [, navigate] = useLocation();

  const scenarios =
    SCENARIO_MAP[findingId] ??
    (findingId.startsWith("sqli-") &&
     !["sqli-no-params", "sqli-not-detected"].includes(findingId)
      ? SCENARIO_MAP["sqli"]
      : undefined) ??
    (findingId.startsWith("sensitive-") && findingId !== "sensitive-files-none"
      ? SCENARIO_MAP["sensitive-file"]
      : undefined);
  if (!scenarios || scenarios.length === 0) return null;

  const handleLaunch = (scenario: AttackScenario) => {
    const params = new URLSearchParams({
      target: scanUrl,
      auto: "1",
      ...(scanId != null ? { returnTo: `/scans/${scanId}` } : {}),
    });
    navigate(`/exploit-playground/${encodeURIComponent(findingId)}/${encodeURIComponent(scenario.id)}?${params.toString()}`);
  };

  return (
    <div className="mt-4">
      <div className="flex items-center gap-2 mb-3">
        <Crosshair className="w-3.5 h-3.5 text-purple-500 dark:text-purple-400 shrink-0" />
        <div className="text-[10px] font-mono font-bold text-purple-500 dark:text-purple-400 uppercase tracking-widest">
          Real-World Attack Scenarios
        </div>
        <div className="h-px flex-1 bg-purple-500/25 dark:bg-purple-400/20" />
        <div className="text-[9px] font-mono text-purple-600/50 dark:text-purple-400/40 uppercase tracking-widest">
          Select a test case to execute
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
        {scenarios.map((scenario) => (
          <ScenarioCard
            key={scenario.id}
            scenario={scenario}
            onLaunch={() => handleLaunch(scenario)}
          />
        ))}
      </div>
    </div>
  );
}

function ScenarioCard({
  scenario,
  onLaunch,
}: {
  scenario: AttackScenario;
  onLaunch: () => void;
}) {
  const isCritical = scenario.objectiveSeverity === "critical";

  return (
    <div className="rounded-md border border-purple-500/20 bg-purple-500/5 hover:border-purple-500/40 hover:bg-purple-500/8 transition-all flex flex-col gap-0 overflow-hidden">
      {/* Card header */}
      <div className="px-3 pt-3 pb-2 flex items-start gap-2">
        <div className="flex-1 min-w-0">
          <div className="font-mono text-xs font-bold text-foreground leading-snug mb-1">
            {scenario.name}
          </div>
          <span
            className={`inline-flex items-center gap-1 text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border uppercase ${
              isCritical
                ? "bg-red-500/15 text-red-500 border-red-500/30"
                : "bg-orange-500/15 text-orange-500 border-orange-500/30"
            }`}
          >
            <AlertOctagon className="w-2.5 h-2.5" />
            {scenario.attackerObjective.split(" / ")[0]}
          </span>
        </div>
      </div>

      {/* Description */}
      <div className="px-3 pb-2">
        <p className="text-[11px] font-sans text-muted-foreground leading-relaxed">
          {scenario.description}
        </p>
      </div>

      {/* Technical how-it-works */}
      <div className="mx-3 mb-3 px-2 py-1.5 rounded bg-purple-950/40 dark:bg-purple-950/60 border border-purple-500/10 text-[10px] font-mono text-purple-300/70 dark:text-purple-300/60 leading-relaxed">
        <span className="text-purple-400 font-bold">Technique: </span>
        {scenario.howItWorks}
      </div>

      {/* Launch button */}
      <button
        type="button"
        onClick={onLaunch}
        className="mt-auto mx-3 mb-3 flex items-center justify-center gap-2 w-[calc(100%-1.5rem)] px-3 py-2 rounded bg-red-600/15 hover:bg-red-600/30 border border-red-500/40 hover:border-red-400/60 text-[11px] font-mono font-bold text-red-400 hover:text-red-300 transition-all active:scale-[0.98]"
      >
        <Zap className="w-3 h-3" />
        [ Exploit This → ]
      </button>
    </div>
  );
}
