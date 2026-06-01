import { EventEmitter } from "events";

export type ScanProgressEvent =
  | { type: "phase"; message: string; pct: number }
  | { type: "target"; current: number; total: number; url: string; check: string }
  | { type: "finding"; severity: string; title: string }
  | { type: "done"; status: "completed" | "failed" | "not_running"; error?: string };

export type ProgressCallback = (event: ScanProgressEvent) => void;

class ScanEventRegistry {
  private readonly emitters = new Map<number, EventEmitter>();

  create(scanId: number): EventEmitter {
    const existing = this.emitters.get(scanId);
    if (existing) {
      existing.removeAllListeners();
    }
    const emitter = new EventEmitter();
    emitter.setMaxListeners(30);
    this.emitters.set(scanId, emitter);
    return emitter;
  }

  get(scanId: number): EventEmitter | undefined {
    return this.emitters.get(scanId);
  }

  delete(scanId: number): void {
    const emitter = this.emitters.get(scanId);
    if (emitter) {
      emitter.removeAllListeners();
      this.emitters.delete(scanId);
    }
  }
}

export const scanRegistry = new ScanEventRegistry();
