import { useCallback, useEffect, useRef, useState } from "react";
import { dispatch } from "./bridge";
import type { UpdateStatus } from "./types";

const CHECK_INTERVAL = 6 * 60 * 60 * 1000;

// Update metadata only: no account credentials, downloads or installation.
export function useUpdateCheck(enabled: boolean) {
  const [available, setAvailable] = useState<UpdateStatus | null>(null);
  const [checking, setChecking] = useState(false);
  const inflight = useRef<Promise<UpdateStatus> | null>(null);
  const lastAttempt = useRef<number | null>(null);
  const alive = useRef(true);
  const generation = useRef(0);

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; };
  }, []);

  const accept = useCallback((result: UpdateStatus) => {
    // An installation result supersedes any metadata check already in flight.
    generation.current++;
    if (alive.current) setAvailable(result.status === "available" ? result : null);
  }, []);

  const check = useCallback((): Promise<UpdateStatus> => {
    if (inflight.current) return inflight.current;
    lastAttempt.current = Date.now();
    const requestGeneration = generation.current;
    setChecking(true);
    const request = dispatch<UpdateStatus>("check_update").then((result) => {
      if (!result || !["available", "up_to_date", "unavailable"].includes(result.status) ||
          (result.status === "available" && !result.version?.trim())) {
        throw new Error("未能确认更新状态，请稍后重试。");
      }
      if (alive.current && generation.current === requestGeneration) {
        setAvailable(result.status === "available" ? result : null);
      }
      return result;
    }).finally(() => {
      inflight.current = null;
      if (alive.current) setChecking(false);
    });
    inflight.current = request;
    return request;
  }, []);

  useEffect(() => {
    if (!enabled) return;
    let timer: number;
    const automatic = () => {
      window.clearTimeout(timer);
      const visible = document.visibilityState !== "hidden";
      if (visible && (lastAttempt.current === null || Date.now() - lastAttempt.current >= CHECK_INTERVAL)) {
        // Offline or unavailable channels must never interrupt normal work.
        void check().catch(() => {});
      }
      const remaining = visible && lastAttempt.current !== null
        ? Math.max(1000, CHECK_INTERVAL - (Date.now() - lastAttempt.current))
        : CHECK_INTERVAL;
      timer = window.setTimeout(automatic, remaining);
    };
    timer = window.setTimeout(automatic, 5000);
    window.addEventListener("focus", automatic);
    document.addEventListener("visibilitychange", automatic);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("focus", automatic);
      document.removeEventListener("visibilitychange", automatic);
    };
  }, [enabled, check]);

  return { available, checking, check, accept };
}
