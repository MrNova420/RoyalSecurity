import { useEffect, useState, useCallback, useRef } from 'react';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

const MAX_EVENTS = 500;

export interface SecurityEvent {
  id: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  title: string;
  source: string;
  description: string;
  host: string;
  raw?: Record<string, unknown>;
}

export function useEventStream() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const unlistenRef = useRef<UnlistenFn | null>(null);
  const idCounterRef = useRef(0);

  useEffect(() => {
    let mounted = true;

    const setup = async () => {
      try {
        unlistenRef.current = await listen<Record<string, unknown>>('security-event', (payload) => {
          if (!mounted) return;

          idCounterRef.current += 1;
          const raw = payload.payload;
          const event: SecurityEvent = {
            id: String(idCounterRef.current),
            timestamp: (raw.timestamp as string) ?? new Date().toISOString(),
            severity: (raw.severity as SecurityEvent['severity']) ?? 'informational',
            title: (raw.title as string) ?? 'Unknown Event',
            source: (raw.source as string) ?? 'system',
            description: (raw.description as string) ?? '',
            host: (raw.host as string) ?? '',
            raw,
          };

          setEvents((prev) => {
            const next = [event, ...prev];
            return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next;
          });
        });

        if (mounted) setIsConnected(true);
      } catch {
        if (mounted) setIsConnected(false);
      }
    };

    setup();

    return () => {
      mounted = false;
      unlistenRef.current?.();
      setIsConnected(false);
    };
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
    idCounterRef.current = 0;
  }, []);

  const eventCount = events.length;

  return { events, clearEvents, isConnected, eventCount } as const;
}
