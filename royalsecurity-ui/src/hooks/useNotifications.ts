import { useState, useCallback, useRef, useEffect } from 'react';

export type NotificationSeverity = 'info' | 'warning' | 'error' | 'success';

export interface AppNotification {
  id: string;
  message: string;
  severity: NotificationSeverity;
  createdAt: number;
  timeout: number | null;
}

const TIMEOUTS: Record<NotificationSeverity, number | null> = {
  info: 5000,
  success: 5000,
  warning: 10_000,
  error: null,
};

const MAX_VISIBLE = 5;

let nextId = 0;

export function useNotifications() {
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const dismissNotification = useCallback((id: string) => {
    const timer = timersRef.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timersRef.current.delete(id);
    }
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  }, []);

  const addNotification = useCallback(
    (message: string, severity: NotificationSeverity = 'info', timeoutOverride?: number | null) => {
      nextId += 1;
      const id = `notif-${nextId}`;
      const timeout = timeoutOverride !== undefined ? timeoutOverride : TIMEOUTS[severity];

      const notif: AppNotification = {
        id,
        message,
        severity,
        createdAt: Date.now(),
        timeout,
      };

      setNotifications((prev) => {
        const next = [notif, ...prev];
        return next.length > MAX_VISIBLE ? next.slice(0, MAX_VISIBLE) : next;
      });

      if (timeout !== null) {
        const timer = setTimeout(() => {
          dismissNotification(id);
          timersRef.current.delete(id);
        }, timeout);
        timersRef.current.set(id, timer);
      }

      return id;
    },
    [dismissNotification]
  );

  const clearAll = useCallback(() => {
    timersRef.current.forEach((t) => clearTimeout(t));
    timersRef.current.clear();
    setNotifications([]);
  }, []);

  useEffect(() => {
    return () => {
      timersRef.current.forEach((t) => clearTimeout(t));
    };
  }, []);

  return { notifications, addNotification, dismissNotification, clearAll } as const;
}
