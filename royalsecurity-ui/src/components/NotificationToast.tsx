import { useEffect, useState } from 'react';
import { X } from 'lucide-react';
import type { AppNotification } from '../hooks/useNotifications';

const SEVERITY_STYLES: Record<string, { bg: string; border: string; bar: string; icon: string }> = {
  success: {
    bg: 'rgba(34,197,94,0.12)',
    border: '#22c55e',
    bar: '#22c55e',
    icon: '\u2713',
  },
  info: {
    bg: 'rgba(59,130,246,0.12)',
    border: '#3b82f6',
    bar: '#3b82f6',
    icon: '\u2139',
  },
  warning: {
    bg: 'rgba(234,179,8,0.12)',
    border: '#eab308',
    bar: '#eab308',
    icon: '\u26a0',
  },
  error: {
    bg: 'rgba(239,68,68,0.12)',
    border: '#ef4444',
    bar: '#ef4444',
    icon: '\u2717',
  },
};

interface ToastItemProps {
  notification: AppNotification;
  onDismiss: (id: string) => void;
}

function ToastItem({ notification, onDismiss }: ToastItemProps) {
  const [progress, setProgress] = useState(100);
  const [visible, setVisible] = useState(false);
  const style = SEVERITY_STYLES[notification.severity] ?? SEVERITY_STYLES.info;

  useEffect(() => {
    requestAnimationFrame(() => setVisible(true));
  }, []);

  useEffect(() => {
    if (notification.timeout === null) return;
    const start = Date.now();
    const duration = notification.timeout;
    const tick = () => {
      const elapsed = Date.now() - start;
      const pct = Math.max(0, 100 - (elapsed / duration) * 100);
      setProgress(pct);
      if (pct > 0) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [notification.timeout]);

  const handleDismiss = () => {
    setVisible(false);
    setTimeout(() => onDismiss(notification.id), 250);
  };

  return (
    <div
      style={{
        backgroundColor: style.bg,
        borderLeft: `3px solid ${style.border}`,
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateX(0)' : 'translateX(100%)',
        transition: 'opacity 0.25s ease, transform 0.25s ease',
      }}
      className="relative w-80 rounded-r-lg shadow-lg overflow-hidden"
    >
      <div className="flex items-start gap-2 p-3">
        <span className="text-sm mt-0.5" style={{ color: style.border }}>
          {style.icon}
        </span>
        <p className="flex-1 text-sm text-gray-200 leading-snug">{notification.message}</p>
        <button onClick={handleDismiss} className="text-gray-400 hover:text-gray-200 shrink-0">
          <X className="w-4 h-4" />
        </button>
      </div>
      {notification.timeout !== null && (
        <div className="h-0.5 w-full" style={{ backgroundColor: 'rgba(255,255,255,0.05)' }}>
          <div
            className="h-full"
            style={{
              width: `${progress}%`,
              backgroundColor: style.bar,
              transition: 'width 0.1s linear',
            }}
          />
        </div>
      )}
    </div>
  );
}

interface NotificationToastProps {
  notifications: AppNotification[];
  onDismiss: (id: string) => void;
}

export default function NotificationToast({ notifications, onDismiss }: NotificationToastProps) {
  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
      {notifications.map((n) => (
        <div key={n.id} className="pointer-events-auto">
          <ToastItem notification={n} onDismiss={onDismiss} />
        </div>
      ))}
    </div>
  );
}
