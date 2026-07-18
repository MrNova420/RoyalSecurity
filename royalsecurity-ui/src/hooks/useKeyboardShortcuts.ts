import { useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';

type ShortcutCallback = () => void;

const NAV_SHORTCUTS: Record<string, string> = {
  'ctrl+shift+s': '/settings',
  'ctrl+shift+d': '/',
  'ctrl+shift+t': '/threats',
  'ctrl+shift+p': '/processes',
};

export function useKeyboardShortcuts() {
  const navigate = useNavigate();
  const customShortcutsRef = useRef<Map<string, ShortcutCallback>>(new Map());
  const refreshCallbackRef = useRef<ShortcutCallback | null>(null);
  const escapeCallbackRef = useRef<ShortcutCallback | null>(null);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const ctrl = e.ctrlKey || e.metaKey;
      const shift = e.shiftKey;
      const key = e.key.toLowerCase();

      if (ctrl && shift) {
        const combo = `ctrl+shift+${key}`;
        if (NAV_SHORTCUTS[combo]) {
          e.preventDefault();
          navigate(NAV_SHORTCUTS[combo]);
          return;
        }
      }

      if (ctrl && !shift && key === 'r') {
        e.preventDefault();
        refreshCallbackRef.current?.();
        return;
      }

      if (key === 'escape') {
        escapeCallbackRef.current?.();
        return;
      }

      const comboParts: string[] = [];
      if (ctrl) comboParts.push('ctrl');
      if (shift) comboParts.push('shift');
      if (e.altKey) comboParts.push('alt');
      comboParts.push(key);
      const combo = comboParts.join('+');
      const cb = customShortcutsRef.current.get(combo);
      if (cb) {
        e.preventDefault();
        cb();
      }
    };

    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [navigate]);

  const registerShortcut = useCallback((key: string, callback: ShortcutCallback) => {
    customShortcutsRef.current.set(key.toLowerCase(), callback);
    return () => {
      customShortcutsRef.current.delete(key.toLowerCase());
    };
  }, []);

  const setRefreshCallback = useCallback((cb: ShortcutCallback | null) => {
    refreshCallbackRef.current = cb;
  }, []);

  const setEscapeCallback = useCallback((cb: ShortcutCallback | null) => {
    escapeCallbackRef.current = cb;
  }, []);

  return { registerShortcut, setRefreshCallback, setEscapeCallback } as const;
}
