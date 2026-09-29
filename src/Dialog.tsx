import {useEffect,useRef,type ReactNode} from 'react';
import {X,WarningCircle} from '@phosphor-icons/react';
export default function Dialog({ title, children, onClose, footer, wide = false, error }: { title: string; eyebrow?: string; children: ReactNode; onClose: () => void; footer?: ReactNode; wide?: boolean; error?: string }) {
  const dialog = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  useEffect(() => { closeRef.current = onClose; }, [onClose]);
  useEffect(() => {
    const prior = document.activeElement as HTMLElement | null;
    const first = dialog.current?.querySelector<HTMLElement>('[autofocus]') || dialog.current?.querySelector<HTMLElement>('input:not([disabled]), select:not([disabled]), textarea:not([disabled])') || dialog.current?.querySelector<HTMLElement>('button:not([disabled]), summary, a[href]');
    first?.focus();
    const onKey = (event: KeyboardEvent) => {
      const visibleDialogs = document.querySelectorAll('[role="dialog"]');
      if (visibleDialogs[visibleDialogs.length - 1] !== dialog.current) return;
      if (event.key === 'Escape') closeRef.current();
      if (event.key !== 'Tab' || !dialog.current) return;
      const items = [...dialog.current.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, a[href], [tabindex="0"]')].filter(el => el.offsetParent !== null);
      if (!items.length) return;
      const firstItem = items[0], lastItem = items[items.length - 1];
      if (event.shiftKey && document.activeElement === firstItem) { event.preventDefault(); lastItem.focus(); }
      else if (!event.shiftKey && document.activeElement === lastItem) { event.preventDefault(); firstItem.focus(); }
    };
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('keydown', onKey); prior?.focus(); };
  }, []);
  return <div className="dialog-scrim" onMouseDown={e => { if (e.target === e.currentTarget) onClose(); }}><div className={`dialog ${wide ? 'dialog-wide' : ''}`} role="dialog" aria-modal="true" aria-label={title} ref={dialog}>
    <div className="dialog-head"><div><h2>{title}</h2></div><button type="button" className="icon-button" onClick={onClose} aria-label="关闭"><X size={18} /></button></div>
    <div className="dialog-body">{error && <div role="alert" className="dialog-error"><WarningCircle size={17} />{error}</div>}{children}</div>{footer && <div className="dialog-footer">{footer}</div>}
  </div></div>;
}
