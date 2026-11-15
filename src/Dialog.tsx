import { useLayoutEffect, useRef, type ReactNode } from 'react';
import { X, WarningCircle } from '@phosphor-icons/react';

type Modal = { element: HTMLDivElement; scrim: HTMLDivElement; previous: HTMLElement | null };
const modals = new Set<Modal>();
const inertBefore = new Map<Element, string | null>();
const focusSelector = 'button, input, select, textarea, summary, a[href], [tabindex]';

function topModal() {
  return [...modals].filter(item => item.element.isConnected).sort((left, right) =>
    left.element.compareDocumentPosition(right.element) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1,
  ).at(-1);
}

function isAvailable(element: HTMLElement) {
  if (element.matches(':disabled') || element.tabIndex < 0) return false;
  for (let ancestor: HTMLElement | null = element; ancestor; ancestor = ancestor.parentElement) {
    if (ancestor.hidden || ancestor.hasAttribute('inert')) return false;
    const style = getComputedStyle(ancestor);
    if (style.display === 'none' || style.visibility === 'hidden') return false;
    if (ancestor instanceof HTMLDetailsElement && !ancestor.open) {
      const summary = ancestor.querySelector(':scope > summary');
      if (!summary?.contains(element)) return false;
    }
  }
  // Rectangles include fixed-position controls (whose offsetParent is null),
  // while excluding elements without a rendered box.
  return element.getClientRects().length > 0;
}

function focusable(element: HTMLElement) {
  return [...element.querySelectorAll<HTMLElement>(focusSelector)].filter(isAvailable);
}

function focusInitial(modal: Modal) {
  const items = focusable(modal.element);
  // React's autoFocus does not leave an attribute, so a field can opt in with data-autofocus.
  const first = items.find(item => item.hasAttribute('autofocus') || item.hasAttribute('data-autofocus'))
    || items.find(item => item.matches('input, select, textarea')) || items[0];
  (first || modal.element).focus();
}

// A dialog can be rendered inside an application root, not only in a portal.
// Inert each sibling along its path to body, preserving pre-existing attributes.
function syncInert() {
  for (const [element, previous] of inertBefore) {
    if (previous === null) element.removeAttribute('inert');
    else element.setAttribute('inert', previous);
  }
  inertBefore.clear();
  let branch: Element | null = topModal()?.scrim || null;
  while (branch?.parentElement) {
    const parent: HTMLElement = branch.parentElement;
    for (const sibling of parent.children) {
      if (sibling === branch) continue;
      inertBefore.set(sibling, sibling.getAttribute('inert'));
      sibling.setAttribute('inert', '');
    }
    if (parent === document.body) break;
    branch = parent;
  }
}

type Props = {
  title: string;
  eyebrow?: string;
  children: ReactNode;
  onClose: () => void;
  footer?: ReactNode;
  wide?: boolean;
  error?: string;
  errorAction?: ReactNode;
  status?: ReactNode;
  dismissDisabled?: boolean;
};

export default function Dialog({ title, children, onClose, footer, wide = false, error, errorAction, status, dismissDisabled = false }: Props) {
  const dialog = useRef<HTMLDivElement>(null);
  const scrim = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  const dismissDisabledRef = useRef(dismissDisabled);
  closeRef.current = onClose;
  dismissDisabledRef.current = dismissDisabled;

  useLayoutEffect(() => {
    const modal: Modal = { element: dialog.current!, scrim: scrim.current!, previous: document.activeElement as HTMLElement | null };
    modals.add(modal);
    syncInert();
    if (topModal() === modal) focusInitial(modal);

    const onKey = (event: KeyboardEvent) => {
      if (topModal() !== modal) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        if (!dismissDisabledRef.current) closeRef.current();
        return;
      }
      if (event.key !== 'Tab') return;
      const items = focusable(modal.element);
      const current = document.activeElement;
      if (!items.length) {
        event.preventDefault();
        modal.element.focus();
      } else if (!items.includes(current as HTMLElement)) {
        event.preventDefault();
        (event.shiftKey ? items.at(-1)! : items[0]).focus();
      } else if (event.shiftKey && current === items[0]) {
        event.preventDefault();
        items.at(-1)!.focus();
      } else if (!event.shiftKey && current === items.at(-1)) {
        event.preventDefault();
        items[0].focus();
      }
    };
    const onFocus = (event: FocusEvent) => {
      if (topModal() === modal && !modal.element.contains(event.target as Node)) modal.element.focus();
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('focusin', onFocus);
    // Newly mounted background controls must also remain inert.
    const observer = new MutationObserver(syncInert);
    observer.observe(document.body, { childList: true, subtree: true });
    return () => {
      const wasTop = topModal() === modal;
      observer.disconnect();
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('focusin', onFocus);
      modals.delete(modal);
      syncInert();
      if (!wasTop) return;
      const next = topModal();
      if (modal.previous?.isConnected && isAvailable(modal.previous)
        && (!next || next.element.contains(modal.previous))) modal.previous.focus();
      else if (next) focusInitial(next);
    };
  }, []);

  useLayoutEffect(() => {
    if (topModal()?.element !== dialog.current) return;
    const current = document.activeElement;
    if (!dialog.current?.contains(current) || (current instanceof HTMLElement && current.matches(':disabled'))) dialog.current?.focus();
  });

  return <div ref={scrim} className="dialog-scrim" onMouseDown={event => {
    if (!dismissDisabled && topModal()?.element === dialog.current && event.target === event.currentTarget) onClose();
  }}>
    <div className={`dialog ${wide ? 'dialog-wide' : ''}`} role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={dialog}>
      <div className="dialog-head"><div><h2>{title}</h2></div><button type="button" className="icon-button" onClick={onClose} aria-label="关闭" disabled={dismissDisabled}><X size={18} /></button></div>
      {(error || status) && <div className="dialog-status">{error && <div role="alert" className="dialog-error"><WarningCircle size={17} /><span>{error}</span>{errorAction}</div>}{status}</div>}
      <div className="dialog-body">{children}</div>
      {footer && <div className="dialog-footer">{footer}</div>}
    </div>
  </div>;
}
