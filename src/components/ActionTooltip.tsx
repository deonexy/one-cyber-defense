import React, { useCallback, useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

export type TooltipSide = 'top' | 'bottom' | 'left' | 'right';

export interface ActionTooltipProps {
  label: string;
  description?: string;
  scope?: string;
  side?: TooltipSide;
  className?: string;
  disabled?: boolean;
  children: React.ReactNode;
}

interface TooltipCoords {
  top: number;
  left: number;
  placement: TooltipSide;
}

export const ActionTooltip: React.FC<ActionTooltipProps> = ({
  label,
  description,
  scope,
  side = 'top',
  className = 'inline-flex',
  disabled = false,
  children,
}) => {
  const triggerRef = useRef<HTMLSpanElement | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState<TooltipCoords | null>(null);
  const tooltipId = useId();

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const computePosition = useCallback(() => {
    const el = triggerRef.current;
    if (!el || typeof window === 'undefined') return;
    const rect = el.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const gap = 8;

    let placement: TooltipSide = side;
    if (side === 'top' && rect.top < 84) placement = 'bottom';
    if (side === 'bottom' && vh - rect.bottom < 84) placement = 'top';
    if (side === 'right' && vw - rect.right < 240) placement = 'left';
    if (side === 'left' && rect.left < 240) placement = 'right';

    let top = rect.top - gap;
    let left = rect.left + rect.width / 2;

    if (placement === 'bottom') {
      top = rect.bottom + gap;
      left = rect.left + rect.width / 2;
    } else if (placement === 'right') {
      top = rect.top + rect.height / 2;
      left = rect.right + gap;
    } else if (placement === 'left') {
      top = rect.top + rect.height / 2;
      left = rect.left - gap;
    }

    // Clamp horizontal center for top/bottom placements so tooltip stays inside viewport
    if (placement === 'top' || placement === 'bottom') {
      left = Math.max(140, Math.min(vw - 140, left));
    }

    setCoords({ top, left, placement });
  }, [side]);

  const showWithDelay = useCallback(
    (delayMs: number) => {
      if (disabled) return;
      clearTimer();
      timerRef.current = setTimeout(() => {
        computePosition();
        setOpen(true);
      }, delayMs);
    },
    [clearTimer, computePosition, disabled]
  );

  const hideTooltip = useCallback(() => {
    clearTimer();
    setOpen(false);
  }, [clearTimer]);

  useEffect(() => {
    if (!open) return;
    const handleDismiss = () => hideTooltip();
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') hideTooltip();
    };
    window.addEventListener('scroll', handleDismiss, true);
    window.addEventListener('resize', handleDismiss);
    window.addEventListener('keydown', handleKey);
    return () => {
      window.removeEventListener('scroll', handleDismiss, true);
      window.removeEventListener('resize', handleDismiss);
      window.removeEventListener('keydown', handleKey);
    };
  }, [open, hideTooltip]);

  useEffect(() => clearTimer, [clearTimer]);

  const transformClass =
    coords?.placement === 'bottom'
      ? '-translate-x-1/2'
      : coords?.placement === 'right'
      ? '-translate-y-1/2'
      : coords?.placement === 'left'
      ? '-translate-x-full -translate-y-1/2'
      : '-translate-x-1/2 -translate-y-full';

  return (
    <span
      ref={triggerRef}
      className={className}
      aria-describedby={open ? tooltipId : undefined}
      onMouseEnter={() => showWithDelay(110)}
      onMouseLeave={hideTooltip}
      onFocus={() => showWithDelay(40)}
      onBlur={hideTooltip}
      onClick={hideTooltip}
    >
      {children}
      {open &&
        coords &&
        typeof document !== 'undefined' &&
        createPortal(
          <div
            id={tooltipId}
            role="tooltip"
            style={{ top: coords.top, left: coords.left }}
            className={`fixed z-[90] pointer-events-none max-w-[260px] w-max bg-zinc-900 border border-zinc-700/90 rounded-md px-2.5 py-2 shadow-xl text-left ${transformClass}`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] font-semibold text-zinc-100 leading-tight">
                {label}
              </span>
              {scope && (
                <span className="font-mono text-[10px] text-emerald-400 shrink-0">
                  {scope}
                </span>
              )}
            </div>
            {description && (
              <p className="mt-1 text-[11px] text-zinc-400 leading-snug">
                {description}
              </p>
            )}
          </div>,
          document.body
        )}
    </span>
  );
};
