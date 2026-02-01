import { useState, useEffect, useRef } from 'react';
import { Wifi, WifiOff, Copy, Check } from 'lucide-react';
import { cn } from './utils';
import { useConnectionStore } from '../../stores/connectionStore';
import * as api from '../../services/api';

export function ConnectionStatus() {
  const status = useConnectionStore((s) => s.status);
  const mixnetAddress = useConnectionStore((s) => s.mixnetAddress);
  const serverAddress = useConnectionStore((s) => s.serverAddress);
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);

  // Status indicator colors and icons
  const statusConfig: Record<string, { color: string; bgColor: string; icon: typeof Wifi; text: string; pulse?: boolean }> = {
    disconnected: { color: 'text-[var(--color-error)]', bgColor: 'bg-[var(--color-error)]', icon: WifiOff, text: 'Offline', pulse: false },
    connecting: { color: 'text-[var(--color-warning)]', bgColor: 'bg-[var(--color-warning)]', icon: Wifi, text: 'Connecting', pulse: true },
    connected: { color: 'text-[var(--color-success)]', bgColor: 'bg-[var(--color-success)]', icon: Wifi, text: 'Connected', pulse: false },
    reconnecting: { color: 'text-[var(--color-warning)]', bgColor: 'bg-[var(--color-warning)]', icon: Wifi, text: 'Reconnecting', pulse: true },
  };

  const config = statusConfig[status];
  const Icon = config.icon;

  // Close panel when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (panelRef.current && !panelRef.current.contains(event.target as Node)) {
        setExpanded(false);
      }
    }

    if (expanded) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [expanded]);

  const copyAddress = async () => {
    if (mixnetAddress) {
      await navigator.clipboard.writeText(mixnetAddress);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleConnect = async () => {
    try {
      useConnectionStore.getState().setConnecting();
      await api.connectToMixnet();
    } catch (error) {
      useConnectionStore.getState().setDisconnected(String(error));
    }
  };

  const handleDisconnect = async () => {
    try {
      await api.disconnectFromMixnet();
      useConnectionStore.getState().setDisconnected();
    } catch (error) {
      console.error('Disconnect failed:', error);
    }
  };

  return (
    <div className="relative" ref={panelRef}>
      {/* Compact indicator */}
      <button
        onClick={() => setExpanded(!expanded)}
        className={cn(
          'flex items-center gap-2 h-6 px-2 rounded-md transition-all duration-200',
          'hover:bg-[var(--color-bg-hover)]',
          expanded && 'bg-[var(--color-bg-hover)]'
        )}
      >
        <span className={cn(
          'w-1.5 h-1.5 rounded-full transition-all',
          config.bgColor,
          config.pulse && 'animate-status-pulse'
        )} />
        <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--color-text-muted)]">
          {config.text}
        </span>
      </button>

      {/* Expanded panel */}
      {expanded && (
        <div className="absolute top-full left-0 mt-2 w-80 p-5 rounded-xl bg-[var(--color-bg-elevated)] border border-[var(--color-border)] shadow-[var(--shadow-xl)] z-50 animate-scale-up">
          {/* Status header */}
          <div className="flex items-center gap-3 mb-5 pb-4 border-b border-[var(--color-border)]">
            <div className={cn(
              'w-10 h-10 rounded-lg flex items-center justify-center',
              status === 'connected' ? 'bg-[var(--color-success)]/10' :
              status === 'disconnected' ? 'bg-[var(--color-error)]/10' : 'bg-[var(--color-warning)]/10'
            )}>
              <Icon className={cn('w-5 h-5', config.color)} />
            </div>
            <div>
              <span className="text-[14px] font-medium text-[var(--color-text-primary)]">{config.text}</span>
              <span className="block text-[11px] text-[var(--color-text-muted)]">Nym Mixnet</span>
            </div>
            {status === 'connected' && (
              <span className="ml-auto encrypted-badge text-[9px]">
                Secure
              </span>
            )}
          </div>

          {/* Addresses */}
          {mixnetAddress && (
            <div className="mb-4">
              <label className="text-[10px] font-medium text-[var(--color-text-muted)] uppercase tracking-[0.15em] mb-2 block">
                Your Address
              </label>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-[11px] bg-[var(--color-bg-tertiary)] px-3 py-2 rounded-lg truncate font-mono text-[var(--color-text-secondary)] border border-[var(--color-border)]">
                  {mixnetAddress}
                </code>
                <button
                  onClick={copyAddress}
                  className={cn(
                    'w-8 h-8 flex items-center justify-center rounded-lg transition-all duration-200',
                    'hover:bg-[var(--color-bg-hover)]',
                    copied && 'bg-[var(--color-success)]/10'
                  )}
                >
                  {copied ? (
                    <Check className="w-4 h-4 text-[var(--color-success)] animate-scale-in" />
                  ) : (
                    <Copy className="w-4 h-4 text-[var(--color-text-muted)]" />
                  )}
                </button>
              </div>
            </div>
          )}

          {serverAddress && (
            <div className="mb-5">
              <label className="text-[10px] font-medium text-[var(--color-text-muted)] uppercase tracking-[0.15em] mb-2 block">
                Discovery Server
              </label>
              <code className="block text-[11px] bg-[var(--color-bg-tertiary)] px-3 py-2 rounded-lg truncate font-mono text-[var(--color-text-secondary)] border border-[var(--color-border)]">
                {serverAddress}
              </code>
            </div>
          )}

          {/* Actions */}
          {status === 'connected' ? (
            <button
              onClick={handleDisconnect}
              className="w-full h-10 px-4 text-[13px] font-medium rounded-lg bg-[var(--color-error)]/10 text-[var(--color-error)] hover:bg-[var(--color-error)]/20 border border-[var(--color-error)]/20 transition-all duration-200"
            >
              Disconnect
            </button>
          ) : status === 'disconnected' ? (
            <button
              onClick={handleConnect}
              className="w-full h-10 px-4 text-[13px] font-medium rounded-lg bg-[var(--color-accent)] text-[var(--color-bg-primary)] hover:bg-[var(--color-accent-hover)] hover:shadow-[var(--shadow-glow-sm)] transition-all duration-200"
            >
              Connect to Mixnet
            </button>
          ) : (
            <div className="flex items-center justify-center gap-2 h-10 text-[var(--color-text-muted)]">
              <div className="w-4 h-4 relative">
                <div className="absolute inset-0 border-2 border-current/20 rounded-full" />
                <div className="absolute inset-0 border-2 border-transparent border-t-current rounded-full animate-cipher-spin" />
              </div>
              <span className="text-[13px]">Establishing connection...</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
