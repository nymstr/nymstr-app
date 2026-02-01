import { useState, useEffect, useRef } from 'react';
import { Wifi, WifiOff, Loader2, Copy, Check } from 'lucide-react';
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
    disconnected: { color: 'text-red-400', bgColor: 'bg-red-500', icon: WifiOff, text: 'Offline', pulse: false },
    connecting: { color: 'text-amber-400', bgColor: 'bg-amber-500', icon: Loader2, text: 'Connecting', pulse: true },
    connected: { color: 'text-emerald-400', bgColor: 'bg-emerald-500', icon: Wifi, text: 'Connected', pulse: false },
    reconnecting: { color: 'text-amber-400', bgColor: 'bg-amber-500', icon: Loader2, text: 'Reconnecting', pulse: true },
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
          'flex items-center gap-2 h-7 px-2.5 rounded-lg transition-all duration-150',
          'hover:bg-[var(--color-bg-hover)]',
          expanded && 'bg-[var(--color-bg-hover)]'
        )}
      >
        <span className={cn(
          'w-1.5 h-1.5 rounded-full',
          config.bgColor,
          config.pulse && 'animate-pulse'
        )} />
        <span className="text-[11px] text-[var(--color-text-muted)]">
          {config.text}
        </span>
      </button>

      {/* Expanded panel */}
      {expanded && (
        <div className="absolute top-full right-0 mt-2 w-72 p-4 rounded-xl bg-[var(--color-bg-elevated)] border border-[var(--color-border)] shadow-[0_8px_32px_rgba(0,0,0,0.3)] z-50 animate-fade-in">
          {/* Status header */}
          <div className="flex items-center gap-2.5 mb-4">
            <div className={cn(
              'w-8 h-8 rounded-lg flex items-center justify-center',
              status === 'connected' ? 'bg-emerald-500/10' :
              status === 'disconnected' ? 'bg-red-500/10' : 'bg-amber-500/10'
            )}>
              <Icon className={cn('w-4 h-4', config.color, config.pulse && 'animate-spin')} />
            </div>
            <div>
              <span className="text-[13px] font-medium text-[var(--color-text-primary)]">{config.text}</span>
              <span className="block text-[11px] text-[var(--color-text-muted)]">Nym Mixnet</span>
            </div>
          </div>

          {/* Addresses */}
          {mixnetAddress && (
            <div className="mb-3">
              <label className="text-[11px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider">Your Address</label>
              <div className="flex items-center gap-2 mt-1.5">
                <code className="flex-1 text-[11px] bg-[var(--color-bg-tertiary)] px-2.5 py-1.5 rounded-lg truncate font-mono text-[var(--color-text-secondary)]">
                  {mixnetAddress}
                </code>
                <button
                  onClick={copyAddress}
                  className="w-7 h-7 flex items-center justify-center rounded-md hover:bg-[var(--color-bg-hover)] transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-[var(--color-text-muted)]" />}
                </button>
              </div>
            </div>
          )}

          {serverAddress && (
            <div className="mb-4">
              <label className="text-[11px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider">Server</label>
              <code className="block text-[11px] bg-[var(--color-bg-tertiary)] px-2.5 py-1.5 rounded-lg mt-1.5 truncate font-mono text-[var(--color-text-secondary)]">
                {serverAddress}
              </code>
            </div>
          )}

          {/* Actions */}
          {status === 'connected' ? (
            <button
              onClick={handleDisconnect}
              className="w-full h-9 px-3 text-[13px] font-medium rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors"
            >
              Disconnect
            </button>
          ) : status === 'disconnected' ? (
            <button
              onClick={handleConnect}
              className="w-full h-9 px-3 text-[13px] font-medium rounded-lg bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] transition-colors"
            >
              Connect
            </button>
          ) : null}
        </div>
      )}
    </div>
  );
}
