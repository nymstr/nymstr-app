import { useState, useEffect } from 'react';
import {
  User,
  Server,
  Shield,
  Info,
  Copy,
  Check,
  LogOut,
  RefreshCw,
  Trash2,
  ExternalLink,
  Wifi,
  WifiOff,
  Lock,
} from 'lucide-react';
import { BaseModal } from '../modals/BaseModal';
import { cn } from '../ui/utils';
import { useAuthStore } from '../../stores/authStore';
import { useConnectionStore } from '../../stores/connectionStore';
import { useToast } from '../../hooks/useToast';
import * as api from '../../services/api';

interface SettingsPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

export function SettingsPanel({ isOpen, onClose }: SettingsPanelProps) {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const connectionStatus = useConnectionStore((s) => s.status);
  const mixnetAddress = useConnectionStore((s) => s.mixnetAddress);
  const serverAddress = useConnectionStore((s) => s.serverAddress);
  const setServerAddressStore = useConnectionStore((s) => s.setServerAddress);

  const { success, error, info } = useToast();

  const [serverAddressInput, setServerAddressInput] = useState(serverAddress || '');
  const [isTestingConnection, setIsTestingConnection] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [isClearingData, setIsClearingData] = useState(false);

  // Load server address on mount
  useEffect(() => {
    const loadServerAddress = async () => {
      try {
        const address = await api.getServerAddress();
        if (address) {
          setServerAddressInput(address);
          setServerAddressStore(address);
        }
      } catch (e) {
        console.error('Failed to load server address:', e);
      }
    };
    if (isOpen) {
      loadServerAddress();
    }
  }, [isOpen, setServerAddressStore]);

  const handleCopy = async (value: string, field: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedField(field);
      success('Copied to clipboard');
      setTimeout(() => setCopiedField(null), 2000);
    } catch (e) {
      error('Failed to copy', 'Could not copy to clipboard');
    }
  };

  const truncateAddress = (address: string, length: number = 20) => {
    if (address.length <= length * 2 + 3) return address;
    return `${address.slice(0, length)}...${address.slice(-length)}`;
  };

  const handleSaveServerAddress = async () => {
    if (!serverAddressInput.trim()) {
      error('Invalid address', 'Please enter a server address');
      return;
    }

    try {
      await api.setServerAddress(serverAddressInput.trim());
      setServerAddressStore(serverAddressInput.trim());
      success('Server address saved');
    } catch (e) {
      error('Failed to save', String(e));
    }
  };

  const handleTestConnection = async () => {
    setIsTestingConnection(true);
    try {
      const status = await api.getConnectionStatus();
      if (status.connected) {
        success('Connection active', 'Mixnet connection is healthy');
      } else {
        info('Not connected', 'Mixnet is currently disconnected');
      }
    } catch (e) {
      error('Connection test failed', String(e));
    } finally {
      setIsTestingConnection(false);
    }
  };

  const handleLogout = async () => {
    try {
      await api.logout();
      logout();
      onClose();
      success('Logged out successfully');
    } catch (e) {
      error('Logout failed', String(e));
    }
  };

  const handleClearLocalData = async () => {
    if (!confirm('Are you sure you want to clear all local data? This action cannot be undone.')) {
      return;
    }

    setIsClearingData(true);
    try {
      // TODO: Implement clear local data API
      // await api.clearLocalData();
      info('Not implemented', 'Clear local data functionality coming soon');
    } catch (e) {
      error('Failed to clear data', String(e));
    } finally {
      setIsClearingData(false);
    }
  };

  const getConnectionStatusDisplay = () => {
    switch (connectionStatus) {
      case 'connected':
        return { text: 'Connected', color: 'text-[var(--color-success)]', Icon: Wifi };
      case 'connecting':
        return { text: 'Connecting...', color: 'text-[var(--color-warning)]', Icon: RefreshCw };
      case 'reconnecting':
        return { text: 'Reconnecting...', color: 'text-[var(--color-warning)]', Icon: RefreshCw };
      default:
        return { text: 'Disconnected', color: 'text-[var(--color-error)]', Icon: WifiOff };
    }
  };

  const connectionStatusDisplay = getConnectionStatusDisplay();

  return (
    <BaseModal isOpen={isOpen} onClose={onClose} title="Settings" className="max-w-lg">
      <div className="space-y-6 max-h-[70vh] overflow-y-auto pr-2 -mr-2">
        {/* Account Section */}
        <section>
          <div className="flex items-center gap-2 mb-4">
            <User className="w-5 h-5 text-[var(--color-accent)]" />
            <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
              Account
            </h3>
          </div>

          <div className="space-y-3 bg-[var(--color-bg-tertiary)] rounded-lg p-4">
            {/* Username */}
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-text-secondary)]">Username</span>
              <span className="font-medium">{user?.username || 'Not logged in'}</span>
            </div>

            {/* Display Name */}
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-text-secondary)]">Display Name</span>
              <span className="font-medium">{user?.displayName || user?.username || '-'}</span>
            </div>

            {/* Public Key */}
            {user?.publicKey && (
              <div className="flex items-center justify-between gap-2">
                <span className="text-[var(--color-text-secondary)]">Public Key</span>
                <div className="flex items-center gap-2">
                  <code className="text-xs font-mono bg-[var(--color-bg-secondary)] px-2 py-1 rounded">
                    {truncateAddress(user.publicKey, 12)}
                  </code>
                  <button
                    onClick={() => handleCopy(user.publicKey, 'publicKey')}
                    className="p-1.5 rounded hover:bg-[var(--color-bg-hover)] transition-colors"
                    title="Copy public key"
                  >
                    {copiedField === 'publicKey' ? (
                      <Check className="w-4 h-4 text-[var(--color-success)]" />
                    ) : (
                      <Copy className="w-4 h-4 text-[var(--color-text-muted)]" />
                    )}
                  </button>
                </div>
              </div>
            )}

            {/* Logout Button */}
            <button
              onClick={handleLogout}
              className="w-full mt-2 flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-[var(--color-error)]/10 text-[var(--color-error)] hover:bg-[var(--color-error)]/20 transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span>Log Out</span>
            </button>
          </div>
        </section>

        {/* Server Configuration Section */}
        <section>
          <div className="flex items-center gap-2 mb-4">
            <Server className="w-5 h-5 text-[var(--color-accent)]" />
            <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
              Server Configuration
            </h3>
          </div>

          <div className="space-y-3 bg-[var(--color-bg-tertiary)] rounded-lg p-4">
            {/* Server Address */}
            <div>
              <label className="block text-sm text-[var(--color-text-secondary)] mb-2">
                Discovery Server Address
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={serverAddressInput}
                  onChange={(e) => setServerAddressInput(e.target.value)}
                  placeholder="Enter Nym address..."
                  className="flex-1 px-3 py-2 rounded-lg bg-[var(--color-bg-secondary)] border border-[var(--color-border)] text-sm font-mono focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
                />
                <button
                  onClick={handleSaveServerAddress}
                  className="px-3 py-2 rounded-lg bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] transition-colors text-sm font-medium"
                >
                  Save
                </button>
              </div>
            </div>

            {/* Connection Status */}
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-text-secondary)]">Connection Status</span>
              <div className="flex items-center gap-2">
                <connectionStatusDisplay.Icon
                  className={cn(
                    'w-4 h-4',
                    connectionStatusDisplay.color,
                    connectionStatus === 'connecting' || connectionStatus === 'reconnecting'
                      ? 'animate-spin'
                      : ''
                  )}
                />
                <span className={connectionStatusDisplay.color}>{connectionStatusDisplay.text}</span>
              </div>
            </div>

            {/* Mixnet Address */}
            {mixnetAddress && (
              <div className="flex items-center justify-between gap-2">
                <span className="text-[var(--color-text-secondary)]">Mixnet Address</span>
                <div className="flex items-center gap-2">
                  <code className="text-xs font-mono bg-[var(--color-bg-secondary)] px-2 py-1 rounded">
                    {truncateAddress(mixnetAddress, 10)}
                  </code>
                  <button
                    onClick={() => handleCopy(mixnetAddress, 'mixnetAddress')}
                    className="p-1.5 rounded hover:bg-[var(--color-bg-hover)] transition-colors"
                    title="Copy mixnet address"
                  >
                    {copiedField === 'mixnetAddress' ? (
                      <Check className="w-4 h-4 text-[var(--color-success)]" />
                    ) : (
                      <Copy className="w-4 h-4 text-[var(--color-text-muted)]" />
                    )}
                  </button>
                </div>
              </div>
            )}

            {/* Test Connection Button */}
            <button
              onClick={handleTestConnection}
              disabled={isTestingConnection}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-[var(--color-bg-secondary)] hover:bg-[var(--color-bg-hover)] transition-colors disabled:opacity-50"
            >
              <RefreshCw className={cn('w-4 h-4', isTestingConnection && 'animate-spin')} />
              <span>{isTestingConnection ? 'Testing...' : 'Test Connection'}</span>
            </button>
          </div>
        </section>

        {/* Privacy Section */}
        <section>
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-5 h-5 text-[var(--color-accent)]" />
            <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
              Privacy & Security
            </h3>
          </div>

          <div className="space-y-3 bg-[var(--color-bg-tertiary)] rounded-lg p-4">
            {/* MLS Info */}
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-text-secondary)]">Encryption Protocol</span>
              <div className="flex items-center gap-2">
                <span className="encrypted-badge">
                  <Lock className="w-3 h-3" />
                  MLS (RFC 9420)
                </span>
              </div>
            </div>

            {/* End-to-End Encryption Status */}
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-text-secondary)]">End-to-End Encryption</span>
              <span className="text-[var(--color-success)] flex items-center gap-1">
                <Check className="w-4 h-4" />
                Enabled
              </span>
            </div>

            {/* Clear Local Data */}
            <button
              onClick={handleClearLocalData}
              disabled={isClearingData}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-[var(--color-error)]/10 text-[var(--color-error)] hover:bg-[var(--color-error)]/20 transition-colors disabled:opacity-50"
            >
              <Trash2 className={cn('w-4 h-4', isClearingData && 'animate-pulse')} />
              <span>{isClearingData ? 'Clearing...' : 'Clear Local Data'}</span>
            </button>
          </div>
        </section>

        {/* About Section */}
        <section>
          <div className="flex items-center gap-2 mb-4">
            <Info className="w-5 h-5 text-[var(--color-accent)]" />
            <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
              About
            </h3>
          </div>

          <div className="space-y-3 bg-[var(--color-bg-tertiary)] rounded-lg p-4">
            {/* Version */}
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-text-secondary)]">Version</span>
              <span className="font-mono text-sm">0.1.0-alpha</span>
            </div>

            {/* Nym Network */}
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-text-secondary)]">Network</span>
              <span>Nym Mainnet</span>
            </div>

            {/* Nym Website Link */}
            <a
              href="https://nymtech.net"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-[var(--color-bg-secondary)] hover:bg-[var(--color-bg-hover)] transition-colors text-[var(--color-accent)]"
            >
              <ExternalLink className="w-4 h-4" />
              <span>Visit Nym Network</span>
            </a>
          </div>
        </section>

        {/* Cipher Noir Signature */}
        <div className="text-center pt-4 border-t border-[var(--color-border)]">
          <p className="text-xs text-[var(--color-text-muted)] font-mono tracking-wider">
            CIPHER NOIR // PRIVACY FIRST
          </p>
        </div>
      </div>
    </BaseModal>
  );
}
