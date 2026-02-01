import { useState } from 'react';
import { Copy, Check, UserMinus, Shield, ShieldCheck, AlertTriangle } from 'lucide-react';
import { Avatar } from '../ui/Avatar';
import { Button } from '../ui/Button';
import { cn } from '../ui/utils';
import * as api from '../../services/api';
import { useChatStore } from '../../stores/chatStore';

interface ContactProfilePanelProps {
  username: string;
  publicKey?: string;
  online?: boolean;
  mlsEstablished?: boolean;
  onClose: () => void;
}

export function ContactProfilePanel({
  username,
  publicKey,
  online,
  mlsEstablished,
  onClose,
}: ContactProfilePanelProps) {
  const [copied, setCopied] = useState(false);
  const [showRemoveConfirm, setShowRemoveConfirm] = useState(false);
  const [isRemoving, setIsRemoving] = useState(false);

  const removeConversation = useChatStore((s) => s.removeConversation);
  const setActiveConversation = useChatStore((s) => s.setActiveConversation);

  const copyPublicKey = async () => {
    if (!publicKey) return;
    try {
      await navigator.clipboard.writeText(publicKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const handleRemoveContact = async () => {
    setIsRemoving(true);
    try {
      await api.removeContact(username);
      removeConversation(username);
      setActiveConversation(null);
      onClose();
    } catch (err) {
      console.error('Failed to remove contact:', err);
    } finally {
      setIsRemoving(false);
      setShowRemoveConfirm(false);
    }
  };

  const truncatedKey = publicKey
    ? `${publicKey.substring(0, 20)}...${publicKey.substring(publicKey.length - 20)}`
    : null;

  return (
    <div className="w-80 h-full bg-[var(--color-bg-secondary)] border-l border-[var(--color-border)] flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-[var(--color-border)]">
        <h3 className="font-semibold text-[var(--color-text-primary)]">Contact Info</h3>
      </div>

      {/* Profile */}
      <div className="flex-1 overflow-y-auto">
        <div className="p-6 flex flex-col items-center">
          {/* Large Avatar */}
          <Avatar fallback={username} size="lg" online={online} className="w-24 h-24 text-3xl mb-4" />

          {/* Username */}
          <h2 className="text-xl font-semibold text-[var(--color-text-primary)] mb-1">
            {username}
          </h2>

          {/* Online status */}
          <p className={cn(
            'text-sm mb-6',
            online ? 'text-[var(--color-success)]' : 'text-[var(--color-text-muted)]'
          )}>
            {online ? 'Online' : 'Offline'}
          </p>

          {/* MLS Status */}
          <div className={cn(
            'flex items-center gap-2 px-4 py-2 rounded-lg mb-6 w-full',
            mlsEstablished
              ? 'bg-[var(--color-success)]/10 text-[var(--color-success)]'
              : 'bg-[var(--color-warning)]/10 text-[var(--color-warning)]'
          )}>
            {mlsEstablished ? (
              <>
                <ShieldCheck className="w-5 h-5" />
                <span className="text-sm font-medium">End-to-end encrypted</span>
              </>
            ) : (
              <>
                <Shield className="w-5 h-5" />
                <span className="text-sm font-medium">Establishing encryption...</span>
              </>
            )}
          </div>

          {/* Public Key */}
          {publicKey && (
            <div className="w-full mb-6">
              <label className="block text-xs text-[var(--color-text-muted)] uppercase tracking-wide mb-2">
                Public Key
              </label>
              <div className="relative">
                <div className="p-3 rounded-lg bg-[var(--color-bg-tertiary)] font-mono text-xs text-[var(--color-text-secondary)] break-all">
                  {truncatedKey}
                </div>
                <button
                  onClick={copyPublicKey}
                  className="absolute top-2 right-2 p-1.5 rounded-md hover:bg-[var(--color-bg-hover)] transition-colors"
                  title="Copy full public key"
                >
                  {copied ? (
                    <Check className="w-4 h-4 text-[var(--color-success)]" />
                  ) : (
                    <Copy className="w-4 h-4 text-[var(--color-text-muted)]" />
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Actions */}
      <div className="p-4 border-t border-[var(--color-border)]">
        {showRemoveConfirm ? (
          <div className="space-y-3">
            <div className="flex items-start gap-2 p-3 rounded-lg bg-[var(--color-error)]/10">
              <AlertTriangle className="w-5 h-5 text-[var(--color-error)] flex-shrink-0 mt-0.5" />
              <p className="text-sm text-[var(--color-error)]">
                Remove {username} from contacts? This action cannot be undone.
              </p>
            </div>
            <div className="flex gap-2">
              <Button
                variant="secondary"
                className="flex-1"
                onClick={() => setShowRemoveConfirm(false)}
                disabled={isRemoving}
              >
                Cancel
              </Button>
              <Button
                variant="danger"
                className="flex-1"
                onClick={handleRemoveContact}
                disabled={isRemoving}
              >
                {isRemoving ? 'Removing...' : 'Remove'}
              </Button>
            </div>
          </div>
        ) : (
          <Button
            variant="ghost"
            className="w-full text-[var(--color-error)] hover:bg-[var(--color-error)]/10"
            onClick={() => setShowRemoveConfirm(true)}
          >
            <UserMinus className="w-4 h-4 mr-2" />
            Remove Contact
          </Button>
        )}
      </div>
    </div>
  );
}
