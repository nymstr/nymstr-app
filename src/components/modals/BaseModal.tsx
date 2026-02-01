import { useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import { cn } from '../ui/utils';

interface BaseModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  className?: string;
}

export function BaseModal({ isOpen, onClose, title, children, className }: BaseModalProps) {
  const modalRef = useRef<HTMLDivElement>(null);

  // Close on escape key
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      document.addEventListener('keydown', handleEscape);
      return () => document.removeEventListener('keydown', handleEscape);
    }
  }, [isOpen, onClose]);

  // Close on click outside
  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) onClose();
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in"
      onClick={handleBackdropClick}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />

      {/* Modal */}
      <div
        ref={modalRef}
        className={cn(
          'relative w-full max-w-md',
          'bg-[var(--color-bg-secondary)]',
          'rounded-xl border border-[var(--color-border)]',
          'shadow-[0_16px_48px_rgba(0,0,0,0.4)]',
          'animate-scale-in',
          className
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between h-14 px-5 border-b border-[var(--color-border)]">
          <h2 className="text-[15px] font-semibold text-[var(--color-text-primary)]">{title}</h2>
          <button
            onClick={onClose}
            className="w-8 h-8 -mr-1 rounded-lg flex items-center justify-center text-[var(--color-text-muted)] hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-secondary)] transition-colors"
          >
            <X className="w-[18px] h-[18px]" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5">
          {children}
        </div>
      </div>
    </div>
  );
}
