import { useState, useRef, useEffect } from 'react';
import { Send, Paperclip, Smile } from 'lucide-react';
import { cn } from '../ui/utils';

interface MessageInputProps {
  onSend: (content: string) => void;
  disabled?: boolean;
  placeholder?: string;
}

export function MessageInput({
  onSend,
  disabled = false,
  placeholder = 'Write a message...',
}: MessageInputProps) {
  const [message, setMessage] = useState('');
  const [isFocused, setIsFocused] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-resize textarea
  useEffect(() => {
    const textarea = textareaRef.current;
    if (textarea) {
      textarea.style.height = 'auto';
      textarea.style.height = `${Math.min(textarea.scrollHeight, 120)}px`;
    }
  }, [message]);

  const handleSend = () => {
    if (message.trim() && !disabled) {
      onSend(message.trim());
      setMessage('');
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const canSend = message.trim() && !disabled;

  return (
    <div className="flex-shrink-0 px-5 py-4 bg-[var(--color-bg-secondary)] border-t border-[var(--color-border)]">
      <div className="flex items-end gap-2.5">
        {/* Attachment button */}
        <button
          className={cn(
            'flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center',
            'text-[var(--color-text-muted)]',
            'hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-secondary)]',
            'transition-all duration-150'
          )}
          title="Attach file"
        >
          <Paperclip className="w-[18px] h-[18px]" />
        </button>

        {/* Input container */}
        <div
          className={cn(
            'flex-1 flex items-end rounded-xl px-4 py-2.5 min-h-[44px]',
            'bg-[var(--color-bg-tertiary)]',
            'border border-[var(--color-border)]',
            'transition-all duration-200',
            isFocused && 'border-[var(--color-accent)] shadow-[0_0_0_3px_var(--color-accent-muted)]'
          )}
        >
          <textarea
            ref={textareaRef}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            onFocus={() => setIsFocused(true)}
            onBlur={() => setIsFocused(false)}
            placeholder={placeholder}
            disabled={disabled}
            rows={1}
            className={cn(
              'flex-1 bg-transparent resize-none py-0.5',
              'text-[14px] leading-relaxed',
              'text-[var(--color-text-primary)]',
              'placeholder:text-[var(--color-text-muted)]',
              'focus:outline-none',
              'max-h-[120px]',
              disabled && 'opacity-50 cursor-not-allowed'
            )}
          />
          <button
            className={cn(
              'flex-shrink-0 ml-2 w-8 h-8 rounded-md flex items-center justify-center',
              'text-[var(--color-text-muted)]',
              'hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-secondary)]',
              'transition-all duration-150'
            )}
            title="Emoji"
          >
            <Smile className="w-[18px] h-[18px]" />
          </button>
        </div>

        {/* Send button - Seal/wax stamp aesthetic */}
        <button
          onClick={handleSend}
          disabled={!canSend}
          className={cn(
            'flex-shrink-0 w-10 h-10 rounded-xl flex items-center justify-center',
            'transition-all duration-200 relative overflow-hidden btn-ripple',
            canSend
              ? 'bg-[var(--color-accent)] text-[var(--color-bg-primary)] shadow-[var(--shadow-glow-sm)] hover:shadow-[var(--shadow-glow)]'
              : 'bg-[var(--color-bg-tertiary)] text-[var(--color-text-muted)] cursor-not-allowed'
          )}
          title="Send message"
        >
          {/* Subtle gradient overlay */}
          {canSend && (
            <div className="absolute inset-0 bg-gradient-to-b from-white/10 to-transparent pointer-events-none" />
          )}
          <Send className={cn(
            'w-[18px] h-[18px] relative z-10 transition-transform duration-200',
            canSend && '-translate-x-0.5 -translate-y-0.5'
          )} />
        </button>
      </div>

      {/* Encryption indicator */}
      <div className="flex items-center justify-center mt-2">
        <span className="text-[10px] text-[var(--color-text-faint)] flex items-center gap-1.5">
          <svg className="w-3 h-3" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 1a4 4 0 0 0-4 4v2H3a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V8a1 1 0 0 0-1-1h-1V5a4 4 0 0 0-4-4zm2 6V5a2 2 0 1 0-4 0v2h4z"/>
          </svg>
          Messages are end-to-end encrypted
        </span>
      </div>
    </div>
  );
}
