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
  placeholder = 'Type a message...',
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
    <div className="flex-shrink-0 px-4 py-3 bg-[var(--color-bg-secondary)] border-t border-[var(--color-border)]">
      <div className="flex items-end gap-2">
        {/* Attachment button */}
        <button
          className={cn(
            'flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center',
            'text-[var(--color-text-muted)]',
            'hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-secondary)]',
            'transition-colors duration-150'
          )}
          title="Attach file"
        >
          <Paperclip className="w-[18px] h-[18px]" />
        </button>

        {/* Input container */}
        <div
          className={cn(
            'flex-1 flex items-end rounded-xl px-3 py-2 min-h-[40px]',
            'bg-[var(--color-bg-tertiary)]',
            'border border-[var(--color-border-subtle)]',
            'transition-all duration-150',
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
              'flex-shrink-0 ml-2 w-7 h-7 rounded-md flex items-center justify-center',
              'text-[var(--color-text-muted)]',
              'hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-secondary)]',
              'transition-colors duration-150'
            )}
            title="Emoji"
          >
            <Smile className="w-[18px] h-[18px]" />
          </button>
        </div>

        {/* Send button */}
        <button
          onClick={handleSend}
          disabled={!canSend}
          className={cn(
            'flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center',
            'transition-all duration-150',
            canSend
              ? 'bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] shadow-[0_0_12px_rgba(59,130,246,0.3)]'
              : 'bg-[var(--color-bg-tertiary)] text-[var(--color-text-muted)] cursor-not-allowed'
          )}
          title="Send message"
        >
          <Send className={cn(
            'w-[18px] h-[18px] transition-transform duration-150',
            canSend && '-translate-x-px -translate-y-px'
          )} />
        </button>
      </div>
    </div>
  );
}
