import { cn } from './utils';

interface AvatarProps {
  src?: string;
  fallback: string;
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl';
  online?: boolean;
  className?: string;
}

// Refined size classes with consistent scaling
const sizeConfig = {
  xs: { container: 'w-6 h-6', text: 'text-[10px]', indicator: 'w-1.5 h-1.5 border' },
  sm: { container: 'w-8 h-8', text: 'text-[11px]', indicator: 'w-2 h-2 border-[1.5px]' },
  md: { container: 'w-10 h-10', text: 'text-[13px]', indicator: 'w-2.5 h-2.5 border-2' },
  lg: { container: 'w-12 h-12', text: 'text-[15px]', indicator: 'w-3 h-3 border-2' },
  xl: { container: 'w-16 h-16', text: 'text-[18px]', indicator: 'w-3.5 h-3.5 border-2' },
};

// Signal Void color palette - warm, earthy, muted tones
const avatarColors = [
  { bg: 'bg-amber-700/80', text: 'text-amber-100' },      // Gold/ochre
  { bg: 'bg-emerald-800/80', text: 'text-emerald-100' },  // Verdigris
  { bg: 'bg-stone-600/80', text: 'text-stone-100' },      // Stone
  { bg: 'bg-rose-800/80', text: 'text-rose-100' },        // Terracotta
  { bg: 'bg-slate-600/80', text: 'text-slate-100' },      // Slate
  { bg: 'bg-orange-800/80', text: 'text-orange-100' },    // Rust
  { bg: 'bg-teal-800/80', text: 'text-teal-100' },        // Deep teal
  { bg: 'bg-zinc-600/80', text: 'text-zinc-100' },        // Charcoal
];

// Generate consistent color based on string
function getAvatarColor(str: string) {
  const hash = str.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
  return avatarColors[hash % avatarColors.length];
}

// Get initials from name
function getInitials(name: string): string {
  return name
    .split(' ')
    .map((s) => s[0])
    .join('')
    .toUpperCase()
    .slice(0, 2);
}

export function Avatar({ src, fallback, size = 'md', online, className }: AvatarProps) {
  const config = sizeConfig[size];
  const color = getAvatarColor(fallback);
  const initials = getInitials(fallback);

  return (
    <div className={cn('relative inline-flex flex-shrink-0', className)}>
      {src ? (
        <img
          src={src}
          alt={fallback}
          className={cn(
            'rounded-full object-cover',
            'ring-1 ring-[var(--color-border)]',
            config.container
          )}
        />
      ) : (
        <div
          className={cn(
            'rounded-full flex items-center justify-center',
            'font-semibold tracking-tight',
            'ring-1 ring-white/5',
            // Subtle inner shadow for depth
            'shadow-[inset_0_1px_2px_rgba(0,0,0,0.2)]',
            config.container,
            config.text,
            color.bg,
            color.text
          )}
        >
          {initials}
        </div>
      )}

      {/* Online indicator with warm glow */}
      {online !== undefined && (
        <span
          className={cn(
            'absolute bottom-0 right-0 rounded-full',
            'border-[var(--color-bg-secondary)]',
            config.indicator,
            online
              ? 'bg-[var(--color-success)] shadow-[0_0_6px_rgba(122,159,125,0.6)] animate-status-pulse'
              : 'bg-[var(--color-text-muted)]'
          )}
        />
      )}
    </div>
  );
}
