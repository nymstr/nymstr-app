import { Check } from 'lucide-react';
import { cn } from './utils';

interface Step {
  id: string;
  label: string;
}

interface ProgressStepperProps {
  steps: Step[];
  currentStep: string;
  completedSteps: string[];
  error?: string;
}

export function ProgressStepper({ steps, currentStep, completedSteps, error }: ProgressStepperProps) {
  return (
    <div className="space-y-1">
      {steps.map((step, index) => {
        const isCompleted = completedSteps.includes(step.id);
        const isCurrent = step.id === currentStep;
        const isError = isCurrent && error;
        const isPending = !isCompleted && !isCurrent;

        return (
          <div
            key={step.id}
            style={{ position: 'relative' }}
            className={cn(
              'flex items-center gap-3 py-2.5 px-3 rounded-lg transition-all duration-300',
              isCurrent && !isError && 'bg-[var(--color-accent-subtle)]',
              isError && 'bg-[var(--color-error)]/10'
            )}
          >
            {/* Step indicator - cipher/seal aesthetic */}
            <div className={cn(
              'relative w-7 h-7 rounded-full flex items-center justify-center text-[11px] font-mono font-semibold transition-all duration-400',
              isCompleted && 'bg-[var(--color-secondary)] text-[var(--color-text-primary)]',
              isError && 'bg-[var(--color-error)]/20 text-[var(--color-error)] border border-[var(--color-error)]/30',
              isCurrent && !isError && 'bg-[var(--color-accent)] text-[var(--color-bg-primary)] shadow-[var(--shadow-glow-sm)]',
              isPending && 'bg-[var(--color-bg-elevated)] text-[var(--color-text-faint)] border border-[var(--color-border)]'
            )}>
              {isCompleted ? (
                <Check className="w-3.5 h-3.5 animate-scale-in" strokeWidth={2.5} />
              ) : isCurrent && !isError ? (
                // Cipher-style spinning indicator
                <div className="relative w-4 h-4">
                  <div className="absolute inset-0 border border-current/30 rounded-full" />
                  <div className="absolute inset-0 border border-transparent border-t-current rounded-full animate-cipher-spin" />
                </div>
              ) : (
                <span className="tabular-nums">{String(index + 1).padStart(2, '0')}</span>
              )}
            </div>

            {/* Step label */}
            <span className={cn(
              'text-[12px] transition-all duration-300',
              isCurrent && !isError && 'text-[var(--color-text-primary)] font-medium',
              isError && 'text-[var(--color-error)] font-medium',
              isCompleted && 'text-[var(--color-text-muted)]',
              isPending && 'text-[var(--color-text-faint)]'
            )}>
              {step.label}
            </span>

            {/* Completed checkmark animation */}
            {isCompleted && (
              <span className="ml-auto text-[10px] text-[var(--color-secondary)] uppercase tracking-wider font-mono animate-fade-in">
                Done
              </span>
            )}

            {/* Connecting line with gradient */}
            {index < steps.length - 1 && (
              <div className={cn(
                'absolute left-[27px] top-[42px] w-px h-[calc(100%-8px)]',
                'transition-colors duration-400',
                isCompleted
                  ? 'bg-gradient-to-b from-[var(--color-secondary)] to-[var(--color-secondary)]/30'
                  : 'bg-[var(--color-border)]'
              )} />
            )}
          </div>
        );
      })}
    </div>
  );
}
