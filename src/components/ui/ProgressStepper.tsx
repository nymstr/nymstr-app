import { Check, Loader2 } from 'lucide-react';
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
    <div className="space-y-2">
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
              'flex items-center gap-3 py-2 px-3 rounded-lg transition-all duration-200',
              isCurrent && 'bg-[var(--color-accent)]/10',
              isError && 'bg-[var(--color-error)]/10'
            )}
          >
            {/* Step indicator */}
            <div className={cn(
              'relative w-7 h-7 rounded-full flex items-center justify-center text-[12px] font-semibold transition-all duration-300',
              isCompleted && 'bg-emerald-500/20 text-emerald-400',
              isError && 'bg-[var(--color-error)]/20 text-[var(--color-error)]',
              isCurrent && !isError && 'bg-[var(--color-accent)] text-white shadow-[0_0_12px_rgba(59,130,246,0.4)]',
              isPending && 'bg-[var(--color-bg-elevated)] text-[var(--color-text-muted)]'
            )}>
              {isCompleted ? (
                <Check className="w-3.5 h-3.5" strokeWidth={3} />
              ) : isCurrent ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                index + 1
              )}
            </div>

            {/* Step label */}
            <span className={cn(
              'text-[13px] transition-colors duration-200',
              isCurrent && !isError && 'text-[var(--color-text-primary)] font-medium',
              isError && 'text-[var(--color-error)] font-medium',
              isCompleted && 'text-[var(--color-text-secondary)]',
              isPending && 'text-[var(--color-text-muted)]'
            )}>
              {step.label}
            </span>

            {/* Connecting line */}
            {index < steps.length - 1 && (
              <div className={cn(
                'absolute left-[27px] top-[38px] w-px h-[calc(100%-12px)]',
                isCompleted ? 'bg-emerald-500/30' : 'bg-[var(--color-border)]'
              )} />
            )}
          </div>
        );
      })}
    </div>
  );
}
