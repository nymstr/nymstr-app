import { useState, useEffect } from 'react';
import { User, Key, Eye, EyeOff, Server, Settings } from 'lucide-react';
import { Button } from '../ui/Button';
import { cn } from '../ui/utils';
import { ProgressStepper } from '../ui/ProgressStepper';
import * as api from '../../services/api';
import { useAuthStore } from '../../stores/authStore';
import { useConnectionStore } from '../../stores/connectionStore';

type AuthMode = 'login' | 'register';

// Define steps for registration and login flows
const REGISTER_STEPS = [
  { id: 'generating_keys', label: 'Generating encryption keys...' },
  { id: 'connecting_mixnet', label: 'Connecting to mixnet...' },
  { id: 'registering', label: 'Registering with server...' },
  { id: 'initializing_mls', label: 'Initializing secure messaging...' },
];

const LOGIN_STEPS = [
  { id: 'loading_keys', label: 'Loading encryption keys...' },
  { id: 'connecting_mixnet', label: 'Connecting to mixnet...' },
  { id: 'authenticating', label: 'Authenticating...' },
  { id: 'loading_conversations', label: 'Loading conversations...' },
];

// Custom Nymstr emblem - keyhole merged with signal waves
function NymstrEmblem({ className }: { className?: string }) {
  return (
    <div className={cn('relative', className)}>
      {/* Outer glow ring */}
      <div className="absolute inset-0 rounded-full bg-[var(--color-accent)]/20 blur-xl" />

      {/* Main emblem */}
      <svg
        viewBox="0 0 64 64"
        className="w-full h-full relative z-10"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        {/* Outer circle with texture */}
        <circle
          cx="32"
          cy="32"
          r="30"
          stroke="url(#emblem-gradient)"
          strokeWidth="2"
          fill="var(--color-bg-secondary)"
        />

        {/* Inner decorative ring */}
        <circle
          cx="32"
          cy="32"
          r="24"
          stroke="var(--color-border-strong)"
          strokeWidth="1"
          strokeDasharray="4 2"
          fill="none"
        />

        {/* Signal waves emanating from center */}
        <path
          d="M32 18 Q38 24 32 32 Q26 24 32 18"
          fill="var(--color-accent)"
          opacity="0.3"
        />
        <path
          d="M32 14 Q42 22 32 32 Q22 22 32 14"
          fill="none"
          stroke="var(--color-accent)"
          strokeWidth="1"
          opacity="0.5"
        />
        <path
          d="M32 10 Q46 20 32 32 Q18 20 32 10"
          fill="none"
          stroke="var(--color-accent)"
          strokeWidth="1"
          opacity="0.3"
        />

        {/* Keyhole shape */}
        <circle
          cx="32"
          cy="28"
          r="6"
          fill="var(--color-accent)"
        />
        <path
          d="M29 32 L29 44 Q29 46 32 46 Q35 46 35 44 L35 32"
          fill="var(--color-accent)"
        />

        {/* Gradient definition */}
        <defs>
          <linearGradient id="emblem-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="var(--color-accent)" />
            <stop offset="50%" stopColor="var(--color-accent)" stopOpacity="0.6" />
            <stop offset="100%" stopColor="var(--color-secondary)" />
          </linearGradient>
        </defs>
      </svg>
    </div>
  );
}

// Cipher wheel loader
function CipherLoader() {
  return (
    <div className="cipher-loader">
      <div className="outer" />
      <div className="inner" />
      <div className="center" />
    </div>
  );
}

export function AuthView() {
  const [mode, setMode] = useState<AuthMode>('login');
  const [username, setUsername] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [serverAddress, setServerAddressInput] = useState('');
  const [serverSaved, setServerSaved] = useState(false);

  // Progress tracking state
  const [currentStep, setCurrentStep] = useState<string>('');
  const [completedSteps, setCompletedSteps] = useState<string[]>([]);

  const setAuthenticated = useAuthStore((s) => s.setAuthenticated);
  const { setServerAddress: setStoreServerAddress } = useConnectionStore();

  // Load server address on mount
  useEffect(() => {
    api.getServerAddress().then((addr) => {
      if (addr) {
        setServerAddressInput(addr);
        setStoreServerAddress(addr);
      }
    });
  }, [setStoreServerAddress]);

  const handleSaveServerAddress = async () => {
    if (!serverAddress.trim()) {
      setError('Server address is required');
      return;
    }
    try {
      await api.setServerAddress(serverAddress.trim());
      setStoreServerAddress(serverAddress.trim());
      setServerSaved(true);
      setTimeout(() => setServerSaved(false), 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save server address');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setCompletedSteps([]);
    setCurrentStep('');

    if (!username.trim()) {
      setError('Username is required');
      return;
    }

    if (!passphrase) {
      setError('Passphrase is required');
      return;
    }

    if (mode === 'register' && passphrase !== confirmPassphrase) {
      setError('Passphrases do not match');
      return;
    }

    setIsLoading(true);

    try {
      if (mode === 'register') {
        setCurrentStep('generating_keys');

        setCompletedSteps(['generating_keys']);
        setCurrentStep('connecting_mixnet');
        await api.connectToMixnet();

        setCompletedSteps(['generating_keys', 'connecting_mixnet']);
        setCurrentStep('registering');
        const user = await api.registerUser(username, passphrase);

        setCompletedSteps(['generating_keys', 'connecting_mixnet', 'registering']);
        setCurrentStep('initializing_mls');

        setCompletedSteps(['generating_keys', 'connecting_mixnet', 'registering', 'initializing_mls']);
        setAuthenticated(user);
      } else {
        setCurrentStep('loading_keys');

        setCompletedSteps(['loading_keys']);
        setCurrentStep('connecting_mixnet');
        await api.connectToMixnet();

        setCompletedSteps(['loading_keys', 'connecting_mixnet']);
        setCurrentStep('authenticating');
        const user = await api.loginUser(username, passphrase);

        setCompletedSteps(['loading_keys', 'connecting_mixnet', 'authenticating']);
        setCurrentStep('loading_conversations');

        setCompletedSteps(['loading_keys', 'connecting_mixnet', 'authenticating', 'loading_conversations']);
        setAuthenticated(user);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[var(--color-bg-primary)] p-6 relative overflow-hidden vignette">
      {/* Subtle radial gradient background */}
      <div className="absolute inset-0 pointer-events-none">
        <div
          className="absolute inset-0"
          style={{
            background: 'radial-gradient(ellipse at 50% 30%, var(--color-bg-secondary) 0%, transparent 60%)'
          }}
        />
      </div>

      <div className="w-full max-w-[400px] relative z-10">
        {/* Header with emblem */}
        <div className="text-center mb-10 animate-fade-up">
          <NymstrEmblem className="w-20 h-20 mx-auto mb-6" />

          <h1 className="font-display text-[28px] font-medium tracking-tight text-[var(--color-text-primary)] mb-2">
            Nymstr
          </h1>
          <p className="text-[14px] text-[var(--color-text-muted)] leading-relaxed max-w-[280px] mx-auto">
            Private messaging through the void.
            <br />
            <span className="text-[var(--color-text-faint)]">Built on the Nym mixnet.</span>
          </p>
        </div>

        {/* Settings toggle */}
        <button
          onClick={() => setShowSettings(!showSettings)}
          className={cn(
            'absolute top-0 right-0 w-10 h-10 rounded-lg flex items-center justify-center',
            'text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]',
            'hover:bg-[var(--color-bg-hover)] transition-all duration-200',
            showSettings && 'bg-[var(--color-bg-hover)] text-[var(--color-accent)]'
          )}
          title="Server Settings"
        >
          <Settings className="w-[18px] h-[18px]" />
        </button>

        {/* Server Settings Panel */}
        {showSettings && (
          <div className="surface-paper p-5 mb-5 animate-scale-up">
            <h3 className="text-[12px] font-medium mb-4 flex items-center gap-2.5 text-[var(--color-text-secondary)] uppercase tracking-widest">
              <Server className="w-4 h-4 text-[var(--color-accent)]" />
              Server Configuration
            </h3>
            <div className="space-y-3">
              <input
                type="text"
                placeholder="Nym server address"
                value={serverAddress}
                onChange={(e) => setServerAddressInput(e.target.value)}
                className="w-full h-12 px-4 rounded-lg text-[13px] font-mono input-base"
              />
              <Button
                type="button"
                onClick={handleSaveServerAddress}
                size="sm"
                className="w-full"
                variant={serverSaved ? 'secondary' : 'primary'}
              >
                {serverSaved ? 'Saved' : 'Save Address'}
              </Button>
              <p className="text-[11px] text-[var(--color-text-muted)] leading-relaxed">
                The Nym address of your nymstr-server discovery node.
              </p>
            </div>
          </div>
        )}

        {/* Auth form card */}
        <div
          className="surface-paper p-7 animate-scale-up"
          style={{ animationDelay: '100ms' }}
        >
          {/* Mode switcher - editorial style */}
          <div className="flex items-center justify-center gap-6 mb-8">
            <button
              onClick={() => setMode('login')}
              className={cn(
                'relative text-[14px] font-medium py-2 transition-all duration-300',
                mode === 'login'
                  ? 'text-[var(--color-text-primary)]'
                  : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]'
              )}
            >
              Sign In
              {mode === 'login' && (
                <div className="absolute -bottom-1 left-0 right-0 h-[2px] bg-[var(--color-accent)] rounded-full" />
              )}
            </button>

            <div className="w-px h-5 bg-[var(--color-border)]" />

            <button
              onClick={() => setMode('register')}
              className={cn(
                'relative text-[14px] font-medium py-2 transition-all duration-300',
                mode === 'register'
                  ? 'text-[var(--color-text-primary)]'
                  : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]'
              )}
            >
              Create Account
              {mode === 'register' && (
                <div className="absolute -bottom-1 left-0 right-0 h-[2px] bg-[var(--color-accent)] rounded-full" />
              )}
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username field */}
            <div className="space-y-2">
              <label className="block text-[11px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider">
                Username
              </label>
              <div className="input-icon-wrapper">
                <User className="input-icon" />
                <input
                  type="text"
                  placeholder="Enter your identity"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full h-12 pr-4 rounded-lg text-[14px] input-base input-with-icon"
                  disabled={isLoading}
                  autoComplete="username"
                />
              </div>
            </div>

            {/* Passphrase field */}
            <div className="space-y-2">
              <label className="block text-[11px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider">
                Passphrase
              </label>
              <div className="input-icon-wrapper">
                <Key className="input-icon" />
                <input
                  type={showPassphrase ? 'text' : 'password'}
                  placeholder="Your secret key"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  className="w-full h-12 rounded-lg text-[14px] input-base input-with-icon input-with-icon-right"
                  disabled={isLoading}
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                />
                <button
                  type="button"
                  onClick={() => setShowPassphrase(!showPassphrase)}
                  className="input-icon-right w-8 h-8 rounded-md flex items-center justify-center text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)] transition-all"
                  tabIndex={-1}
                >
                  {showPassphrase ? (
                    <EyeOff className="w-4 h-4" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>

            {/* Confirm Passphrase (register only) */}
            {mode === 'register' && (
              <div className="space-y-2 animate-fade-up">
                <label className="block text-[11px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider">
                  Confirm Passphrase
                </label>
                <div className="input-icon-wrapper">
                  <Key className="input-icon" />
                  <input
                    type={showPassphrase ? 'text' : 'password'}
                    placeholder="Confirm your secret key"
                    value={confirmPassphrase}
                    onChange={(e) => setConfirmPassphrase(e.target.value)}
                    className="w-full h-12 pr-4 rounded-lg text-[14px] input-base input-with-icon"
                    disabled={isLoading}
                    autoComplete="new-password"
                  />
                </div>
              </div>
            )}

            {/* Progress stepper (shown during loading) */}
            {isLoading && currentStep && (
              <div className="py-4 px-4 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] animate-fade-in">
                <div className="flex items-center gap-4 mb-4">
                  <CipherLoader />
                  <div>
                    <p className="text-[13px] font-medium text-[var(--color-text-primary)]">
                      {mode === 'login' ? 'Establishing secure channel...' : 'Creating your identity...'}
                    </p>
                    <p className="text-[11px] text-[var(--color-text-muted)]">
                      This may take a moment
                    </p>
                  </div>
                </div>
                <ProgressStepper
                  steps={mode === 'register' ? REGISTER_STEPS : LOGIN_STEPS}
                  currentStep={currentStep}
                  completedSteps={completedSteps}
                  error={error || undefined}
                />
              </div>
            )}

            {/* Error message */}
            {error && !isLoading && (
              <div className="flex items-start gap-3 p-4 rounded-lg bg-[var(--color-error)]/10 border border-[var(--color-error)]/20 animate-fade-in">
                <div className="w-5 h-5 rounded-full bg-[var(--color-error)]/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-[11px] font-bold text-[var(--color-error)]">!</span>
                </div>
                <div>
                  <p className="text-[13px] font-medium text-[var(--color-error)]">
                    Authentication failed
                  </p>
                  <p className="text-[12px] text-[var(--color-error)]/80 mt-0.5">{error}</p>
                </div>
              </div>
            )}

            {/* Submit button */}
            <div className="pt-3">
              <Button
                type="submit"
                className="w-full h-12 text-[14px]"
                size="md"
                loading={isLoading}
              >
                {isLoading
                  ? mode === 'login' ? 'Connecting...' : 'Creating...'
                  : mode === 'login' ? 'Enter the Void' : 'Create Identity'
                }
              </Button>
            </div>
          </form>

          {/* Security note */}
          <div className="mt-6 pt-5 border-t border-[var(--color-border)]">
            <div className="flex items-center justify-center gap-2 text-[11px] text-[var(--color-text-muted)]">
              <span className="encrypted-badge">
                <svg className="w-3 h-3" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M8 1a4 4 0 0 0-4 4v2H3a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V8a1 1 0 0 0-1-1h-1V5a4 4 0 0 0-4-4zm2 6V5a2 2 0 1 0-4 0v2h4z"/>
                </svg>
                End-to-end encrypted
              </span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-[11px] text-[var(--color-text-faint)] mt-6 animate-fade-in" style={{ animationDelay: '200ms' }}>
          Your messages never touch our servers unencrypted.
        </p>
      </div>
    </div>
  );
}
