import { useState, useEffect } from 'react';
import { Lock, User, Key, Eye, EyeOff, Server, Settings } from 'lucide-react';
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
        // Registration flow with progress steps
        setCurrentStep('generating_keys');
        // Key generation happens in backend during register

        setCompletedSteps(['generating_keys']);
        setCurrentStep('connecting_mixnet');
        await api.connectToMixnet();

        setCompletedSteps(['generating_keys', 'connecting_mixnet']);
        setCurrentStep('registering');
        const user = await api.registerUser(username, passphrase);

        setCompletedSteps(['generating_keys', 'connecting_mixnet', 'registering']);
        setCurrentStep('initializing_mls');
        // MLS initialization happens in backend

        setCompletedSteps(['generating_keys', 'connecting_mixnet', 'registering', 'initializing_mls']);
        setAuthenticated(user);
      } else {
        // Login flow with progress steps
        setCurrentStep('loading_keys');
        // Key loading happens in backend during login

        setCompletedSteps(['loading_keys']);
        setCurrentStep('connecting_mixnet');
        await api.connectToMixnet();

        setCompletedSteps(['loading_keys', 'connecting_mixnet']);
        setCurrentStep('authenticating');
        const user = await api.loginUser(username, passphrase);

        setCompletedSteps(['loading_keys', 'connecting_mixnet', 'authenticating']);
        setCurrentStep('loading_conversations');
        // Conversation loading happens in the main app

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
    <div className="min-h-screen flex items-center justify-center bg-[var(--color-bg-primary)] p-4 relative overflow-hidden">
      {/* Ambient background glow */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-[var(--color-accent)]/5 rounded-full blur-[120px]" />
        <div className="absolute bottom-0 left-1/4 w-[400px] h-[400px] bg-purple-500/5 rounded-full blur-[100px]" />
      </div>

      <div className="w-full max-w-[380px] relative z-10">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="relative inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-[var(--color-accent)] to-blue-600 mb-4 shadow-[0_8px_32px_rgba(59,130,246,0.3)]">
            <Lock className="w-7 h-7 text-white" />
            <div className="absolute inset-0 rounded-2xl bg-gradient-to-t from-transparent to-white/10" />
          </div>
          <h1 className="text-[22px] font-semibold tracking-tight text-[var(--color-text-primary)]">Nymstr</h1>
          <p className="text-[13px] text-[var(--color-text-muted)] mt-1.5">
            Privacy-first messaging on the Nym mixnet
          </p>
        </div>

        {/* Settings toggle */}
        <button
          onClick={() => setShowSettings(!showSettings)}
          className={cn(
            'absolute -top-2 right-0 w-9 h-9 rounded-lg flex items-center justify-center',
            'text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]',
            'hover:bg-[var(--color-bg-hover)] transition-all duration-150',
            showSettings && 'bg-[var(--color-bg-hover)] text-[var(--color-text-secondary)]'
          )}
          title="Server Settings"
        >
          <Settings className="w-[18px] h-[18px]" />
        </button>

        {/* Server Settings Panel */}
        {showSettings && (
          <div className="bg-[var(--color-bg-secondary)] rounded-xl p-5 border border-[var(--color-border)] mb-4 shadow-[0_8px_32px_rgba(0,0,0,0.3)] animate-fade-in">
            <h3 className="text-[13px] font-medium mb-4 flex items-center gap-2 text-[var(--color-text-secondary)]">
              <Server className="w-4 h-4 text-[var(--color-accent)]" />
              Server Configuration
            </h3>
            <div className="space-y-3">
              <input
                type="text"
                placeholder="Nym server address (e.g., abc123...@gateway)"
                value={serverAddress}
                onChange={(e) => setServerAddressInput(e.target.value)}
                className="w-full h-11 px-4 rounded-lg text-[13px] font-mono input-base"
              />
              <Button
                type="button"
                onClick={handleSaveServerAddress}
                size="sm"
                className="w-full"
                variant={serverSaved ? 'secondary' : 'primary'}
              >
                {serverSaved ? 'Saved!' : 'Save Server Address'}
              </Button>
              <p className="text-[11px] text-[var(--color-text-muted)] leading-relaxed">
                This is the Nym address of the nymstr-server discovery node.
              </p>
            </div>
          </div>
        )}

        {/* Auth form */}
        <div className="bg-[var(--color-bg-secondary)] rounded-xl p-6 border border-[var(--color-border)] shadow-[0_8px_32px_rgba(0,0,0,0.3)]">
          {/* Segmented Tab Switcher */}
          <div className="flex p-1 mb-6 bg-[var(--color-bg-tertiary)] rounded-lg">
            <button
              onClick={() => setMode('login')}
              className={cn(
                'flex-1 py-2 text-[13px] font-medium text-center rounded-md transition-all duration-200',
                mode === 'login'
                  ? 'bg-[var(--color-bg-elevated)] text-[var(--color-text-primary)] shadow-sm'
                  : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]'
              )}
            >
              Login
            </button>
            <button
              onClick={() => setMode('register')}
              className={cn(
                'flex-1 py-2 text-[13px] font-medium text-center rounded-md transition-all duration-200',
                mode === 'register'
                  ? 'bg-[var(--color-bg-elevated)] text-[var(--color-text-primary)] shadow-sm'
                  : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]'
              )}
            >
              Register
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-3">
            {/* Username */}
            <div className="input-icon-wrapper">
              <User className="input-icon" />
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full h-11 pr-4 rounded-lg text-[14px] input-base input-with-icon"
                disabled={isLoading}
              />
            </div>

            {/* Passphrase */}
            <div className="input-icon-wrapper">
              <Key className="input-icon" />
              <input
                type={showPassphrase ? 'text' : 'password'}
                placeholder="Passphrase"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                className="w-full h-11 rounded-lg text-[14px] input-base input-with-icon input-with-icon-right"
                disabled={isLoading}
              />
              <button
                type="button"
                onClick={() => setShowPassphrase(!showPassphrase)}
                className="input-icon-right w-7 h-7 rounded-md flex items-center justify-center text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)] transition-all"
              >
                {showPassphrase ? (
                  <EyeOff className="w-4 h-4" />
                ) : (
                  <Eye className="w-4 h-4" />
                )}
              </button>
            </div>

            {/* Confirm Passphrase (register only) */}
            {mode === 'register' && (
              <div className="input-icon-wrapper animate-fade-in">
                <Key className="input-icon" />
                <input
                  type={showPassphrase ? 'text' : 'password'}
                  placeholder="Confirm Passphrase"
                  value={confirmPassphrase}
                  onChange={(e) => setConfirmPassphrase(e.target.value)}
                  className="w-full h-11 pr-4 rounded-lg text-[14px] input-base input-with-icon"
                  disabled={isLoading}
                />
              </div>
            )}

            {/* Progress stepper (shown during loading) */}
            {isLoading && currentStep && (
              <div className="py-3 px-1 rounded-lg bg-[var(--color-bg-tertiary)] animate-fade-in">
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
              <div className="flex items-start gap-2 p-3 rounded-lg bg-[var(--color-error)]/10 text-[var(--color-error)] text-[13px] animate-fade-in">
                <div className="w-4 h-4 mt-0.5 rounded-full bg-[var(--color-error)]/20 flex items-center justify-center flex-shrink-0">
                  <span className="text-[10px] font-bold">!</span>
                </div>
                <span>{error}</span>
              </div>
            )}

            {/* Submit button */}
            <div className="pt-2">
              <Button
                type="submit"
                className="w-full"
                size="md"
                loading={isLoading}
              >
                {isLoading
                  ? mode === 'login' ? 'Logging in...' : 'Creating account...'
                  : mode === 'login' ? 'Login' : 'Create Account'
                }
              </Button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
