'use client';

interface PasswordStrengthMeterProps {
  password: string;
}

interface StrengthResult {
  score: number; // 0-4
  label: string;
  color: string;
  checks: { label: string; passed: boolean }[];
}

const STRENGTH_LEVELS: Record<number, { label: string; color: string; textColor: string }> = {
  0: { label: 'Very Weak',   color: 'bg-red-500',    textColor: 'text-red-400' },
  1: { label: 'Very Weak',   color: 'bg-red-500',    textColor: 'text-red-400' },
  2: { label: 'Weak',        color: 'bg-orange-500', textColor: 'text-orange-400' },
  3: { label: 'Fair',        color: 'bg-yellow-500', textColor: 'text-yellow-400' },
  4: { label: 'Strong',      color: 'bg-blue-500',   textColor: 'text-blue-400' },
  5: { label: 'Very Strong', color: 'bg-green-500',  textColor: 'text-green-400' },
};

function getStrength(password: string): StrengthResult {
  const checks = [
    { label: 'At least 8 characters', passed: password.length >= 8 },
    { label: 'Uppercase letter', passed: /[A-Z]/.test(password) },
    { label: 'Lowercase letter', passed: /[a-z]/.test(password) },
    { label: 'Number', passed: /[0-9]/.test(password) },
    { label: 'Special character', passed: /[^A-Za-z0-9]/.test(password) },
  ];

  const score = checks.filter((c) => c.passed).length;
  const { label, color } = STRENGTH_LEVELS[score];

  return { score, label, color, checks };
}

export function PasswordStrengthMeter({ password }: PasswordStrengthMeterProps) {
  if (!password) return null;

  const { score, label, color, checks } = getStrength(password);
  const { textColor } = STRENGTH_LEVELS[score];
  const segments = 5;

  return (
    <div className="space-y-2 mt-1" aria-label="Password strength indicator" role="region">
      {/* Strength bar */}
      <div className="flex gap-1" aria-hidden="true">
        {Array.from({ length: segments }).map((_, i) => (
          <div
            key={i}
            className={`h-1.5 flex-1 rounded-full transition-colors duration-300 ${
              i < score ? color : 'bg-gray-700'
            }`}
          />
        ))}
      </div>

      {/* Label */}
      <div className="flex justify-between items-center">
        <span className="text-xs text-gray-400">Password strength</span>
        <span className={`text-xs font-medium ${textColor}`} aria-live="polite">
          {label}
        </span>
      </div>

      {/* Requirements checklist */}
      <ul className="space-y-1" aria-label="Password requirements">
        {checks.map((check) => (
          <li key={check.label} className="flex items-center gap-2 text-xs">
            <span
              className={`w-3.5 h-3.5 rounded-full flex items-center justify-center flex-shrink-0 ${
                check.passed ? 'bg-green-500' : 'bg-gray-700'
              }`}
              aria-hidden="true"
            >
              {check.passed && (
                <svg className="w-2 h-2 text-white" fill="currentColor" viewBox="0 0 12 12">
                  <path d="M10 3L5 8.5 2 5.5" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              )}
            </span>
            <span className={check.passed ? 'text-gray-300' : 'text-gray-500'}>
              {check.label}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
