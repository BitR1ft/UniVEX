'use client';

import { useState } from 'react';
import { useForm, FormProvider } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { campaignSchema, type CampaignFormData } from '@/lib/validations';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import {
  CheckCircle,
  Circle,
  ChevronRight,
  ChevronLeft,
  Rocket,
  Settings2,
  Target,
  FileText,
  Clock,
} from 'lucide-react';

interface CampaignWizardProps {
  onSubmit: (data: CampaignFormData) => void;
  isLoading?: boolean;
  error?: string;
}

const WIZARD_STEPS = [
  { id: 1, title: 'Details', description: 'Name and description', icon: FileText },
  { id: 2, title: 'Targets', description: 'Scope and concurrency', icon: Target },
  { id: 3, title: 'Config', description: 'Scan profile and timing', icon: Settings2 },
  { id: 4, title: 'Schedule', description: 'Launch options', icon: Clock },
  { id: 5, title: 'Review', description: 'Confirm and launch', icon: Rocket },
];

const SCAN_PROFILE_INFO: Record<string, { label: string; description: string; color: string }> = {
  quick: {
    label: 'Quick',
    description: 'Fast surface-level scan, ~15 min per target',
    color: 'text-green-400',
  },
  standard: {
    label: 'Standard',
    description: 'Balanced depth and speed, ~45 min per target',
    color: 'text-blue-400',
  },
  thorough: {
    label: 'Thorough',
    description: 'Deep comprehensive scan, ~2h per target',
    color: 'text-yellow-400',
  },
  stealth: {
    label: 'Stealth',
    description: 'Low-noise evasion mode, ~3h per target',
    color: 'text-purple-400',
  },
};

function StepIndicator({ currentStep }: { currentStep: number }) {
  return (
    <nav aria-label="Wizard steps" className="mb-8">
      <ol className="flex items-center justify-between">
        {WIZARD_STEPS.map((step, idx) => {
          const isCompleted = currentStep > step.id;
          const isCurrent = currentStep === step.id;
          const Icon = step.icon;
          return (
            <li key={step.id} className="flex items-center flex-1" aria-current={isCurrent ? 'step' : undefined}>
              <div className="flex flex-col items-center flex-1">
                <div
                  className={`w-9 h-9 rounded-full flex items-center justify-center border-2 transition-colors ${
                    isCompleted
                      ? 'bg-green-600 border-green-600 text-white'
                      : isCurrent
                      ? 'bg-blue-600 border-blue-600 text-white'
                      : 'bg-gray-800 border-gray-600 text-gray-500'
                  }`}
                >
                  {isCompleted ? (
                    <CheckCircle className="w-5 h-5" />
                  ) : isCurrent ? (
                    <Icon className="w-4 h-4" />
                  ) : (
                    <Circle className="w-4 h-4" />
                  )}
                </div>
                <div className="mt-1.5 text-center hidden sm:block">
                  <p className={`text-xs font-medium ${isCurrent ? 'text-white' : isCompleted ? 'text-green-400' : 'text-gray-500'}`}>
                    {step.title}
                  </p>
                </div>
              </div>
              {idx < WIZARD_STEPS.length - 1 && (
                <div
                  className={`flex-1 h-0.5 mx-2 transition-colors ${
                    currentStep > step.id ? 'bg-green-600' : 'bg-gray-700'
                  }`}
                />
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

// ---------------------------------------------------------------------------
// Step 1: Campaign Details
// ---------------------------------------------------------------------------
function StepDetails({ methods }: { methods: ReturnType<typeof useForm<CampaignFormData>> }) {
  const { register, formState: { errors } } = methods;
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-white mb-1">Campaign Details</h2>
        <p className="text-sm text-gray-400">Provide a name and description for this pentest campaign.</p>
      </div>
      <div className="space-y-4">
        <div>
          <Label htmlFor="name">Campaign Name *</Label>
          <Input
            id="name"
            {...register('name')}
            placeholder="Q1 2026 Web Application Assessment"
            className="mt-1"
          />
          {errors.name && <p className="text-red-400 text-sm mt-1">{errors.name.message}</p>}
        </div>
        <div>
          <Label htmlFor="description">Description</Label>
          <Textarea
            id="description"
            {...register('description')}
            placeholder="Describe the scope, objectives, and engagement context..."
            rows={4}
            className="mt-1"
          />
          {errors.description && (
            <p className="text-red-400 text-sm mt-1">{errors.description.message}</p>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 2: Target Configuration
// ---------------------------------------------------------------------------
function StepTargets({ methods }: { methods: ReturnType<typeof useForm<CampaignFormData>> }) {
  const { register, watch, setValue, formState: { errors } } = methods;
  const concurrent = watch('config.max_concurrent_targets') ?? 3;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-white mb-1">Target Scope</h2>
        <p className="text-sm text-gray-400">Configure how targets will be scanned concurrently.</p>
      </div>
      <div className="space-y-4">
        <div>
          <Label>Concurrent Targets: <span className="text-blue-400 font-bold">{concurrent}</span></Label>
          <input
            type="range"
            min={1}
            max={20}
            step={1}
            value={concurrent}
            onChange={(e) => setValue('config.max_concurrent_targets', Number(e.target.value))}
            className="w-full mt-2 accent-blue-500"
          />
          <div className="flex justify-between text-xs text-gray-500 mt-1">
            <span>1 (sequential)</span><span>20 (max parallel)</span>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label htmlFor="scan_timeout_seconds">Scan Timeout (seconds)</Label>
            <Input
              id="scan_timeout_seconds"
              type="number"
              min={60}
              max={86400}
              {...register('config.scan_timeout_seconds', { valueAsNumber: true })}
              className="mt-1"
            />
          </div>
          <div>
            <Label htmlFor="max_retries">Max Retries</Label>
            <Input
              id="max_retries"
              type="number"
              min={0}
              max={5}
              {...register('config.max_retries', { valueAsNumber: true })}
              className="mt-1"
            />
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Checkbox
            id="retry_failed"
            checked={watch('config.retry_failed_targets') ?? true}
            onChange={(e) => setValue('config.retry_failed_targets', e.target.checked)}
          />
          <Label htmlFor="retry_failed" className="cursor-pointer">Retry failed targets automatically</Label>
        </div>
        <div className="flex items-center gap-3">
          <Checkbox
            id="enable_correlation"
            checked={watch('config.enable_correlation') ?? true}
            onChange={(e) => setValue('config.enable_correlation', e.target.checked)}
          />
          <Label htmlFor="enable_correlation" className="cursor-pointer">Enable cross-target correlation analysis</Label>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 3: Scan Config
// ---------------------------------------------------------------------------
function StepConfig({ methods }: { methods: ReturnType<typeof useForm<CampaignFormData>> }) {
  const { watch, setValue } = methods;
  const selected = watch('config.scan_profile') ?? 'standard';
  const rps = watch('config.rate_limit_rps') ?? 10;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-white mb-1">Scan Profile</h2>
        <p className="text-sm text-gray-400">Choose the scan depth and intensity.</p>
      </div>
      <div className="grid grid-cols-2 gap-3">
        {Object.entries(SCAN_PROFILE_INFO).map(([key, info]) => (
          <button
            key={key}
            type="button"
            onClick={() => setValue('config.scan_profile', key as 'quick' | 'standard' | 'thorough' | 'stealth')}
            className={`p-4 rounded-lg border text-left transition-colors ${
              selected === key
                ? 'border-blue-500 bg-blue-600/20'
                : 'border-gray-700 bg-gray-800 hover:border-gray-600'
            }`}
          >
            <p className={`text-sm font-semibold ${info.color}`}>{info.label}</p>
            <p className="text-xs text-gray-400 mt-1">{info.description}</p>
          </button>
        ))}
      </div>
      <div>
        <Label>Rate Limit: <span className="text-blue-400 font-bold">{rps} req/s</span></Label>
        <input
          type="range"
          min={0.1}
          max={100}
          step={0.5}
          value={rps}
          onChange={(e) => setValue('config.rate_limit_rps', parseFloat(e.target.value))}
          className="w-full mt-2 accent-blue-500"
        />
        <div className="flex justify-between text-xs text-gray-500 mt-1">
          <span>0.1 (slowest)</span><span>100 (fastest)</span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 4: Schedule (launch options placeholder)
// ---------------------------------------------------------------------------
function StepSchedule() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-white mb-1">Launch Options</h2>
        <p className="text-sm text-gray-400">Configure when and how the campaign will start.</p>
      </div>
      <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
        <p className="text-blue-300 text-sm">
          <strong>Immediate launch:</strong> The campaign will start as soon as you add targets and click &ldquo;Launch&rdquo;.
          Scheduled launch support (cron-based) is coming in a future release.
        </p>
      </div>
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 space-y-2">
        <p className="text-sm text-gray-300 font-medium">Current behaviour:</p>
        <ul className="text-sm text-gray-400 list-disc list-inside space-y-1">
          <li>Campaign created in <strong className="text-white">Draft</strong> state</li>
          <li>Add targets via the Target Grid on the detail page</li>
          <li>Click <strong className="text-white">Start</strong> to begin scanning</li>
          <li>Real-time progress updates via WebSocket</li>
        </ul>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 5: Review
// ---------------------------------------------------------------------------
function StepReview({ data }: { data: CampaignFormData }) {
  const profile = SCAN_PROFILE_INFO[data.config?.scan_profile ?? 'standard'];
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-white mb-1">Review &amp; Launch</h2>
        <p className="text-sm text-gray-400">Confirm campaign configuration before creating.</p>
      </div>
      <div className="space-y-3">
        <ReviewRow label="Name" value={data.name} />
        <ReviewRow label="Description" value={data.description || '—'} />
        <ReviewRow label="Scan Profile" value={profile?.label ?? data.config?.scan_profile} />
        <ReviewRow label="Concurrent Targets" value={String(data.config?.max_concurrent_targets ?? 3)} />
        <ReviewRow label="Scan Timeout" value={`${data.config?.scan_timeout_seconds ?? 3600}s`} />
        <ReviewRow label="Rate Limit" value={`${data.config?.rate_limit_rps ?? 10} req/s`} />
        <ReviewRow label="Max Retries" value={String(data.config?.max_retries ?? 2)} />
        <ReviewRow
          label="Cross-target Correlation"
          value={data.config?.enable_correlation !== false ? 'Enabled' : 'Disabled'}
        />
      </div>
    </div>
  );
}

function ReviewRow({ label, value }: { label: string; value: string | undefined }) {
  return (
    <div className="flex items-start justify-between py-2 border-b border-gray-700">
      <span className="text-sm text-gray-400">{label}</span>
      <span className="text-sm text-white font-medium text-right max-w-xs truncate">{value}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Wizard
// ---------------------------------------------------------------------------
export function CampaignWizard({ onSubmit, isLoading = false, error }: CampaignWizardProps) {
  const [step, setStep] = useState(1);
  const methods = useForm<CampaignFormData>({
    resolver: zodResolver(campaignSchema),
    defaultValues: {
      name: '',
      description: '',
      config: {
        max_concurrent_targets: 3,
        scan_timeout_seconds: 3600,
        retry_failed_targets: true,
        max_retries: 2,
        enable_correlation: true,
        rate_limit_rps: 10,
        tags: [],
        scan_profile: 'standard',
      },
    },
    mode: 'onBlur',
  });

  const watchedData = methods.watch();

  const handleNext = async () => {
    let fieldsToValidate: (keyof CampaignFormData)[] = [];
    if (step === 1) fieldsToValidate = ['name', 'description'];
    const valid = fieldsToValidate.length === 0 || await methods.trigger(fieldsToValidate);
    if (valid) setStep((s) => Math.min(s + 1, WIZARD_STEPS.length));
  };

  const handleBack = () => setStep((s) => Math.max(s - 1, 1));

  const handleSubmit = methods.handleSubmit(onSubmit);

  return (
    <FormProvider {...methods}>
      <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 max-w-2xl mx-auto">
        <StepIndicator currentStep={step} />

        <form onSubmit={handleSubmit}>
          {step === 1 && <StepDetails methods={methods} />}
          {step === 2 && <StepTargets methods={methods} />}
          {step === 3 && <StepConfig methods={methods} />}
          {step === 4 && <StepSchedule />}
          {step === 5 && <StepReview data={watchedData} />}

          {error && (
            <div className="mt-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30">
              <p className="text-red-400 text-sm">{error}</p>
            </div>
          )}

          <div className="flex justify-between mt-8">
            <Button
              type="button"
              variant="secondary"
              onClick={handleBack}
              disabled={step === 1}
              className="flex items-center gap-2"
            >
              <ChevronLeft className="w-4 h-4" /> Back
            </Button>

            {step < WIZARD_STEPS.length ? (
              <Button type="button" onClick={handleNext} className="flex items-center gap-2">
                Next <ChevronRight className="w-4 h-4" />
              </Button>
            ) : (
              <Button
                type="submit"
                disabled={isLoading}
                className="flex items-center gap-2 bg-green-600 hover:bg-green-700"
              >
                <Rocket className="w-4 h-4" />
                {isLoading ? 'Creating…' : 'Create Campaign'}
              </Button>
            )}
          </div>
        </form>
      </div>
    </FormProvider>
  );
}
