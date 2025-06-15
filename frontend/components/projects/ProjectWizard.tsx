'use client';

import { useState } from 'react';
import { useForm, FormProvider } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { projectSchema, type ProjectFormData } from '@/lib/validations';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Checkbox } from '@/components/ui/checkbox';
import { Select } from '@/components/ui/select';
import { CheckCircle, Circle, ChevronRight, ChevronLeft, Rocket } from 'lucide-react';

interface ProjectWizardProps {
  onSubmit: (data: ProjectFormData) => void;
  isLoading?: boolean;
  error?: string;
}

const WIZARD_DEFAULTS: Partial<ProjectFormData> = {
  enable_subdomain_enum: true,
  enable_port_scan: true,
  enable_web_crawl: true,
  enable_tech_detection: true,
  enable_vuln_scan: true,
  enable_nuclei: true,
  enable_auto_exploit: false,
  port_scan_type: 'quick',
  max_crawl_depth: 3,
  concurrent_scans: 5,
};

const STEPS = [
  { id: 1, title: 'Basic Info', description: 'Project name and target' },
  { id: 2, title: 'Target Config', description: 'Scanning modules' },
  { id: 3, title: 'Tool Selection', description: 'Advanced tool settings' },
  { id: 4, title: 'Review', description: 'Confirm and launch' },
];

function StepIndicator({ currentStep }: { currentStep: number }) {
  return (
    <nav aria-label="Wizard steps" className="mb-8">
      <ol className="flex items-center justify-between">
        {STEPS.map((step, idx) => {
          const isCompleted = currentStep > step.id;
          const isCurrent = currentStep === step.id;
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
                  aria-hidden="true"
                >
                  {isCompleted ? (
                    <CheckCircle className="w-5 h-5" />
                  ) : (
                    <span className="text-sm font-semibold">{step.id}</span>
                  )}
                </div>
                <div className="mt-1.5 text-center hidden sm:block">
                  <p className={`text-xs font-medium ${isCurrent ? 'text-white' : isCompleted ? 'text-green-400' : 'text-gray-500'}`}>
                    {step.title}
                  </p>
                </div>
              </div>
              {idx < STEPS.length - 1 && (
                <div
                  className={`flex-1 h-0.5 mx-2 transition-colors ${
                    currentStep > step.id ? 'bg-green-600' : 'bg-gray-700'
                  }`}
                  aria-hidden="true"
                />
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

// Step 1 – Basic Info
function Step1({ methods }: { methods: any }) {
  const { register, formState: { errors } } = methods;
  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Basic Information</h2>
        <p className="text-gray-400 text-sm">Enter your project name and target</p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="name">Project Name <span className="text-red-400">*</span></Label>
        <Input
          id="name"
          placeholder="My Penetration Test"
          {...register('name')}
          aria-required="true"
          aria-describedby={errors.name ? 'name-error' : undefined}
        />
        {errors.name && (
          <p id="name-error" className="text-sm text-red-400" role="alert">{errors.name.message as string}</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="target">Target <span className="text-red-400">*</span></Label>
        <Input
          id="target"
          placeholder="example.com or 192.168.1.1"
          {...register('target')}
          aria-required="true"
          aria-describedby={errors.target ? 'target-error' : undefined}
        />
        <p className="text-xs text-gray-500">Domain, IP address, or URL to test</p>
        {errors.target && (
          <p id="target-error" className="text-sm text-red-400" role="alert">{errors.target.message as string}</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="description">Description</Label>
        <Textarea
          id="description"
          rows={3}
          placeholder="Optional project description..."
          {...register('description')}
        />
        {errors.description && (
          <p className="text-sm text-red-400">{errors.description.message as string}</p>
        )}
      </div>
    </div>
  );
}

// Step 2 – Target Config / Scanning modules
function Step2({ methods }: { methods: any }) {
  const { register, watch } = methods;
  const enablePortScan = watch('enable_port_scan');
  const enableWebCrawl = watch('enable_web_crawl');

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Target Configuration</h2>
        <p className="text-gray-400 text-sm">Choose which modules to enable for this target</p>
      </div>

      <div className="space-y-3">
        {[
          { id: 'enable_subdomain_enum', label: 'Subdomain Enumeration', desc: 'Discover subdomains' },
          { id: 'enable_tech_detection', label: 'Technology Detection', desc: 'Identify tech stack' },
          { id: 'enable_vuln_scan', label: 'Vulnerability Scanning', desc: 'Find vulnerabilities' },
          { id: 'enable_nuclei', label: 'Nuclei Scanner', desc: 'Template-based scanning' },
        ].map(({ id, label, desc }) => (
          <label key={id} className="flex items-start gap-3 p-3 bg-gray-700/50 rounded-lg cursor-pointer hover:bg-gray-700 transition-colors">
            <Checkbox id={id} {...register(id)} className="mt-0.5" />
            <div>
              <p className="text-white text-sm font-medium">{label}</p>
              <p className="text-gray-500 text-xs">{desc}</p>
            </div>
          </label>
        ))}

        {/* Port scan with sub-option */}
        <div className="p-3 bg-gray-700/50 rounded-lg space-y-3">
          <label className="flex items-start gap-3 cursor-pointer">
            <Checkbox id="enable_port_scan" {...register('enable_port_scan')} className="mt-0.5" />
            <div>
              <p className="text-white text-sm font-medium">Port Scanning</p>
              <p className="text-gray-500 text-xs">Discover open ports and services</p>
            </div>
          </label>
          {enablePortScan && (
            <div className="ml-7 space-y-2">
              <Label htmlFor="port_scan_type" className="text-xs">Scan Type</Label>
              <Select id="port_scan_type" {...register('port_scan_type')} className="text-sm">
                <option value="quick">Quick (Top 1000)</option>
                <option value="full">Full (All ports)</option>
                <option value="custom">Custom range</option>
              </Select>
            </div>
          )}
        </div>

        {/* Web crawl with sub-option */}
        <div className="p-3 bg-gray-700/50 rounded-lg space-y-3">
          <label className="flex items-start gap-3 cursor-pointer">
            <Checkbox id="enable_web_crawl" {...register('enable_web_crawl')} className="mt-0.5" />
            <div>
              <p className="text-white text-sm font-medium">Web Crawling</p>
              <p className="text-gray-500 text-xs">Map web application endpoints</p>
            </div>
          </label>
          {enableWebCrawl && (
            <div className="ml-7 space-y-2">
              <Label htmlFor="max_crawl_depth" className="text-xs">Max Crawl Depth</Label>
              <Input
                id="max_crawl_depth"
                type="number"
                min={1}
                max={10}
                {...register('max_crawl_depth', { valueAsNumber: true })}
                className="text-sm h-8"
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Step 3 – Tool Selection
function Step3({ methods }: { methods: any }) {
  const { register, watch } = methods;
  const enableNuclei = watch('enable_nuclei');

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Tool Selection</h2>
        <p className="text-gray-400 text-sm">Fine-tune tool configurations</p>
      </div>

      {/* Concurrency */}
      <div className="space-y-2">
        <Label htmlFor="concurrent_scans">Concurrent Scans</Label>
        <Input
          id="concurrent_scans"
          type="number"
          min={1}
          max={10}
          {...register('concurrent_scans', { valueAsNumber: true })}
        />
        <p className="text-xs text-gray-500">Number of simultaneous scans (1–10)</p>
      </div>

      {/* Nuclei severity */}
      {enableNuclei && (
        <div className="space-y-2">
          <Label>Nuclei Severity Filter</Label>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {['critical', 'high', 'medium', 'low', 'info'].map((sev) => (
              <label
                key={sev}
                className="flex items-center gap-2 p-2.5 bg-gray-700/50 rounded-lg cursor-pointer hover:bg-gray-700 transition-colors"
              >
                <Checkbox
                  id={`nuclei_${sev}`}
                  {...register('nuclei_severity')}
                  value={sev}
                />
                <span className="text-sm text-white capitalize">{sev}</span>
              </label>
            ))}
          </div>
        </div>
      )}

      {/* Auto exploit (dangerous) */}
      <div className="p-4 bg-red-900/20 border border-red-900 rounded-lg">
        <label className="flex items-start gap-3 cursor-pointer">
          <Checkbox id="enable_auto_exploit" {...register('enable_auto_exploit')} className="mt-0.5" />
          <div>
            <p className="text-red-400 text-sm font-medium">⚠️ Automated Exploitation</p>
            <p className="text-gray-500 text-xs">Only enable for explicitly authorized targets</p>
          </div>
        </label>
      </div>
    </div>
  );
}

// Step 4 – Review
function Step4({ data }: { data: ProjectFormData }) {
  const modules = [
    { key: 'enable_subdomain_enum', label: 'Subdomain Enumeration' },
    { key: 'enable_port_scan', label: 'Port Scanning' },
    { key: 'enable_web_crawl', label: 'Web Crawling' },
    { key: 'enable_tech_detection', label: 'Tech Detection' },
    { key: 'enable_vuln_scan', label: 'Vulnerability Scanning' },
    { key: 'enable_nuclei', label: 'Nuclei Scanner' },
    { key: 'enable_auto_exploit', label: 'Auto Exploitation' },
  ];

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Review & Launch</h2>
        <p className="text-gray-400 text-sm">Confirm your project configuration before creating</p>
      </div>

      <div className="bg-gray-700/50 rounded-lg p-4 space-y-3">
        <div className="flex justify-between">
          <span className="text-gray-400 text-sm">Project Name</span>
          <span className="text-white text-sm font-medium">{data.name}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-gray-400 text-sm">Target</span>
          <span className="text-blue-400 text-sm">{data.target}</span>
        </div>
        {data.description && (
          <div className="flex justify-between gap-4">
            <span className="text-gray-400 text-sm flex-shrink-0">Description</span>
            <span className="text-white text-sm text-right">{data.description}</span>
          </div>
        )}
        <div className="flex justify-between">
          <span className="text-gray-400 text-sm">Concurrent Scans</span>
          <span className="text-white text-sm">{data.concurrent_scans ?? WIZARD_DEFAULTS.concurrent_scans}</span>
        </div>
      </div>

      <div>
        <p className="text-gray-400 text-sm mb-2">Enabled Modules</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {modules.map(({ key, label }) => {
            const enabled = data[key as keyof ProjectFormData] as boolean;
            return (
              <div
                key={key}
                className={`flex items-center gap-2 p-2.5 rounded-lg text-sm ${
                  enabled
                    ? 'bg-green-900/20 border border-green-800 text-green-400'
                    : 'bg-gray-800 border border-gray-700 text-gray-600'
                }`}
              >
                {enabled ? <CheckCircle className="w-4 h-4 flex-shrink-0" /> : <Circle className="w-4 h-4 flex-shrink-0" />}
                {label}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export function ProjectWizard({ onSubmit, isLoading, error }: ProjectWizardProps) {
  const [step, setStep] = useState(1);

  const methods = useForm<ProjectFormData>({
    resolver: zodResolver(projectSchema),
    defaultValues: WIZARD_DEFAULTS,
    mode: 'onTouched',
  });

  const { handleSubmit, trigger, getValues, formState: { errors } } = methods;

  const fieldsPerStep: Record<number, (keyof ProjectFormData)[]> = {
    1: ['name', 'target', 'description'],
    2: [],
    3: [],
  };

  const handleNext = async () => {
    const fields = fieldsPerStep[step];
    const valid = fields.length ? await trigger(fields) : true;
    if (valid) setStep((s) => Math.min(4, s + 1));
  };

  const handleBack = () => setStep((s) => Math.max(1, s - 1));

  return (
    <FormProvider {...methods}>
      <div className="space-y-6">
        <StepIndicator currentStep={step} />

        {error && (
          <div className="bg-red-500/10 border border-red-500 text-red-400 px-4 py-3 rounded text-sm" role="alert">
            {error}
          </div>
        )}

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 min-h-[340px]">
          {step === 1 && <Step1 methods={methods} />}
          {step === 2 && <Step2 methods={methods} />}
          {step === 3 && <Step3 methods={methods} />}
          {step === 4 && <Step4 data={getValues()} />}
        </div>

        {/* Navigation */}
        <div className="flex justify-between items-center">
          <Button
            type="button"
            variant="secondary"
            onClick={handleBack}
            disabled={step === 1 || isLoading}
            className="flex items-center gap-2"
            aria-label="Go to previous step"
          >
            <ChevronLeft className="w-4 h-4" />
            Back
          </Button>

          <span className="text-gray-500 text-sm">
            Step {step} of {STEPS.length}
          </span>

          {step < 4 ? (
            <Button
              type="button"
              onClick={handleNext}
              disabled={isLoading}
              className="flex items-center gap-2"
              aria-label="Go to next step"
            >
              Next
              <ChevronRight className="w-4 h-4" />
            </Button>
          ) : (
            <Button
              type="button"
              onClick={handleSubmit(onSubmit)}
              disabled={isLoading}
              className="flex items-center gap-2"
              aria-label="Create project"
            >
              <Rocket className="w-4 h-4" />
              {isLoading ? 'Creating...' : 'Create Project'}
            </Button>
          )}
        </div>
      </div>
    </FormProvider>
  );
}
