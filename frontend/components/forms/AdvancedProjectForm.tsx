'use client';

import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Checkbox } from '@/components/ui/checkbox';
import { Select } from '@/components/ui/select';
import { ChevronDown, ChevronRight, Save, RotateCcw, Cloud, Loader2, Check } from 'lucide-react';
import { useFormAutosave, type AutosaveStatus } from '@/hooks/useFormAutosave';

// ─── Full schema with 180+ parameters ─────────────────────────────────────────
const advancedSchema = z.object({
  // === Basic ===
  name: z.string().min(3).max(100),
  description: z.string().max(500).optional(),
  target: z.string().min(1),
  tags: z.string().optional(),

  // === Subdomain Enumeration (20 params) ===
  enable_subdomain_enum: z.boolean().default(true),
  subdomain_wordlist: z.string().optional(),
  subdomain_resolvers: z.string().optional(),
  subdomain_max_depth: z.number().min(1).max(5).default(3),
  subdomain_brute_force: z.boolean().default(true),
  subdomain_permutation: z.boolean().default(false),
  subdomain_passive: z.boolean().default(true),
  subdomain_active: z.boolean().default(true),
  subdomain_concurrent: z.number().min(1).max(50).default(10),
  subdomain_timeout: z.number().min(1).max(60).default(10),
  subdomain_retries: z.number().min(0).max(5).default(2),
  subdomain_wildcards: z.boolean().default(true),
  subdomain_provider_chaos: z.boolean().default(false),
  subdomain_provider_shodan: z.boolean().default(false),
  subdomain_provider_censys: z.boolean().default(false),
  subdomain_provider_virustotal: z.boolean().default(false),
  subdomain_provider_crtsh: z.boolean().default(true),
  subdomain_provider_dnsdumpster: z.boolean().default(true),
  subdomain_provider_wayback: z.boolean().default(true),
  subdomain_max_results: z.number().min(100).max(100000).default(10000),

  // === Port Scan Config (20 params) ===
  enable_port_scan: z.boolean().default(true),
  port_scan_type: z.enum(['quick', 'full', 'custom']).default('quick'),
  custom_ports: z.string().optional(),
  port_scan_timing: z.enum(['T0', 'T1', 'T2', 'T3', 'T4', 'T5']).default('T3'),
  port_scan_service_detection: z.boolean().default(true),
  port_scan_os_detection: z.boolean().default(false),
  port_scan_version_intensity: z.number().min(0).max(9).default(5),
  port_scan_scripts: z.string().optional(),
  port_scan_udp: z.boolean().default(false),
  port_scan_syn: z.boolean().default(true),
  port_scan_connect: z.boolean().default(false),
  port_scan_max_retries: z.number().min(0).max(10).default(3),
  port_scan_host_timeout: z.number().min(30).max(3600).default(300),
  port_scan_min_rate: z.number().min(0).max(10000).default(0),
  port_scan_max_rate: z.number().min(0).max(10000).default(1000),
  port_scan_exclude_ports: z.string().optional(),
  port_scan_top_ports: z.number().min(10).max(65535).optional(),
  port_scan_traceroute: z.boolean().default(false),
  port_scan_fragmentation: z.boolean().default(false),
  port_scan_decoy: z.string().optional(),

  // === HTTP Probe Config (20 params) ===
  enable_http_probe: z.boolean().default(true),
  http_probe_timeout: z.number().min(1).max(60).default(10),
  http_probe_retries: z.number().min(0).max(5).default(2),
  http_probe_threads: z.number().min(1).max(100).default(50),
  http_probe_follow_redirects: z.boolean().default(true),
  http_probe_max_redirects: z.number().min(1).max(20).default(10),
  http_probe_http2: z.boolean().default(false),
  http_probe_screenshot: z.boolean().default(false),
  http_probe_title: z.boolean().default(true),
  http_probe_tech: z.boolean().default(true),
  http_probe_status_codes: z.string().optional(),
  http_probe_match_string: z.string().optional(),
  http_probe_filter_string: z.string().optional(),
  http_probe_custom_headers: z.string().optional(),
  http_probe_method: z.enum(['GET', 'POST', 'HEAD']).default('GET'),
  http_probe_body: z.string().optional(),
  http_probe_path: z.string().optional(),
  http_probe_cdn_filter: z.boolean().default(false),
  http_probe_tls_probe: z.boolean().default(true),
  http_probe_pipeline: z.boolean().default(false),

  // === Web Crawl Config (20 params) ===
  enable_web_crawl: z.boolean().default(true),
  enable_tech_detection: z.boolean().default(true),
  max_crawl_depth: z.number().min(1).max(10).default(3),
  crawl_concurrent: z.number().min(1).max(50).default(10),
  crawl_delay: z.number().min(0).max(5000).default(0),
  crawl_timeout: z.number().min(5).max(120).default(30),
  crawl_js_rendering: z.boolean().default(false),
  crawl_forms: z.boolean().default(true),
  crawl_subdomains: z.boolean().default(false),
  crawl_external: z.boolean().default(false),
  crawl_extensions_ignore: z.string().optional(),
  crawl_scope: z.enum(['strict', 'relaxed', 'fuzzy']).default('strict'),
  crawl_user_agent: z.string().optional(),
  crawl_cookies: z.string().optional(),
  crawl_headers: z.string().optional(),
  crawl_proxy: z.string().optional(),
  crawl_max_urls: z.number().min(100).max(100000).default(10000),
  crawl_blacklist: z.string().optional(),
  crawl_whitelist: z.string().optional(),
  crawl_robots_txt: z.boolean().default(true),
  crawl_sitemap: z.boolean().default(true),

  // === Vulnerability Scan Config (30 params) ===
  enable_vuln_scan: z.boolean().default(true),
  enable_nuclei: z.boolean().default(true),
  nuclei_severity: z.array(z.enum(['critical', 'high', 'medium', 'low', 'info'])).optional(),
  nuclei_tags: z.string().optional(),
  nuclei_exclude_tags: z.string().optional(),
  nuclei_templates: z.string().optional(),
  nuclei_rate_limit: z.number().min(1).max(1000).default(150),
  nuclei_bulk_size: z.number().min(1).max(500).default(25),
  nuclei_concurrency: z.number().min(1).max(100).default(25),
  nuclei_timeout: z.number().min(1).max(60).default(10),
  nuclei_retries: z.number().min(0).max(5).default(1),
  nuclei_follow_redirects: z.boolean().default(true),
  nuclei_interactsh: z.boolean().default(true),
  nuclei_headless: z.boolean().default(false),
  nuclei_system_resolvers: z.boolean().default(false),
  nuclei_update_templates: z.boolean().default(true),
  nuclei_stats: z.boolean().default(true),
  nuclei_no_color: z.boolean().default(false),
  nuclei_proxy: z.string().optional(),
  nuclei_custom_headers: z.string().optional(),
  nuclei_matcher_status: z.boolean().default(false),
  enable_nikto: z.boolean().default(false),
  nikto_timeout: z.number().min(30).max(3600).default(300),
  nikto_tuning: z.string().optional(),
  enable_zap: z.boolean().default(false),
  zap_scan_type: z.enum(['passive', 'active', 'ajax']).default('passive'),
  enable_sqlmap: z.boolean().default(false),
  sqlmap_level: z.number().min(1).max(5).default(1),
  sqlmap_risk: z.number().min(1).max(3).default(1),
  sqlmap_threads: z.number().min(1).max(10).default(1),

  // === AI Agent Config (20 params) ===
  enable_ai_agent: z.boolean().default(true),
  ai_model: z.enum(['gpt-4', 'gpt-3.5-turbo', 'claude-3', 'local']).default('gpt-4'),
  ai_max_tokens: z.number().min(256).max(8192).default(2048),
  ai_temperature: z.number().min(0).max(2).default(0.7),
  ai_auto_exploit: z.boolean().default(false),
  ai_report_generation: z.boolean().default(true),
  ai_vuln_prioritization: z.boolean().default(true),
  ai_attack_paths: z.boolean().default(true),
  ai_max_iterations: z.number().min(1).max(50).default(10),
  ai_approval_required: z.boolean().default(true),
  ai_safe_mode: z.boolean().default(true),
  ai_context_window: z.number().min(1024).max(128000).default(8192),
  ai_system_prompt: z.string().optional(),
  ai_tools_enabled: z.string().optional(),
  ai_tool_timeout: z.number().min(10).max(600).default(60),
  ai_memory_enabled: z.boolean().default(true),
  ai_reflection: z.boolean().default(true),
  ai_chain_of_thought: z.boolean().default(true),
  ai_few_shot_examples: z.boolean().default(true),
  ai_output_format: z.enum(['markdown', 'json', 'html']).default('markdown'),

  // === Output Config (20 params) ===
  output_dir: z.string().optional(),
  output_json: z.boolean().default(true),
  output_html_report: z.boolean().default(true),
  output_pdf_report: z.boolean().default(false),
  output_csv: z.boolean().default(false),
  output_xml: z.boolean().default(false),
  output_sarif: z.boolean().default(false),
  output_notify_slack: z.boolean().default(false),
  output_slack_webhook: z.string().optional(),
  output_notify_email: z.boolean().default(false),
  output_email_to: z.string().optional(),
  output_notify_discord: z.boolean().default(false),
  output_discord_webhook: z.string().optional(),
  output_s3_upload: z.boolean().default(false),
  output_s3_bucket: z.string().optional(),
  output_compress: z.boolean().default(false),
  output_encrypt: z.boolean().default(false),
  output_retention_days: z.number().min(1).max(365).default(90),
  output_include_screenshots: z.boolean().default(false),
  output_verbose: z.boolean().default(false),

  // === Performance / Concurrency (10 params) ===
  concurrent_scans: z.number().min(1).max(10).default(5),
  global_rate_limit: z.number().min(1).max(10000).default(500),
  global_timeout: z.number().min(60).max(86400).default(3600),
  memory_limit_mb: z.number().min(256).max(16384).default(2048),
  cpu_limit: z.number().min(1).max(32).default(4),
  retry_on_fail: z.boolean().default(true),
  retry_count: z.number().min(0).max(10).default(3),
  retry_delay: z.number().min(0).max(60).default(5),
  proxy_url: z.string().optional(),
  user_agent: z.string().optional(),
});

export type AdvancedProjectFormData = z.infer<typeof advancedSchema>;

interface AdvancedProjectFormProps {
  onSubmit: (data: AdvancedProjectFormData) => void;
  isLoading?: boolean;
  defaultValues?: Partial<AdvancedProjectFormData>;
  error?: string;
  autosaveKey?: string;
  submitLabel?: string;
}

// ─── Save status indicator ────────────────────────────────────────────────────
/**
 * Displays a live autosave status indicator.
 * - 'idle': renders nothing
 * - 'pending': shows an animated spinner with "Saving…" text
 * - 'saved': shows a check mark with "Saved" text, auto-reverts to idle after 2s
 */
function SaveIndicator({ status }: { status: AutosaveStatus }) {
  if (status === 'idle') return null;
  return (
    <span
      className={`inline-flex items-center gap-1 text-xs transition-all ${
        status === 'pending' ? 'text-gray-400' : 'text-green-400'
      }`}
      aria-live="polite"
      aria-label={status === 'pending' ? 'Saving draft…' : 'Draft saved'}
    >
      {status === 'pending' ? (
        <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />
      ) : (
        <Check className="w-3 h-3" aria-hidden="true" />
      )}
      {status === 'pending' ? 'Saving…' : 'Saved'}
    </span>
  );
}

// ─── Accordion section wrapper ────────────────────────────────────────────────
function Section({
  title,
  description,
  children,
  defaultOpen = false,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const id = `section-${title.toLowerCase().replace(/\s+/g, '-')}`;

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between p-5 text-left hover:bg-gray-750 transition-colors"
        aria-expanded={open}
        aria-controls={id}
      >
        <div>
          <h3 className="text-base font-semibold text-white">{title}</h3>
          {description && <p className="text-xs text-gray-500 mt-0.5">{description}</p>}
        </div>
        {open ? (
          <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0" aria-hidden="true" />
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0" aria-hidden="true" />
        )}
      </button>
      {open && (
        <div id={id} className="px-5 pb-5 space-y-4 border-t border-gray-700">
          <div className="pt-4">{children}</div>
        </div>
      )}
    </div>
  );
}

// ─── Reusable field helpers ───────────────────────────────────────────────────
function FieldRow({ children, cols = 1 }: { children: React.ReactNode; cols?: number }) {
  return (
    <div className={`grid gap-4 ${cols === 2 ? 'grid-cols-1 sm:grid-cols-2' : cols === 3 ? 'grid-cols-1 sm:grid-cols-3' : 'grid-cols-1'}`}>
      {children}
    </div>
  );
}

function NumberField({
  id, label, min, max, help, register, errors,
}: {
  id: string; label: string; min?: number; max?: number; help?: string;
  register: any; errors: any;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} type="number" min={min} max={max} {...register(id, { valueAsNumber: true })} />
      {help && <p className="text-xs text-gray-500">{help}</p>}
      {errors[id] && <p className="text-xs text-red-400">{errors[id].message}</p>}
    </div>
  );
}

function TextField({ id, label, placeholder, help, register, errors }: any) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} placeholder={placeholder} {...register(id)} />
      {help && <p className="text-xs text-gray-500">{help}</p>}
      {errors[id] && <p className="text-xs text-red-400">{errors[id].message}</p>}
    </div>
  );
}

function CheckField({ id, label, help, register }: { id: string; label: string; help?: string; register: any }) {
  return (
    <label className="flex items-start gap-2.5 cursor-pointer group">
      <Checkbox id={id} {...register(id)} className="mt-0.5" />
      <div>
        <span className="text-sm text-white group-hover:text-gray-200">{label}</span>
        {help && <p className="text-xs text-gray-500">{help}</p>}
      </div>
    </label>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────
export function AdvancedProjectForm({
  onSubmit,
  isLoading,
  defaultValues,
  error,
  autosaveKey = 'advanced-project-form',
  submitLabel = 'Create Project',
}: AdvancedProjectFormProps) {
  const [draftRestored, setDraftRestored] = useState(false);
  const [showDraftBanner, setShowDraftBanner] = useState(false);

  const {
    register,
    handleSubmit,
    watch,
    reset,
    getValues,
    formState: { errors, isDirty },
  } = useForm<AdvancedProjectFormData>({
    resolver: zodResolver(advancedSchema),
    defaultValues: {
      enable_subdomain_enum: true,
      enable_port_scan: true,
      enable_web_crawl: true,
      enable_tech_detection: true,
      enable_vuln_scan: true,
      enable_nuclei: true,
      enable_auto_exploit: false,
      enable_http_probe: true,
      enable_ai_agent: true,
      port_scan_type: 'quick',
      max_crawl_depth: 3,
      concurrent_scans: 5,
      nuclei_severity: ['critical', 'high', 'medium'],
      ai_model: 'gpt-4',
      output_json: true,
      output_html_report: true,
      ...defaultValues,
    } as AdvancedProjectFormData,
  });

  // Autosave
  const watchedValues = watch();
  const { getDraft, clearDraft, autosaveStatus } = useFormAutosave({
    key: autosaveKey,
    data: watchedValues,
    debounceMs: 1500,
  });

  // Offer to restore draft on mount
  useEffect(() => {
    if (draftRestored) return;
    const draft = getDraft();
    if (draft) setShowDraftBanner(true);
    setDraftRestored(true);
  }, [getDraft, draftRestored]);

  const restoreDraft = () => {
    const draft = getDraft();
    if (draft) {
      reset(draft.data as AdvancedProjectFormData);
    }
    setShowDraftBanner(false);
  };

  const dismissDraft = () => {
    clearDraft();
    setShowDraftBanner(false);
  };

  const portScanType = watch('port_scan_type');
  const enablePortScan = watch('enable_port_scan');
  const enableWebCrawl = watch('enable_web_crawl');
  const enableNuclei = watch('enable_nuclei');
  const enableNikto = watch('enable_nikto');
  const enableZap = watch('enable_zap');
  const enableSqlmap = watch('enable_sqlmap');
  const enableSlack = watch('output_notify_slack');
  const enableEmail = watch('output_notify_email');
  const enableDiscord = watch('output_notify_discord');
  const enableS3 = watch('output_s3_upload');
  const enableAiAgent = watch('enable_ai_agent');

  return (
    <form
      onSubmit={handleSubmit(onSubmit as any)}
      className="space-y-4"
      noValidate
      aria-label="Advanced project configuration form"
    >
      {/* Draft restore banner */}
      {showDraftBanner && (
        <div className="bg-blue-900/30 border border-blue-700 rounded-lg px-4 py-3 flex items-center justify-between gap-4" role="status">
          <p className="text-blue-300 text-sm">A saved draft was found. Would you like to restore it?</p>
          <div className="flex gap-2 flex-shrink-0">
            <button type="button" onClick={restoreDraft} className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors">Restore</button>
            <button type="button" onClick={dismissDraft} className="px-3 py-1 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded transition-colors">Dismiss</button>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-500/10 border border-red-500 text-red-400 px-4 py-3 rounded text-sm" role="alert">
          {error}
        </div>
      )}

      {/* ── Basic Info ──────────────────────────────── */}
      <Section title="Basic Information" description="Project name, target, and description" defaultOpen>
        <FieldRow cols={2}>
          <div className="space-y-1.5">
            <Label htmlFor="name">Project Name <span className="text-red-400">*</span></Label>
            <Input id="name" placeholder="My Pentest" {...register('name')} aria-required="true" aria-describedby={errors.name ? 'err-name' : undefined} />
            {errors.name && <p id="err-name" className="text-xs text-red-400" role="alert">{errors.name.message}</p>}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="target">Target <span className="text-red-400">*</span></Label>
            <Input id="target" placeholder="example.com" {...register('target')} aria-required="true" aria-describedby={errors.target ? 'err-target' : undefined} />
            {errors.target && <p id="err-target" className="text-xs text-red-400" role="alert">{errors.target.message}</p>}
          </div>
        </FieldRow>
        <div className="space-y-1.5">
          <Label htmlFor="description">Description</Label>
          <Textarea id="description" rows={2} placeholder="Optional description..." {...register('description')} />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="tags">Tags</Label>
          <Input id="tags" placeholder="web, internal, bug-bounty" {...register('tags')} />
          <p className="text-xs text-gray-500">Comma-separated tags</p>
        </div>
      </Section>

      {/* ── Subdomain Enumeration ──────────────────── */}
      <Section title="Subdomain Enumeration" description="20 parameters for subdomain discovery">
        <CheckField id="enable_subdomain_enum" label="Enable subdomain enumeration" register={register} />
        <FieldRow cols={2}>
          <NumberField id="subdomain_max_depth" label="Max Recursion Depth" min={1} max={5} register={register} errors={errors} />
          <NumberField id="subdomain_concurrent" label="Concurrent Tasks" min={1} max={50} register={register} errors={errors} />
          <NumberField id="subdomain_timeout" label="Timeout (seconds)" min={1} max={60} register={register} errors={errors} />
          <NumberField id="subdomain_retries" label="Retries" min={0} max={5} register={register} errors={errors} />
          <NumberField id="subdomain_max_results" label="Max Results" min={100} max={100000} register={register} errors={errors} />
        </FieldRow>
        <TextField id="subdomain_wordlist" label="Custom Wordlist Path" placeholder="/path/to/wordlist.txt" register={register} errors={errors} />
        <TextField id="subdomain_resolvers" label="Custom Resolvers" placeholder="8.8.8.8,1.1.1.1" register={register} errors={errors} />

        <div className="space-y-2">
          <p className="text-sm font-medium text-gray-300">Discovery Methods</p>
          <div className="grid grid-cols-2 gap-2">
            <CheckField id="subdomain_brute_force" label="Brute Force" register={register} />
            <CheckField id="subdomain_permutation" label="Permutation" register={register} />
            <CheckField id="subdomain_passive" label="Passive Sources" register={register} />
            <CheckField id="subdomain_active" label="Active DNS" register={register} />
            <CheckField id="subdomain_wildcards" label="Handle Wildcards" register={register} />
          </div>
        </div>

        <div className="space-y-2">
          <p className="text-sm font-medium text-gray-300">External Providers</p>
          <div className="grid grid-cols-2 gap-2">
            <CheckField id="subdomain_provider_crtsh" label="crt.sh" register={register} />
            <CheckField id="subdomain_provider_dnsdumpster" label="DNSDumpster" register={register} />
            <CheckField id="subdomain_provider_wayback" label="Wayback Machine" register={register} />
            <CheckField id="subdomain_provider_chaos" label="Chaos (ProjectDiscovery)" register={register} />
            <CheckField id="subdomain_provider_shodan" label="Shodan" register={register} />
            <CheckField id="subdomain_provider_censys" label="Censys" register={register} />
            <CheckField id="subdomain_provider_virustotal" label="VirusTotal" register={register} />
          </div>
        </div>
      </Section>

      {/* ── Port Scan Config ───────────────────────── */}
      <Section title="Port Scan Configuration" description="20 parameters for Nmap-based port scanning">
        <CheckField id="enable_port_scan" label="Enable port scanning" register={register} />
        {enablePortScan && (
          <>
            <FieldRow cols={2}>
              <div className="space-y-1.5">
                <Label htmlFor="port_scan_type">Scan Type</Label>
                <Select id="port_scan_type" {...register('port_scan_type')}>
                  <option value="quick">Quick (Top 1000)</option>
                  <option value="full">Full (All 65535)</option>
                  <option value="custom">Custom</option>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="port_scan_timing">Timing Template</Label>
                <Select id="port_scan_timing" {...register('port_scan_timing')}>
                  {['T0', 'T1', 'T2', 'T3', 'T4', 'T5'].map((t) => (
                    <option key={t} value={t}>{t} {t === 'T3' ? '(default)' : t === 'T4' ? '(aggressive)' : t === 'T5' ? '(insane)' : ''}</option>
                  ))}
                </Select>
              </div>
            </FieldRow>

            {portScanType === 'custom' && (
              <TextField id="custom_ports" label="Custom Ports" placeholder="80,443,8080-8090" register={register} errors={errors} help="Comma-separated ports or ranges" />
            )}

            <FieldRow cols={3}>
              <NumberField id="port_scan_version_intensity" label="Version Intensity (0-9)" min={0} max={9} register={register} errors={errors} />
              <NumberField id="port_scan_max_retries" label="Max Retries" min={0} max={10} register={register} errors={errors} />
              <NumberField id="port_scan_host_timeout" label="Host Timeout (s)" min={30} max={3600} register={register} errors={errors} />
              <NumberField id="port_scan_min_rate" label="Min Rate (pkt/s)" min={0} max={10000} register={register} errors={errors} />
              <NumberField id="port_scan_max_rate" label="Max Rate (pkt/s)" min={0} max={10000} register={register} errors={errors} />
            </FieldRow>

            <TextField id="port_scan_scripts" label="NSE Scripts" placeholder="default,safe" register={register} errors={errors} />
            <TextField id="port_scan_exclude_ports" label="Exclude Ports" placeholder="22,23" register={register} errors={errors} />
            <TextField id="port_scan_decoy" label="Decoy IPs" placeholder="IP1,IP2" register={register} errors={errors} />

            <div className="grid grid-cols-2 gap-2">
              <CheckField id="port_scan_service_detection" label="Service Detection" register={register} />
              <CheckField id="port_scan_os_detection" label="OS Detection" register={register} />
              <CheckField id="port_scan_syn" label="SYN Scan" register={register} />
              <CheckField id="port_scan_connect" label="Connect Scan" register={register} />
              <CheckField id="port_scan_udp" label="UDP Scan" register={register} />
              <CheckField id="port_scan_traceroute" label="Traceroute" register={register} />
              <CheckField id="port_scan_fragmentation" label="Fragmentation" register={register} />
            </div>
          </>
        )}
      </Section>

      {/* ── HTTP Probe Config ──────────────────────── */}
      <Section title="HTTP Probe Configuration" description="20 parameters for HTTP fingerprinting">
        <CheckField id="enable_http_probe" label="Enable HTTP probing (httpx)" register={register} />
        <FieldRow cols={3}>
          <NumberField id="http_probe_timeout" label="Timeout (s)" min={1} max={60} register={register} errors={errors} />
          <NumberField id="http_probe_retries" label="Retries" min={0} max={5} register={register} errors={errors} />
          <NumberField id="http_probe_threads" label="Threads" min={1} max={100} register={register} errors={errors} />
          <NumberField id="http_probe_max_redirects" label="Max Redirects" min={1} max={20} register={register} errors={errors} />
        </FieldRow>

        <FieldRow cols={2}>
          <div className="space-y-1.5">
            <Label htmlFor="http_probe_method">HTTP Method</Label>
            <Select id="http_probe_method" {...register('http_probe_method')}>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="HEAD">HEAD</option>
            </Select>
          </div>
        </FieldRow>

        <TextField id="http_probe_status_codes" label="Filter Status Codes" placeholder="200,301,403" register={register} errors={errors} />
        <TextField id="http_probe_custom_headers" label="Custom Headers" placeholder="Authorization: Bearer TOKEN" register={register} errors={errors} />
        <TextField id="http_probe_match_string" label="Match String" placeholder="text to match in response" register={register} errors={errors} />
        <TextField id="http_probe_path" label="Custom Path" placeholder="/api/v1/" register={register} errors={errors} />

        <div className="grid grid-cols-2 gap-2">
          <CheckField id="http_probe_follow_redirects" label="Follow Redirects" register={register} />
          <CheckField id="http_probe_http2" label="HTTP/2 Support" register={register} />
          <CheckField id="http_probe_screenshot" label="Take Screenshots" register={register} />
          <CheckField id="http_probe_title" label="Extract Page Title" register={register} />
          <CheckField id="http_probe_tech" label="Tech Detection" register={register} />
          <CheckField id="http_probe_tls_probe" label="TLS Probe" register={register} />
          <CheckField id="http_probe_cdn_filter" label="Filter CDN IPs" register={register} />
          <CheckField id="http_probe_pipeline" label="HTTP Pipeline" register={register} />
        </div>
      </Section>

      {/* ── Web Crawl Config ───────────────────────── */}
      <Section title="Web Crawl Configuration" description="20 parameters for Katana/crawler settings">
        <CheckField id="enable_web_crawl" label="Enable web crawling" register={register} />
        {enableWebCrawl && (
          <>
            <FieldRow cols={3}>
              <NumberField id="max_crawl_depth" label="Max Depth (1-10)" min={1} max={10} register={register} errors={errors} />
              <NumberField id="crawl_concurrent" label="Concurrency" min={1} max={50} register={register} errors={errors} />
              <NumberField id="crawl_delay" label="Request Delay (ms)" min={0} max={5000} register={register} errors={errors} />
              <NumberField id="crawl_timeout" label="Timeout (s)" min={5} max={120} register={register} errors={errors} />
              <NumberField id="crawl_max_urls" label="Max URLs" min={100} max={100000} register={register} errors={errors} />
            </FieldRow>

            <div className="space-y-1.5">
              <Label htmlFor="crawl_scope">Scope</Label>
              <Select id="crawl_scope" {...register('crawl_scope')}>
                <option value="strict">Strict (same domain)</option>
                <option value="relaxed">Relaxed (include subdomains)</option>
                <option value="fuzzy">Fuzzy (follow all)</option>
              </Select>
            </div>

            <TextField id="crawl_user_agent" label="Custom User-Agent" placeholder="Mozilla/5.0 ..." register={register} errors={errors} />
            <TextField id="crawl_cookies" label="Session Cookies" placeholder="session=abc123" register={register} errors={errors} />
            <TextField id="crawl_headers" label="Custom Headers" placeholder="Authorization: ..." register={register} errors={errors} />
            <TextField id="crawl_proxy" label="Proxy" placeholder="http://127.0.0.1:8080" register={register} errors={errors} />
            <TextField id="crawl_extensions_ignore" label="Ignore Extensions" placeholder=".jpg,.png,.gif" register={register} errors={errors} />
            <TextField id="crawl_blacklist" label="URL Blacklist (regex)" placeholder="logout|signout" register={register} errors={errors} />
            <TextField id="crawl_whitelist" label="URL Whitelist (regex)" placeholder="\/api\/" register={register} errors={errors} />

            <div className="grid grid-cols-2 gap-2">
              <CheckField id="crawl_js_rendering" label="JavaScript Rendering" register={register} />
              <CheckField id="crawl_forms" label="Form Submission" register={register} />
              <CheckField id="crawl_subdomains" label="Crawl Subdomains" register={register} />
              <CheckField id="crawl_external" label="Crawl External Links" register={register} />
              <CheckField id="crawl_robots_txt" label="Respect robots.txt" register={register} />
              <CheckField id="crawl_sitemap" label="Parse Sitemap" register={register} />
            </div>
          </>
        )}
      </Section>

      {/* ── Vulnerability Scan Config ──────────────── */}
      <Section title="Vulnerability Scan Configuration" description="30 parameters for Nuclei, Nikto, ZAP, SQLMap">
        <CheckField id="enable_vuln_scan" label="Enable vulnerability scanning" register={register} />

        <div className="space-y-3">
          {/* Nuclei */}
          <div className="p-3 bg-gray-700/40 rounded-lg space-y-3">
            <CheckField id="enable_nuclei" label="Nuclei Scanner" help="Fast template-based scanner" register={register} />
            {enableNuclei && (
              <>
                <div className="space-y-2">
                  <Label>Severity Filter</Label>
                  <div className="flex flex-wrap gap-2">
                    {['critical', 'high', 'medium', 'low', 'info'].map((sev) => (
                      <label key={sev} className="flex items-center gap-1.5 cursor-pointer">
                        <Checkbox id={`nuclei_sev_${sev}`} {...register('nuclei_severity')} value={sev} />
                        <span className="text-sm text-white capitalize">{sev}</span>
                      </label>
                    ))}
                  </div>
                </div>
                <FieldRow cols={3}>
                  <NumberField id="nuclei_rate_limit" label="Rate Limit" min={1} max={1000} register={register} errors={errors} />
                  <NumberField id="nuclei_concurrency" label="Concurrency" min={1} max={100} register={register} errors={errors} />
                  <NumberField id="nuclei_bulk_size" label="Bulk Size" min={1} max={500} register={register} errors={errors} />
                  <NumberField id="nuclei_timeout" label="Timeout (s)" min={1} max={60} register={register} errors={errors} />
                  <NumberField id="nuclei_retries" label="Retries" min={0} max={5} register={register} errors={errors} />
                </FieldRow>
                <TextField id="nuclei_tags" label="Include Tags" placeholder="cve,rce,sqli" register={register} errors={errors} />
                <TextField id="nuclei_exclude_tags" label="Exclude Tags" placeholder="info,dos" register={register} errors={errors} />
                <TextField id="nuclei_templates" label="Custom Templates Path" placeholder="/templates/" register={register} errors={errors} />
                <TextField id="nuclei_proxy" label="Proxy" placeholder="http://127.0.0.1:8080" register={register} errors={errors} />
                <TextField id="nuclei_custom_headers" label="Custom Headers" placeholder="X-Custom: value" register={register} errors={errors} />
                <div className="grid grid-cols-2 gap-2">
                  <CheckField id="nuclei_follow_redirects" label="Follow Redirects" register={register} />
                  <CheckField id="nuclei_interactsh" label="Interactsh (OOB)" register={register} />
                  <CheckField id="nuclei_headless" label="Headless Mode" register={register} />
                  <CheckField id="nuclei_update_templates" label="Auto-update Templates" register={register} />
                  <CheckField id="nuclei_stats" label="Show Statistics" register={register} />
                  <CheckField id="nuclei_matcher_status" label="Match Status Only" register={register} />
                </div>
              </>
            )}
          </div>

          {/* Nikto */}
          <div className="p-3 bg-gray-700/40 rounded-lg space-y-3">
            <CheckField id="enable_nikto" label="Nikto Web Scanner" help="HTTP server vulnerability scanner" register={register} />
            {enableNikto && (
              <FieldRow cols={2}>
                <NumberField id="nikto_timeout" label="Timeout (s)" min={30} max={3600} register={register} errors={errors} />
                <TextField id="nikto_tuning" label="Tuning" placeholder="1234" help="1=Files, 2=Interesting, 3=Misconfiguration..." register={register} errors={errors} />
              </FieldRow>
            )}
          </div>

          {/* ZAP */}
          <div className="p-3 bg-gray-700/40 rounded-lg space-y-3">
            <CheckField id="enable_zap" label="OWASP ZAP" help="Dynamic application security testing" register={register} />
            {enableZap && (
              <div className="space-y-1.5">
                <Label htmlFor="zap_scan_type">ZAP Scan Type</Label>
                <Select id="zap_scan_type" {...register('zap_scan_type')}>
                  <option value="passive">Passive</option>
                  <option value="active">Active</option>
                  <option value="ajax">AJAX Spider</option>
                </Select>
              </div>
            )}
          </div>

          {/* SQLMap */}
          <div className="p-3 bg-gray-700/40 rounded-lg space-y-3">
            <CheckField id="enable_sqlmap" label="SQLMap" help="SQL injection detection and exploitation" register={register} />
            {enableSqlmap && (
              <FieldRow cols={3}>
                <NumberField id="sqlmap_level" label="Level (1-5)" min={1} max={5} register={register} errors={errors} />
                <NumberField id="sqlmap_risk" label="Risk (1-3)" min={1} max={3} register={register} errors={errors} />
                <NumberField id="sqlmap_threads" label="Threads" min={1} max={10} register={register} errors={errors} />
              </FieldRow>
            )}
          </div>
        </div>
      </Section>

      {/* ── AI Agent Config ────────────────────────── */}
      <Section title="AI Agent Configuration" description="20 parameters for the AI pentest agent">
        <CheckField id="enable_ai_agent" label="Enable AI Agent" help="Autonomous AI-driven penetration testing" register={register} />
        {enableAiAgent && (
          <>
            <FieldRow cols={2}>
              <div className="space-y-1.5">
                <Label htmlFor="ai_model">AI Model</Label>
                <Select id="ai_model" {...register('ai_model')}>
                  <option value="gpt-4o">GPT-4o (OpenAI)</option>
                  <option value="gpt-4">GPT-4 (OpenAI)</option>
                  <option value="gpt-3.5-turbo">GPT-3.5 Turbo (OpenAI)</option>
                  <option value="claude-3-5-sonnet-20241022">Claude 3.5 Sonnet (Anthropic)</option>
                  <option value="claude-3">Claude 3 (Anthropic)</option>
                  <option value="gemini-1.5-flash">Gemini 1.5 Flash (Google — free)</option>
                  <option value="gemini-1.5-pro">Gemini 1.5 Pro (Google)</option>
                  <option value="llama-3.3-70b-versatile">Llama 3.3 70B (Groq — free)</option>
                  <option value="llama-3.1-8b-instant">Llama 3.1 8B Instant (Groq — free)</option>
                  <option value="mixtral-8x7b-32768">Mixtral 8x7B (Groq — free)</option>
                  <option value="anthropic/claude-3.5-sonnet">Claude 3.5 Sonnet via OpenRouter</option>
                  <option value="openai/gpt-4o">GPT-4o via OpenRouter</option>
                  <option value="meta-llama/llama-3.3-70b-instruct">Llama 3.3 70B via OpenRouter</option>
                  <option value="local">Local LLM</option>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="ai_output_format">Output Format</Label>
                <Select id="ai_output_format" {...register('ai_output_format')}>
                  <option value="markdown">Markdown</option>
                  <option value="json">JSON</option>
                  <option value="html">HTML</option>
                </Select>
              </div>
            </FieldRow>

            <FieldRow cols={3}>
              <NumberField id="ai_max_tokens" label="Max Tokens" min={256} max={8192} register={register} errors={errors} />
              <NumberField id="ai_max_iterations" label="Max Iterations" min={1} max={50} register={register} errors={errors} />
              <NumberField id="ai_context_window" label="Context Window" min={1024} max={128000} register={register} errors={errors} />
              <NumberField id="ai_tool_timeout" label="Tool Timeout (s)" min={10} max={600} register={register} errors={errors} />
            </FieldRow>

            <div className="space-y-1.5">
              <Label htmlFor="ai_system_prompt">Custom System Prompt</Label>
              <Textarea id="ai_system_prompt" rows={3} placeholder="Additional instructions for the AI agent..." {...register('ai_system_prompt')} />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <CheckField id="ai_approval_required" label="Require Human Approval" help="Approve each AI action" register={register} />
              <CheckField id="ai_safe_mode" label="Safe Mode" help="Prevent destructive actions" register={register} />
              <CheckField id="ai_auto_exploit" label="Auto Exploit" help="Automatically exploit found vulnerabilities" register={register} />
              <CheckField id="ai_report_generation" label="Auto-generate Report" register={register} />
              <CheckField id="ai_vuln_prioritization" label="Vulnerability Prioritization" register={register} />
              <CheckField id="ai_attack_paths" label="Attack Path Analysis" register={register} />
              <CheckField id="ai_memory_enabled" label="Persistent Memory" register={register} />
              <CheckField id="ai_reflection" label="Self-reflection" register={register} />
              <CheckField id="ai_chain_of_thought" label="Chain of Thought" register={register} />
              <CheckField id="ai_few_shot_examples" label="Few-shot Examples" register={register} />
            </div>
          </>
        )}
      </Section>

      {/* ── Output Config ──────────────────────────── */}
      <Section title="Output Configuration" description="20 parameters for reports and notifications">
        <TextField id="output_dir" label="Output Directory" placeholder="/results/my-project" register={register} errors={errors} />
        <NumberField id="output_retention_days" label="Data Retention (days)" min={1} max={365} register={register} errors={errors} />

        <div className="space-y-2">
          <p className="text-sm font-medium text-gray-300">Report Formats</p>
          <div className="grid grid-cols-2 gap-2">
            <CheckField id="output_json" label="JSON" register={register} />
            <CheckField id="output_html_report" label="HTML Report" register={register} />
            <CheckField id="output_pdf_report" label="PDF Report" register={register} />
            <CheckField id="output_csv" label="CSV" register={register} />
            <CheckField id="output_xml" label="XML" register={register} />
            <CheckField id="output_sarif" label="SARIF" register={register} />
            <CheckField id="output_include_screenshots" label="Include Screenshots" register={register} />
            <CheckField id="output_verbose" label="Verbose Output" register={register} />
            <CheckField id="output_compress" label="Compress Output" register={register} />
            <CheckField id="output_encrypt" label="Encrypt Output" register={register} />
          </div>
        </div>

        <div className="space-y-3">
          <p className="text-sm font-medium text-gray-300">Notifications</p>

          <div className="p-3 bg-gray-700/40 rounded-lg space-y-2">
            <CheckField id="output_notify_slack" label="Slack Notifications" register={register} />
            {enableSlack && <TextField id="output_slack_webhook" label="Slack Webhook URL" placeholder="https://hooks.slack.com/..." register={register} errors={errors} />}
          </div>
          <div className="p-3 bg-gray-700/40 rounded-lg space-y-2">
            <CheckField id="output_notify_email" label="Email Notifications" register={register} />
            {enableEmail && <TextField id="output_email_to" label="Email To" placeholder="security@example.com" register={register} errors={errors} />}
          </div>
          <div className="p-3 bg-gray-700/40 rounded-lg space-y-2">
            <CheckField id="output_notify_discord" label="Discord Notifications" register={register} />
            {enableDiscord && <TextField id="output_discord_webhook" label="Discord Webhook URL" placeholder="https://discord.com/api/webhooks/..." register={register} errors={errors} />}
          </div>
          <div className="p-3 bg-gray-700/40 rounded-lg space-y-2">
            <CheckField id="output_s3_upload" label="Upload to S3" register={register} />
            {enableS3 && <TextField id="output_s3_bucket" label="S3 Bucket" placeholder="my-pentest-results" register={register} errors={errors} />}
          </div>
        </div>
      </Section>

      {/* ── Performance Config ─────────────────────── */}
      <Section title="Performance & Concurrency" description="Global concurrency, rate limits, and resource limits">
        <FieldRow cols={3}>
          <NumberField id="concurrent_scans" label="Concurrent Scans" min={1} max={10} register={register} errors={errors} />
          <NumberField id="global_rate_limit" label="Global Rate Limit (req/s)" min={1} max={10000} register={register} errors={errors} />
          <NumberField id="global_timeout" label="Global Timeout (s)" min={60} max={86400} register={register} errors={errors} />
          <NumberField id="memory_limit_mb" label="Memory Limit (MB)" min={256} max={16384} register={register} errors={errors} />
          <NumberField id="cpu_limit" label="CPU Cores Limit" min={1} max={32} register={register} errors={errors} />
          <NumberField id="retry_count" label="Retry Count" min={0} max={10} register={register} errors={errors} />
          <NumberField id="retry_delay" label="Retry Delay (s)" min={0} max={60} register={register} errors={errors} />
        </FieldRow>

        <TextField id="proxy_url" label="Global Proxy" placeholder="http://127.0.0.1:8080" register={register} errors={errors} />
        <TextField id="user_agent" label="Global User-Agent" placeholder="Mozilla/5.0 ..." register={register} errors={errors} />

        <CheckField id="retry_on_fail" label="Retry on Failure" register={register} />
      </Section>

      {/* Submit */}
      <div className="flex items-center justify-between pt-2">
        <div className="flex items-center gap-3">
          <p className="text-xs text-gray-500">
            {isDirty ? 'Unsaved changes' : 'No unsaved changes'}
          </p>
          <SaveIndicator status={autosaveStatus} />
        </div>
        <div className="flex gap-3">
          <Button
            type="button"
            variant="secondary"
            onClick={() => { clearDraft(); reset(); }}
            disabled={isLoading}
            className="flex items-center gap-2"
            aria-label="Reset form to defaults"
          >
            <RotateCcw className="w-4 h-4" />
            Reset
          </Button>
          <Button
            type="submit"
            disabled={isLoading}
            className="flex items-center gap-2"
            aria-label="Save project configuration"
          >
            <Save className="w-4 h-4" />
            {isLoading ? 'Saving...' : submitLabel}
          </Button>
        </div>
      </div>
    </form>
  );
}
