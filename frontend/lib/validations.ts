import { z } from 'zod';

// Project validation schema
export const projectSchema = z.object({
  name: z
    .string()
    .min(3, 'Project name must be at least 3 characters')
    .max(100, 'Project name must be less than 100 characters'),
  
  description: z
    .string()
    .max(500, 'Description must be less than 500 characters')
    .optional(),
  
  target: z
    .string()
    .min(1, 'Target is required')
    .refine((val) => {
      // Validate domain, IP, or URL
      const domainRegex = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      const urlRegex = /^https?:\/\/.+/;
      return domainRegex.test(val) || ipRegex.test(val) || urlRegex.test(val);
    }, 'Target must be a valid domain, IP address, or URL'),
  
  enable_subdomain_enum: z.boolean().default(true),
  enable_port_scan: z.boolean().default(true),
  enable_web_crawl: z.boolean().default(true),
  enable_tech_detection: z.boolean().default(true),
  enable_vuln_scan: z.boolean().default(true),
  enable_nuclei: z.boolean().default(true),
  enable_auto_exploit: z.boolean().default(false),
  
  // Advanced settings
  port_scan_type: z.enum(['quick', 'full', 'custom']).optional(),
  custom_ports: z.string().optional(),
  max_crawl_depth: z.number().min(1).max(10).optional(),
  nuclei_severity: z.array(z.enum(['critical', 'high', 'medium', 'low', 'info'])).optional(),
  concurrent_scans: z.number().min(1).max(10).optional(),
});

export type ProjectFormData = z.infer<typeof projectSchema>;

// Login validation schema
export const loginSchema = z.object({
  username: z
    .string()
    .min(3, 'Username must be at least 3 characters')
    .max(50, 'Username must be less than 50 characters'),
  
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be less than 128 characters'),
});

export type LoginFormData = z.infer<typeof loginSchema>;

// Register validation schema
export const registerSchema = z.object({
  username: z
    .string()
    .min(3, 'Username must be at least 3 characters')
    .max(50, 'Username must be less than 50 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens'),
  
  email: z
    .string()
    .email('Invalid email address'),
  
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be less than 128 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

export type RegisterFormData = z.infer<typeof registerSchema>;

// Target configuration validation
export const targetConfigSchema = z.object({
  target_type: z.enum(['domain', 'ip', 'url', 'cidr']),
  target_value: z.string().min(1, 'Target value is required'),
  exclude_targets: z.array(z.string()).optional(),
  include_subdomains: z.boolean().default(true),
});

export type TargetConfigData = z.infer<typeof targetConfigSchema>;

// Tool-specific configuration schemas
export const nmapConfigSchema = z.object({
  scan_type: z.enum(['quick', 'full', 'custom']).default('quick'),
  custom_flags: z.string().optional(),
  port_range: z.string().optional(),
  timing: z.enum(['T0', 'T1', 'T2', 'T3', 'T4', 'T5']).default('T3'),
  service_detection: z.boolean().default(true),
  os_detection: z.boolean().default(false),
});

export type NmapConfigData = z.infer<typeof nmapConfigSchema>;

export const nucleiConfigSchema = z.object({
  severity: z.array(z.enum(['critical', 'high', 'medium', 'low', 'info'])).default(['critical', 'high', 'medium']),
  tags: z.array(z.string()).optional(),
  exclude_tags: z.array(z.string()).optional(),
  templates: z.array(z.string()).optional(),
  rate_limit: z.number().min(1).max(1000).default(150),
});

export type NucleiConfigData = z.infer<typeof nucleiConfigSchema>;

// Campaign validation schemas
export const campaignConfigSchema = z.object({
  max_concurrent_targets: z.number().min(1).max(20).default(3),
  scan_timeout_seconds: z.number().min(60).max(86400).default(3600),
  retry_failed_targets: z.boolean().default(true),
  max_retries: z.number().min(0).max(5).default(2),
  enable_correlation: z.boolean().default(true),
  rate_limit_rps: z.number().min(0.1).max(100).default(10),
  tags: z.array(z.string()).default([]),
  scan_profile: z.enum(['quick', 'standard', 'thorough', 'stealth']).default('standard'),
});

export type CampaignConfigData = z.infer<typeof campaignConfigSchema>;

export const campaignSchema = z.object({
  name: z
    .string()
    .min(3, 'Campaign name must be at least 3 characters')
    .max(200, 'Campaign name must be less than 200 characters'),
  description: z
    .string()
    .max(2000, 'Description must be less than 2000 characters')
    .optional()
    .default(''),
  config: campaignConfigSchema.optional().default({}),
});

export type CampaignFormData = z.infer<typeof campaignSchema>;

export const addTargetSchema = z.object({
  host: z
    .string()
    .min(1, 'Host is required')
    .refine((val) => {
      const domainRegex = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
      const wildcardRegex = /^\*\.[a-zA-Z0-9-]+(\.[a-zA-Z]{2,})+$/;
      return domainRegex.test(val) || ipRegex.test(val) || wildcardRegex.test(val);
    }, 'Must be a valid domain, IP, or CIDR range'),
  port: z.number().min(1).max(65535).optional(),
  protocol: z.enum(['http', 'https']).default('https'),
  scope_notes: z.string().max(500).optional().default(''),
  tags: z.array(z.string()).default([]),
});

export type AddTargetFormData = z.infer<typeof addTargetSchema>;
