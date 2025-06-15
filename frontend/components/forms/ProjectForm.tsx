'use client';

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { projectSchema, type ProjectFormData } from '@/lib/validations';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Checkbox } from '@/components/ui/checkbox';
import { Select } from '@/components/ui/select';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useState } from 'react';

interface ProjectFormProps {
  onSubmit: (data: ProjectFormData) => void;
  isLoading?: boolean;
  defaultValues?: Partial<ProjectFormData>;
  error?: string;
}

export function ProjectForm({ onSubmit, isLoading, defaultValues, error }: ProjectFormProps) {
  const {
    register,
    handleSubmit,
    watch,
    setValue,
    formState: { errors },
  } = useForm<ProjectFormData>({
    resolver: zodResolver(projectSchema),
    defaultValues: {
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
      ...defaultValues,
    },
  });

  const enablePortScan = watch('enable_port_scan');
  const enableWebCrawl = watch('enable_web_crawl');
  const enableNuclei = watch('enable_nuclei');
  const portScanType = watch('port_scan_type');

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
      {error && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 px-4 py-3 rounded-md">
          {error}
        </div>
      )}

      {/* Basic Information */}
      <Card>
        <CardHeader>
          <CardTitle>Basic Information</CardTitle>
          <CardDescription>Configure your penetration testing project</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Project Name *</Label>
            <Input
              id="name"
              placeholder="My Penetration Test"
              {...register('name')}
              disabled={isLoading}
            />
            {errors.name && (
              <p className="text-sm text-red-600 dark:text-red-400">{errors.name.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="target">Target *</Label>
            <Input
              id="target"
              placeholder="example.com or 192.168.1.1"
              {...register('target')}
              disabled={isLoading}
            />
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Domain, IP address, or URL to test
            </p>
            {errors.target && (
              <p className="text-sm text-red-600 dark:text-red-400">{errors.target.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="description">Description</Label>
            <Textarea
              id="description"
              rows={3}
              placeholder="Optional project description..."
              {...register('description')}
              disabled={isLoading}
            />
            {errors.description && (
              <p className="text-sm text-red-600 dark:text-red-400">{errors.description.message}</p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Reconnaissance Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Reconnaissance</CardTitle>
          <CardDescription>Configure information gathering modules</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Checkbox
            id="enable_subdomain_enum"
            label="Enable subdomain enumeration"
            {...register('enable_subdomain_enum')}
            disabled={isLoading}
          />

          <div className="space-y-3">
            <Checkbox
              id="enable_port_scan"
              label="Enable port scanning"
              {...register('enable_port_scan')}
              disabled={isLoading}
            />

            {enablePortScan && (
              <div className="ml-7 space-y-3 border-l-2 border-blue-200 dark:border-blue-800 pl-4">
                <div className="space-y-2">
                  <Label htmlFor="port_scan_type">Scan Type</Label>
                  <Select
                    id="port_scan_type"
                    {...register('port_scan_type')}
                    disabled={isLoading}
                  >
                    <option value="quick">Quick Scan (Top 1000 ports)</option>
                    <option value="full">Full Scan (All 65535 ports)</option>
                    <option value="custom">Custom Port Range</option>
                  </Select>
                </div>

                {portScanType === 'custom' && (
                  <div className="space-y-2">
                    <Label htmlFor="custom_ports">Custom Ports</Label>
                    <Input
                      id="custom_ports"
                      placeholder="e.g., 80,443,8080-8090"
                      {...register('custom_ports')}
                      disabled={isLoading}
                    />
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      Comma-separated ports or ranges
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="space-y-3">
            <Checkbox
              id="enable_web_crawl"
              label="Enable web crawling"
              {...register('enable_web_crawl')}
              disabled={isLoading}
            />

            {enableWebCrawl && (
              <div className="ml-7 space-y-2 border-l-2 border-blue-200 dark:border-blue-800 pl-4">
                <Label htmlFor="max_crawl_depth">Maximum Crawl Depth</Label>
                <Input
                  id="max_crawl_depth"
                  type="number"
                  min="1"
                  max="10"
                  {...register('max_crawl_depth', { valueAsNumber: true })}
                  disabled={isLoading}
                />
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  How deep to crawl (1-10 levels)
                </p>
              </div>
            )}
          </div>

          <Checkbox
            id="enable_tech_detection"
            label="Enable technology detection"
            {...register('enable_tech_detection')}
            disabled={isLoading}
          />
        </CardContent>
      </Card>

      {/* Vulnerability Scanning */}
      <Card>
        <CardHeader>
          <CardTitle>Vulnerability Scanning</CardTitle>
          <CardDescription>Configure vulnerability detection tools</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Checkbox
            id="enable_vuln_scan"
            label="Enable vulnerability scanning"
            {...register('enable_vuln_scan')}
            disabled={isLoading}
          />

          <div className="space-y-3">
            <Checkbox
              id="enable_nuclei"
              label="Enable Nuclei scanner"
              {...register('enable_nuclei')}
              disabled={isLoading}
            />

            {enableNuclei && (
              <div className="ml-7 space-y-3 border-l-2 border-blue-200 dark:border-blue-800 pl-4">
                <div className="space-y-2">
                  <Label>Nuclei Severity Filter</Label>
                  <div className="space-y-2">
                    {['critical', 'high', 'medium', 'low', 'info'].map((severity) => (
                      <Checkbox
                        key={severity}
                        id={`nuclei_${severity}`}
                        label={severity.charAt(0).toUpperCase() + severity.slice(1)}
                        {...register('nuclei_severity')}
                        value={severity}
                        disabled={isLoading}
                      />
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Advanced Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Advanced Settings</CardTitle>
          <CardDescription>Configure performance and concurrency</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="concurrent_scans">Concurrent Scans</Label>
            <Input
              id="concurrent_scans"
              type="number"
              min="1"
              max="10"
              {...register('concurrent_scans', { valueAsNumber: true })}
              disabled={isLoading}
            />
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Number of scans to run simultaneously (1-10)
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Exploitation Settings */}
      <Card className="border-red-200 dark:border-red-900">
        <CardHeader>
          <CardTitle className="text-red-600 dark:text-red-400">
            ⚠️ Exploitation (Advanced)
          </CardTitle>
          <CardDescription className="text-yellow-600 dark:text-yellow-500">
            Only enable for authorized targets. Disabled by default for safety.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Checkbox
            id="enable_auto_exploit"
            label="Enable automated exploitation"
            {...register('enable_auto_exploit')}
            disabled={isLoading}
          />
        </CardContent>
      </Card>

      {/* Submit Buttons */}
      <div className="flex gap-4">
        <Button type="submit" className="flex-1" disabled={isLoading}>
          {isLoading ? 'Creating...' : 'Create Project'}
        </Button>
        <Button type="button" variant="secondary" disabled={isLoading}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
