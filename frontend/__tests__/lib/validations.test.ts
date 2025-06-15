import {
  projectSchema,
  loginSchema,
  registerSchema,
  targetConfigSchema,
  nmapConfigSchema,
  nucleiConfigSchema,
} from '@/lib/validations';

// ─── projectSchema ──────────────────────────────────────────────────────────

describe('projectSchema', () => {
  const validProject = {
    name: 'Test Project',
    target: 'example.com',
  };

  it('accepts a valid project with domain target', () => {
    const result = projectSchema.safeParse(validProject);
    expect(result.success).toBe(true);
  });

  it('accepts an IP address as target', () => {
    const result = projectSchema.safeParse({ ...validProject, target: '192.168.1.1' });
    expect(result.success).toBe(true);
  });

  it('accepts a URL as target', () => {
    const result = projectSchema.safeParse({ ...validProject, target: 'https://example.com' });
    expect(result.success).toBe(true);
  });

  it('rejects a name that is too short (< 3 chars)', () => {
    const result = projectSchema.safeParse({ ...validProject, name: 'AB' });
    expect(result.success).toBe(false);
  });

  it('rejects a name that is too long (> 100 chars)', () => {
    const result = projectSchema.safeParse({ ...validProject, name: 'A'.repeat(101) });
    expect(result.success).toBe(false);
  });

  it('rejects an invalid target (plain text)', () => {
    const result = projectSchema.safeParse({ ...validProject, target: 'not a target' });
    expect(result.success).toBe(false);
  });

  it('applies boolean defaults', () => {
    const result = projectSchema.safeParse(validProject);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.enable_subdomain_enum).toBe(true);
      expect(result.data.enable_auto_exploit).toBe(false);
    }
  });
});

// ─── loginSchema ──────────────────────────────────────────────────────────

describe('loginSchema', () => {
  it('accepts valid credentials', () => {
    const result = loginSchema.safeParse({ username: 'alice', password: 'SecurePass1' });
    expect(result.success).toBe(true);
  });

  it('rejects a username that is too short', () => {
    const result = loginSchema.safeParse({ username: 'ab', password: 'SecurePass1' });
    expect(result.success).toBe(false);
  });

  it('rejects a password shorter than 8 characters', () => {
    const result = loginSchema.safeParse({ username: 'alice', password: 'short' });
    expect(result.success).toBe(false);
  });
});

// ─── registerSchema ───────────────────────────────────────────────────────

describe('registerSchema', () => {
  const validUser = {
    username: 'alice_01',
    email: 'alice@example.com',
    password: 'SecurePass1',
    confirmPassword: 'SecurePass1',
  };

  it('accepts a valid registration', () => {
    expect(registerSchema.safeParse(validUser).success).toBe(true);
  });

  it('rejects mismatched passwords', () => {
    const result = registerSchema.safeParse({ ...validUser, confirmPassword: 'Different1' });
    expect(result.success).toBe(false);
  });

  it('rejects invalid email', () => {
    const result = registerSchema.safeParse({ ...validUser, email: 'not-an-email' });
    expect(result.success).toBe(false);
  });

  it('rejects username with special characters', () => {
    const result = registerSchema.safeParse({ ...validUser, username: 'alice@home' });
    expect(result.success).toBe(false);
  });

  it('rejects password without uppercase letter', () => {
    const result = registerSchema.safeParse({ ...validUser, password: 'securepass1', confirmPassword: 'securepass1' });
    expect(result.success).toBe(false);
  });
});

// ─── targetConfigSchema ──────────────────────────────────────────────────

describe('targetConfigSchema', () => {
  it('accepts a valid domain target config', () => {
    const result = targetConfigSchema.safeParse({
      target_type: 'domain',
      target_value: 'example.com',
    });
    expect(result.success).toBe(true);
  });

  it('rejects an unknown target_type', () => {
    const result = targetConfigSchema.safeParse({
      target_type: 'unknown',
      target_value: 'example.com',
    });
    expect(result.success).toBe(false);
  });
});

// ─── nmapConfigSchema ──────────────────────────────────────────────────────

describe('nmapConfigSchema', () => {
  it('uses defaults when no options provided', () => {
    const result = nmapConfigSchema.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.scan_type).toBe('quick');
      expect(result.data.timing).toBe('T3');
    }
  });
});

// ─── nucleiConfigSchema ───────────────────────────────────────────────────

describe('nucleiConfigSchema', () => {
  it('uses defaults when no options provided', () => {
    const result = nucleiConfigSchema.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.severity).toEqual(['critical', 'high', 'medium']);
      expect(result.data.rate_limit).toBe(150);
    }
  });

  it('rejects rate_limit below 1', () => {
    const result = nucleiConfigSchema.safeParse({ rate_limit: 0 });
    expect(result.success).toBe(false);
  });

  it('rejects rate_limit above 1000', () => {
    const result = nucleiConfigSchema.safeParse({ rate_limit: 1001 });
    expect(result.success).toBe(false);
  });
});
