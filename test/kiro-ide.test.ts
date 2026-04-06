import { afterEach, describe, expect, it, vi } from 'vitest';

const MOCK_HOME = 'C:/Users/TestUser';

async function importWithMocks(options: {
  tokenExists?: boolean;
  regExists?: boolean;
  tokenData?: Record<string, unknown>;
  regData?: Record<string, unknown>;
}) {
  vi.resetModules();
  vi.doMock('node:os', () => ({ homedir: () => MOCK_HOME }));
  vi.doMock('node:fs', () => ({
    existsSync: vi.fn((path: string) => {
      if (path.endsWith('kiro-auth-token.json')) return options.tokenExists ?? true;
      if (path.endsWith('.json')) return options.regExists ?? true;
      return false;
    }),
    readFileSync: vi.fn((path: string) => {
      if (path.endsWith('kiro-auth-token.json')) {
        return JSON.stringify(
          options.tokenData ?? {
            accessToken: 'at',
            refreshToken: 'rt',
            expiresAt: new Date(Date.now() + 3600_000).toISOString(),
            region: 'us-east-1',
            clientIdHash: 'hash',
            authMethod: 'IdC',
          },
        );
      }
      return JSON.stringify(options.regData ?? { clientId: 'cid', clientSecret: 'csec' });
    }),
  }));
  return import('../src/kiro-ide.js');
}

afterEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});

describe('Feature X: Kiro IDE Credential Fallback', () => {
  it('reads valid IDC credentials from the Kiro IDE token cache', async () => {
    const mod = await importWithMocks({});
    const creds = mod.getKiroIdeCredentials();
    expect(creds?.access).toBe('at');
    expect(creds?.refresh).toBe('rt|cid|csec|idc');
    expect(creds?.authMethod).toBe('idc');
  });

  it('reads valid desktop credentials without client registration', async () => {
    const mod = await importWithMocks({
      regExists: false,
      tokenData: {
        accessToken: 'at',
        refreshToken: 'rt',
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        region: 'eu-central-1',
        authMethod: 'desktop',
      },
    });
    const creds = mod.getKiroIdeCredentials();
    expect(creds?.refresh).toBe('rt|desktop');
    expect(creds?.authMethod).toBe('desktop');
    expect(creds?.region).toBe('eu-central-1');
  });

  it('returns undefined for expired credentials in strict mode', async () => {
    const mod = await importWithMocks({
      tokenData: {
        accessToken: 'at',
        refreshToken: 'rt',
        expiresAt: new Date(Date.now() - 1000).toISOString(),
        authMethod: 'IdC',
        clientIdHash: 'hash',
      },
    });
    expect(mod.getKiroIdeCredentials()).toBeUndefined();
    expect(mod.getKiroIdeCredentialsAllowExpired()?.refresh).toBe('rt|cid|csec|idc');
  });
});
