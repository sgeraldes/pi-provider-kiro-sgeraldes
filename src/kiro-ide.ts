// ABOUTME: Reads credentials from Kiro IDE token files as a Windows-friendly auth fallback.
// ABOUTME: Supports valid-token lookup and allow-expired lookup for silent refresh.

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { KiroAuthMethod, KiroCredentials } from './oauth.js';

const SSO_CACHE_DIR = join(homedir(), '.aws', 'sso', 'cache');
const KIRO_TOKEN_PATH = join(SSO_CACHE_DIR, 'kiro-auth-token.json');

interface KiroIdeTokenFileData {
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
  region?: string;
  clientIdHash?: string;
  authMethod?: string;
}

interface KiroIdeClientRegistration {
  clientId?: string;
  clientSecret?: string;
}

function readIdeToken(): KiroIdeTokenFileData | undefined {
  try {
    if (!existsSync(KIRO_TOKEN_PATH)) return undefined;
    return JSON.parse(readFileSync(KIRO_TOKEN_PATH, 'utf-8')) as KiroIdeTokenFileData;
  } catch {
    return undefined;
  }
}

function readClientRegistration(clientIdHash: string | undefined): KiroIdeClientRegistration | undefined {
  if (!clientIdHash) return undefined;
  try {
    const regPath = join(SSO_CACHE_DIR, `${clientIdHash}.json`);
    if (!existsSync(regPath)) return undefined;
    return JSON.parse(readFileSync(regPath, 'utf-8')) as KiroIdeClientRegistration;
  } catch {
    return undefined;
  }
}

function toCredentials(token: KiroIdeTokenFileData): KiroCredentials | undefined {
  if (!token.accessToken || !token.refreshToken) return undefined;
  const expiresAt = new Date(token.expiresAt).getTime();
  if (!Number.isFinite(expiresAt)) return undefined;

  const authMethod: KiroAuthMethod = token.authMethod === 'IdC' ? 'idc' : 'desktop';
  const region = token.region ?? 'us-east-1';
  const reg = readClientRegistration(token.clientIdHash);
  const clientId = reg?.clientId ?? '';
  const clientSecret = reg?.clientSecret ?? '';

  return {
    refresh:
      authMethod === 'desktop'
        ? `${token.refreshToken}|desktop`
        : `${token.refreshToken}|${clientId}|${clientSecret}|idc`,
    access: token.accessToken,
    expires: expiresAt - 2 * 60 * 1000,
    clientId,
    clientSecret,
    region,
    authMethod,
  };
}

export function getKiroIdeCredentialsAllowExpired(): KiroCredentials | undefined {
  const token = readIdeToken();
  if (!token) return undefined;
  return toCredentials(token);
}

export function getKiroIdeCredentials(): KiroCredentials | undefined {
  const creds = getKiroIdeCredentialsAllowExpired();
  if (!creds) return undefined;
  if (Date.now() >= creds.expires) return undefined;
  return creds;
}
