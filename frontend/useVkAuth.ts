/**
 * VK Auth Extension - useVkAuth Hook
 *
 * React hook for VK OAuth authentication with PKCE.
 */
import { useState, useCallback, useEffect, useRef } from "react";

// =============================================================================
// TYPES
// =============================================================================

const REFRESH_TOKEN_KEY = "vk_auth_refresh_token";
const CODE_VERIFIER_KEY = "vk_auth_code_verifier";
const STATE_KEY = "vk_auth_state";

export interface User {
  id: number;
  email: string | null;
  name: string | null;
  avatar_url: string | null;
  vk_id: string;
}

interface AuthApiUrls {
  authUrl: string;
  callback: string;
  refresh: string;
  logout: string;
}

interface UseVkAuthOptions {
  apiUrls: AuthApiUrls;
  onAuthChange?: (user: User | null) => void;
  autoRefresh?: boolean;
  refreshBeforeExpiry?: number;
}

interface UseVkAuthReturn {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  accessToken: string | null;
  login: () => Promise<void>;
  handleCallback: (urlParams?: URLSearchParams) => Promise<boolean>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<boolean>;
  getAuthHeader: () => { Authorization: string } | {};
}

// =============================================================================
// LOCAL STORAGE
// =============================================================================

function getStoredRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

function setStoredRefreshToken(token: string): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(REFRESH_TOKEN_KEY, token);
}

function clearStoredRefreshToken(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(REFRESH_TOKEN_KEY);
}

function getStoredCodeVerifier(): string | null {
  if (typeof window === "undefined") return null;
  return sessionStorage.getItem(CODE_VERIFIER_KEY);
}

function setStoredCodeVerifier(verifier: string): void {
  if (typeof window === "undefined") return;
  sessionStorage.setItem(CODE_VERIFIER_KEY, verifier);
}

function clearStoredCodeVerifier(): void {
  if (typeof window === "undefined") return;
  sessionStorage.removeItem(CODE_VERIFIER_KEY);
}

function setStoredState(state: string): void {
  if (typeof window === "undefined") return;
  sessionStorage.setItem(STATE_KEY, state);
}

function getStoredState(): string | null {
  if (typeof window === "undefined") return null;
  return sessionStorage.getItem(STATE_KEY);
}

function clearStoredState(): void {
  if (typeof window === "undefined") return;
  sessionStorage.removeItem(STATE_KEY);
}

// =============================================================================
// HOOK
// =============================================================================

export function useVkAuth(options: UseVkAuthOptions): UseVkAuthReturn {
  const {
    apiUrls,
    onAuthChange,
    autoRefresh = true,
    refreshBeforeExpiry = 60,
  } = options;

  const [user, setUser] = useState<User | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearAuth = useCallback(() => {
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
    }
    setAccessToken(null);
    setUser(null);
    clearStoredRefreshToken();
    clearStoredCodeVerifier();
    clearStoredState();
  }, []);

  const scheduleRefresh = useCallback(
    (expiresInSeconds: number, refreshFn: () => Promise<boolean>) => {
      if (!autoRefresh) return;

      if (refreshTimerRef.current) {
        clearTimeout(refreshTimerRef.current);
      }

      const refreshIn = Math.max((expiresInSeconds - refreshBeforeExpiry) * 1000, 1000);

      refreshTimerRef.current = setTimeout(async () => {
        const success = await refreshFn();
        if (!success) {
          clearAuth();
        }
      }, refreshIn);
    },
    [autoRefresh, refreshBeforeExpiry, clearAuth]
  );

  const refreshTokenFn = useCallback(async (): Promise<boolean> => {
    const storedRefreshToken = getStoredRefreshToken();
    if (!storedRefreshToken) {
      return false;
    }

    try {
      const response = await fetch(apiUrls.refresh, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: storedRefreshToken }),
      });

      if (!response.ok) {
        clearAuth();
        return false;
      }

      const data = await response.json();
      setAccessToken(data.access_token);
      setUser(data.user);
      scheduleRefresh(data.expires_in, refreshTokenFn);
      return true;
    } catch {
      clearAuth();
      return false;
    }
  }, [apiUrls.refresh, clearAuth, scheduleRefresh]);

  // Restore session on mount
  useEffect(() => {
    const restoreSession = async () => {
      const hasToken = !!getStoredRefreshToken();
      if (hasToken) {
        await refreshTokenFn();
      }
      setIsLoading(false);
    };

    restoreSession();

    return () => {
      if (refreshTimerRef.current) {
        clearTimeout(refreshTimerRef.current);
      }
    };
  }, [refreshTokenFn]);

  // Notify on auth change
  useEffect(() => {
    onAuthChange?.(user);
  }, [user, onAuthChange]);

  /**
   * Start VK login flow - redirects to VK
   */
  const login = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(apiUrls.authUrl, {
        method: "GET",
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || "Failed to get auth URL");
        setIsLoading(false);
        return;
      }

      // Store state and code_verifier for callback
      if (typeof window !== "undefined") {
        if (data.state) {
          setStoredState(data.state);
        }
        if (data.code_verifier) {
          setStoredCodeVerifier(data.code_verifier);
        }
      }

      // Redirect to VK (keep loading state, page will navigate away)
      window.location.href = data.auth_url;
    } catch (err) {
      setError("Network error");
      setIsLoading(false);
    }
  }, [apiUrls.authUrl]);

  /**
   * Handle OAuth callback - exchange code for tokens
   * @param urlParams - Optional URLSearchParams, defaults to current URL
   */
  const handleCallback = useCallback(
    async (urlParams?: URLSearchParams): Promise<boolean> => {
      setIsLoading(true);
      setError(null);

      try {
        // Get params from URL or provided params
        const params = urlParams || new URLSearchParams(window.location.search);
        const code = params.get("code");
        const device_id = params.get("device_id");
        const state = params.get("state");

        if (!code) {
          setError("No authorization code received");
          return false;
        }

        // Verify state for CSRF protection
        const storedState = getStoredState();
        if (storedState && state !== storedState) {
          setError("Invalid state parameter");
          return false;
        }

        // Get stored code_verifier
        const code_verifier = getStoredCodeVerifier();
        if (!code_verifier) {
          setError("No code verifier found. Please try logging in again.");
          return false;
        }

        const response = await fetch(apiUrls.callback, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            code,
            code_verifier,
            device_id: device_id || "",
          }),
        });

        const data = await response.json();

        if (!response.ok) {
          setError(data.error || "Authentication failed");
          return false;
        }

        // Clear temporary storage
        clearStoredCodeVerifier();
        clearStoredState();

        // Set auth data
        setAccessToken(data.access_token);
        setUser(data.user);
        setStoredRefreshToken(data.refresh_token);
        scheduleRefresh(data.expires_in, refreshTokenFn);
        return true;
      } catch (err) {
        setError("Network error");
        return false;
      } finally {
        setIsLoading(false);
      }
    },
    [apiUrls.callback, scheduleRefresh, refreshTokenFn]
  );

  /**
   * Logout user
   */
  const logout = useCallback(async () => {
    const storedRefreshToken = getStoredRefreshToken();

    try {
      await fetch(apiUrls.logout, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: storedRefreshToken || "" }),
      });
    } catch {
      // Ignore errors
    }

    clearAuth();
  }, [apiUrls.logout, clearAuth]);

  /**
   * Get Authorization header for API requests
   */
  const getAuthHeader = useCallback(() => {
    if (!accessToken) return {};
    return { Authorization: `Bearer ${accessToken}` };
  }, [accessToken]);

  return {
    user,
    isAuthenticated: !!user && !!accessToken,
    isLoading,
    error,
    accessToken,
    login,
    handleCallback,
    logout,
    refreshToken: refreshTokenFn,
    getAuthHeader,
  };
}

export default useVkAuth;
