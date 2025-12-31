/**
 * VK Auth Extension - useVkAuth Hook
 *
 * React hook for VK OAuth authentication.
 */
import { useState, useCallback, useEffect, useRef } from "react";

// =============================================================================
// TYPES
// =============================================================================

const REFRESH_TOKEN_KEY = "vk_auth_refresh_token";

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
  handleCallback: (code: string) => Promise<boolean>;
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
    setError(null);

    try {
      const response = await fetch(apiUrls.authUrl, {
        method: "GET",
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || "Failed to get auth URL");
        return;
      }

      // Store state for CSRF verification
      if (typeof window !== "undefined" && data.state) {
        sessionStorage.setItem("vk_auth_state", data.state);
      }

      // Redirect to VK
      window.location.href = data.auth_url;
    } catch (err) {
      setError("Network error");
    }
  }, [apiUrls.authUrl]);

  /**
   * Handle OAuth callback - exchange code for tokens
   */
  const handleCallback = useCallback(
    async (code: string): Promise<boolean> => {
      setIsLoading(true);
      setError(null);

      try {
        const response = await fetch(apiUrls.callback, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code }),
        });

        const data = await response.json();

        if (!response.ok) {
          setError(data.error || "Authentication failed");
          return false;
        }

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
