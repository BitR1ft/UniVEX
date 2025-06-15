import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';

interface User {
  id: string;
  username: string;
  email: string;
}

interface AuthState {
  // NOTE: 'token' is intentionally removed from state.
  // Tokens are now stored exclusively in httpOnly cookies set by the backend —
  // they are never accessible to JavaScript and therefore cannot be stolen via XSS.
  user: User | null;
  isAuthenticated: boolean;

  setUser: (user: User | null) => void;
  // Kept for backward-compat call sites — now a no-op since tokens are in cookies
  setToken: (token: string | null) => void;
  login: (user: User) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,

      setUser: (user) =>
        set({
          user,
          isAuthenticated: !!user,
        }),

      // No-op: token is now managed by httpOnly cookies, not by JS state
      setToken: (_token) => {
        // Intentionally empty. Token is stored in httpOnly cookie by the backend.
      },

      login: (user) =>
        set({
          user,
          isAuthenticated: true,
        }),

      logout: () =>
        set({
          user: null,
          isAuthenticated: false,
        }),
    }),
    {
      // Only persist non-sensitive user info (id, username, email).
      // The actual auth token lives in an httpOnly cookie and never touches
      // localStorage or Zustand state.
      name: 'auth-storage',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);
