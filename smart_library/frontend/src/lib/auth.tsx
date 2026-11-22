import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, getToken, setToken, setUnauthorizedHandler, type Me } from "./api";

interface AuthState {
  token: string | null;
  me: Me | undefined;
  loading: boolean;
  signIn: (memberId: string) => Promise<Me>;
  signOut: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setTok] = useState<string | null>(() => getToken());
  const qc = useQueryClient();

  const meQuery = useQuery({
    queryKey: ["me", token],
    queryFn: () => api<Me>("/me"),
    enabled: !!token,
    staleTime: 30_000,
  });

  const signOut = useCallback(() => {
    setToken(null);
    setTok(null);
    qc.clear();
  }, [qc]);

  useEffect(() => {
    setUnauthorizedHandler(signOut);
  }, [signOut]);

  const signIn = useCallback(
    async (memberId: string) => {
      const { access_token } = await api<{ access_token: string }>("/auth/demo-login", {
        method: "POST",
        json: { member_id: memberId },
      });
      qc.clear();
      setToken(access_token);
      setTok(access_token);
      const me = await api<Me>("/me");
      qc.setQueryData(["me", access_token], me);
      return me;
    },
    [qc],
  );

  const value = useMemo<AuthState>(
    () => ({ token, me: meQuery.data, loading: !!token && meQuery.isLoading, signIn, signOut }),
    [token, meQuery.data, meQuery.isLoading, signIn, signOut],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}
