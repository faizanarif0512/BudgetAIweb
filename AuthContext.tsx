import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8001/api';

interface User {
  user_id: string;
  email: string;
  name: string;
  picture?: string;
  monthly_income_range?: string;
  spending_priorities?: string[];
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  sessionToken: string | null;
  login: () => void;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const processSessionId = async (sessionId: string) => {
    try {
      const response = await axios.post(`${API_URL}/auth/session`, null, {
        headers: { 'X-Session-ID': sessionId },
      });

      const data = response.data;
      localStorage.setItem('session_token', data.session_token);
      setSessionToken(data.session_token);
      setUser({
        user_id: data.user_id,
        email: data.email,
        name: data.name,
        picture: data.picture,
      });

      return true;
    } catch (error) {
      console.error('Session processing error:', error);
      return false;
    }
  };

  const checkSession = async () => {
    try {
      const token = localStorage.getItem('session_token');
      if (!token) {
        setLoading(false);
        return;
      }

      const response = await axios.get(`${API_URL}/auth/me`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });

      if (response.status === 200) {
        setUser(response.data);
        setSessionToken(token);
      } else {
        localStorage.removeItem('session_token');
      }
    } catch (error) {
      localStorage.removeItem('session_token');
    } finally {
      setLoading(false);
    }
  };

  const refreshUser = async () => {
    try {
      const token = sessionToken || localStorage.getItem('session_token');
      if (!token) return;

      const response = await axios.get(`${API_URL}/auth/me`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });

      if (response.status === 200) {
        setUser(response.data);
      }
    } catch (error) {
      console.error('Refresh user error:', error);
    }
  };

  const login = () => {
    const redirectUrl = window.location.origin;
    const authUrl = `https://auth.emergentagent.com/?redirect=${encodeURIComponent(redirectUrl)}`;
    window.location.href = authUrl;
  };

  const logout = async () => {
    try {
      const token = sessionToken || localStorage.getItem('session_token');
      if (token) {
        await axios.post(`${API_URL}/auth/logout`, null, {
          headers: { 'Authorization': `Bearer ${token}` },
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('session_token');
      setUser(null);
      setSessionToken(null);
    }
  };

  useEffect(() => {
    const init = async () => {
      const url = window.location.href;
      const hasSessionId = url.includes('session_id=');

      if (hasSessionId) {
        setLoading(true);
        const sessionIdMatch = url.match(/[#?&]session_id=([^&]+)/);
        if (sessionIdMatch) {
          const success = await processSessionId(sessionIdMatch[1]);
          if (success) {
            window.history.replaceState({}, document.title, window.location.pathname);
          }
        }
        setLoading(false);
        return;
      }

      await checkSession();
    };

    init();
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, sessionToken, login, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
};
