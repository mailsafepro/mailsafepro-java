import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  ReactNode,
  FC
} from 'react';
import api from '../services/api';

interface AuthContextType {
  isAuthenticated: boolean;
  userPlan: string;
  nextBillingDate: string;
  isLoading: boolean;
  userEmail: string | null;
  apiKey: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUserData: () => Promise<void>;
  setApiKey: (apiKey: string) => void;
  updateTokens: (accessToken: string, refreshToken: string, plan?: string) => void; // ✅ NUEVO
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: FC<{ children: ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return sessionStorage.getItem('token') !== null;
  });

  const [userPlan, setUserPlan] = useState('FREE');
  const [nextBillingDate, setNextBillingDate] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [userEmail, setUserEmail] = useState(() => {
    return sessionStorage.getItem('user_email');
  });

  const [apiKey, setApiKeyState] = useState(() => {
    return sessionStorage.getItem('api_key');
  });

  const fetchUserData = async () => {
    try {
      const token = sessionStorage.getItem('token');
      if (!token) return;

      // Obtener información del usuario
      const response = await api.get('/auth/me');

      // Guardar información del usuario
      sessionStorage.setItem('user_plan', response.data.plan);
      sessionStorage.setItem('user_email', response.data.email);
      setUserPlan(response.data.plan);
      setUserEmail(response.data.email);
      setNextBillingDate(response.data.next_billing_date || '');
    } catch (error) {
      console.error('Error fetching user data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isAuthenticated) {
      fetchUserData();
    } else {
      setIsLoading(false);
    }
  }, [isAuthenticated]);

  const setApiKey = (key: string) => {
    sessionStorage.setItem('api_key', key);
    setApiKeyState(key);
  };

  // ✅ NUEVO: Actualizar tokens y plan
  const updateTokens = (accessToken: string, refreshToken: string, plan?: string) => {
    sessionStorage.setItem('token', accessToken);
    sessionStorage.setItem('refresh_token', refreshToken);
    
    if (plan) {
      sessionStorage.setItem('user_plan', plan);
      setUserPlan(plan);
    }
    
    setIsAuthenticated(true);
    console.log('✅ Tokens actualizados con plan:', plan || 'actual');
    
    // ✅ IMPORTANTE: Actualizar la cabecera del API para usar el nuevo token
    api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
  };


  const login = async (email: string, password: string) => {
    try {
      const response = await api.post('/auth/login', {
        email,
        password
      });

      const { access_token, refresh_token, api_key, plan } = response.data;

      // Almacenar tokens
      sessionStorage.setItem('token', access_token);
      sessionStorage.setItem('refresh_token', refresh_token);
      sessionStorage.setItem('user_email', email);
      sessionStorage.setItem('user_plan', plan || 'FREE');

      // Almacenar API Key si está presente en la respuesta
      if (api_key && api_key !== '***') {
        sessionStorage.setItem('api_key', api_key);
        setApiKeyState(api_key);
      } else {
        // Si no se recibe la API Key, intentar obtenerla de sessionStorage
        const storedApiKey = sessionStorage.getItem('api_key');
        if (storedApiKey) {
          setApiKeyState(storedApiKey);
        }
      }

      setUserEmail(email);
      setUserPlan(plan || 'FREE');
      setIsAuthenticated(true);
      await fetchUserData();
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    }
  };

  const logout = async () => {
    try {
      const token = sessionStorage.getItem("token");
      const refreshToken = sessionStorage.getItem("refresh_token");

      if (token && refreshToken) {
        try {
          await api.post('/auth/logout', { refresh_token: refreshToken }, {
            headers: { Authorization: `Bearer ${token}` }
          });
        } catch (error) {
          console.warn('Logout warning:', error);
        }
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Limpiar sessionStorage
      sessionStorage.removeItem("token");
      sessionStorage.removeItem("refresh_token");
      sessionStorage.removeItem("api_key");
      sessionStorage.removeItem("user_plan");
      sessionStorage.removeItem("user_email");

      // Resetear estado
      setApiKeyState(null);
      setUserEmail(null);
      setIsAuthenticated(false);
      setUserPlan('FREE');
      setNextBillingDate('');
    }
  };

  const refreshUserData = async () => {
    setIsLoading(true);
    await fetchUserData();
  };

  const value: AuthContextType = {
    isAuthenticated,
    userPlan,
    nextBillingDate,
    isLoading,
    userEmail,
    apiKey,
    login,
    logout,
    refreshUserData,
    setApiKey,
    updateTokens // ✅ NUEVO
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;
