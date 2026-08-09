import { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';
import { API_URL } from '../config';

const API = API_URL;
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('soar_token'));
  const [loading, setLoading] = useState(true);

  // Configure axios defaults
  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    } else {
      delete axios.defaults.headers.common['Authorization'];
    }
  }, [token]);

  // Check token on mount
  useEffect(() => {
    const checkAuth = async () => {
      if (!token) { setLoading(false); return; }
      try {
        const res = await axios.get(`${API}/auth/me`);
        setUser(res.data.user);
      } catch {
        logout();
      }
      setLoading(false);
    };
    checkAuth();
  }, []);

  const login = async (username, password) => {
    const res = await axios.post(`${API}/auth/login`, { username, password });
    const { token: newToken, user: userData } = res.data;
    localStorage.setItem('soar_token', newToken);
    setToken(newToken);
    setUser(userData);
    axios.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
    return userData;
  };

  const logout = () => {
    localStorage.removeItem('soar_token');
    setToken(null);
    setUser(null);
    delete axios.defaults.headers.common['Authorization'];
  };

  const updateUser = (updatedUser) => {
    setUser(prev => ({ ...prev, ...updatedUser }));
  };

  return (
    <AuthContext.Provider value={{ 
      user, token, loading, login, logout, updateUser,
      isAnalyst: user?.role === 'analyst' 
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
export default AuthContext;
