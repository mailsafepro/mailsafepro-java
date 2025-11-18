// src/services/api.ts
import axios from "axios";

// Crear instancia de axios
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Interceptor para añadir token a las solicitudes
api.interceptors.request.use(config => {
  const token = sessionStorage.getItem("token");
  
  if (token) {
    config.headers["Authorization"] = `Bearer ${token}`;
  }
  
  return config;
});

// Interceptor para manejar errores y refrescar tokens
let isRefreshing = false;
let refreshQueue: { resolve: (value?: any) => void; reject: (reason?: any) => void }[] = [];

api.interceptors.response.use(
  response => response,
  async (error) => {
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      if (originalRequest.url.includes('/auth/refresh')) {
        // Manejar error de refresh recursivo
        sessionStorage.removeItem("token");
        sessionStorage.removeItem("refresh_token");
        sessionStorage.removeItem("user_email");
        window.location.href = "/login";
        return Promise.reject(error);
      }
      
      if (!isRefreshing) {
        isRefreshing = true;
        originalRequest._retry = true;
        const refreshToken = sessionStorage.getItem("refresh_token");
        
        if (!refreshToken) {
          sessionStorage.removeItem("token");
          sessionStorage.removeItem("user_email");
          window.location.href = "/login";
          return Promise.reject(error);
        }
        
        try {
          const response = await axios.post(
            `${import.meta.env.VITE_API_BASE_URL}/auth/refresh`,
            { refresh_token: refreshToken }
          );
          
          // Actualizar tokens
          sessionStorage.setItem("token", response.data.access_token);
          sessionStorage.setItem("refresh_token", response.data.refresh_token);
          
          // Actualizar header para la solicitud original
          api.defaults.headers.common['Authorization'] = `Bearer ${response.data.access_token}`;
          originalRequest.headers.Authorization = `Bearer ${response.data.access_token}`;
          
          // Reintentar solicitudes en cola
          refreshQueue.forEach(({ resolve }) => resolve());
          
          // Reintentar solicitud original
          return api(originalRequest);
        } catch (refreshError) {
          // Manejar error de refresh
          refreshQueue.forEach(({ reject }) => reject(refreshError));
          sessionStorage.removeItem("token");
          sessionStorage.removeItem("refresh_token");
          sessionStorage.removeItem("user_email");
          window.location.href = "/login";
          return Promise.reject(refreshError);
        } finally {
          isRefreshing = false;
          refreshQueue = [];
        }
      }
      
      // Encolar solicitudes mientras se refresca
      return new Promise((resolve, reject) => {
        refreshQueue.push({ resolve, reject });
      }).then(() => {
        originalRequest.headers.Authorization = `Bearer ${sessionStorage.getItem("token")}`;
        return api(originalRequest);
      });
    }
    
    return Promise.reject(error);
  }
);

export default api;