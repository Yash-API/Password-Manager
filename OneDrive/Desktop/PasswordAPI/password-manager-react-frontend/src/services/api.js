import axios from 'axios';

const API_URL = 'http://localhost:8000';

// Create axios instance with enhanced configuration
const axiosInstance = axios.create({
  baseURL: API_URL,
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
  },
  withCredentials: false  // Changed to false since we're allowing all origins
});

// Add request interceptor for debugging
axiosInstance.interceptors.request.use(
  (config) => {
    console.log('Making request to:', config.url);
    const token = localStorage.getItem('token');
    if (token && !config.url.includes('/token')) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    console.error('Request error:', error);
    return Promise.reject(error);
  }
);

// Add response interceptor for debugging
axiosInstance.interceptors.response.use(
  (response) => {
    console.log('Response received:', response.status);
    return response;
  },
  (error) => {
    console.error('Response error:', error);
    if (error.response) {
      console.error('Error details:', error.response.data);
    }
    return Promise.reject(error);
  }
);

// Authentication service
export const authService = {
  // Login user
  async login(email, password) {
    try {
      console.log('Attempting login for:', email);
      const formData = new URLSearchParams();
      formData.append('username', email);
      formData.append('password', password);
      
      const response = await axios.post(`${API_URL}/token`, formData, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json'
        },
        withCredentials: false
      });
      
      console.log('Login response:', response.data);
      
      if (response.data.access_token) {
        localStorage.setItem('token', response.data.access_token);
        return { success: true };
      } else {
        throw new Error('No access token received');
      }
    } catch (error) {
      console.error('Login error:', error);
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to login');
      } else if (error.request) {
        throw new Error('Network error - no response received');
      } else {
        throw new Error('Error setting up request');
      }
    }
  },

  // Register user
  async register(email, password ) {
    try {
      // Change to query parameters format which FastAPI will accept
      const response = await axiosInstance.post('/register/', null, {
        params: { email, password }
      });
      
      return response.data;
    } catch (error) {
      console.error('Registration error:', error);
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to register');
      } else {
        throw new Error(error.message || 'Network error');
      }
    }
  },

  // Logout user
  logout() {
    localStorage.removeItem('token');
    return { success: true };
  },

  // Check if user is logged in
  isLoggedIn() {
    const token = localStorage.getItem('token');
    if (!token) {
      console.log('isLoggedIn: No token found');
      return false;
    }
    
    try {
      // Verify token is valid by parsing it
      const payload = JSON.parse(atob(token.split('.')[1]));
      
      // Check if token has expired
      const currentTime = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < currentTime) {
        console.log('isLoggedIn: Token expired');
        localStorage.removeItem('token'); // Remove expired token
        return false;
      }
      
      console.log('isLoggedIn: Valid token found for user', payload.sub);
      return true;
    } catch (error) {
      console.error('isLoggedIn: Error parsing token', error);
      localStorage.removeItem('token'); // Remove invalid token
      return false;
    }
  },

  // Check if user is admin
  isAdmin() {
    const userInfo = this.getUserInfo();
    return userInfo && userInfo.role === 'master';
  },

  // Get user info from token
  getUserInfo() {
    const token = localStorage.getItem('token');
    if (!token) {
      console.log('getUserInfo: No token found');
      return null;
    }
    
    try {
      // Parse JWT payload (second part of token)
      const payload = JSON.parse(atob(token.split('.')[1]));
      
      // Check if token has expired
      const currentTime = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < currentTime) {
        console.log('getUserInfo: Token expired');
        localStorage.removeItem('token'); // Remove expired token
        return null;
      }
      
      console.log('getUserInfo: Retrieved user info for', payload.sub, 'with role', payload.role);
      return payload;
    } catch (error) {
      console.error('getUserInfo: Error parsing token', error);
      localStorage.removeItem('token'); // Remove invalid token
      return null;
    }
  }
};

// Password service
export const passwordService = {
  // Get user passwords
  async getUserPasswords() {
    try {
      const response = await axiosInstance.get('/get-user-passwords/');
      return response.data;
    } catch (error) {
      console.error('Get passwords error:', error);
      
      if (error.response && error.response.status === 401) {
        // Token expired or invalid
        authService.logout();
        throw new Error('Session expired. Please login again.');
      }
      
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to get passwords');
      } else {
        throw new Error(error.message || 'Network error');
      }
    }
  },

  // Add website password
  async addWebsitePassword(website, password) {
    try {
      // Change to query parameters format which FastAPI will accept
      const response = await axiosInstance.post('/add-websites-passwords/', null, {
        params: { website, hashed_password: password }
      });
      
      return response.data;
    } catch (error) {
      console.error('Add password error:', error);
      
      if (error.response && error.response.status === 401) {
        // Token expired or invalid
        authService.logout();
        throw new Error('Session expired. Please login again.');
      }
      
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to add password');
      } else {
        throw new Error(error.message || 'Network error');
      }
    }
  },

  // Update user password
  async updatePassword(email, newPassword, userSpecificId) {
    try {
      console.log('Updating password with params:', { 
        email, 
        new_password: newPassword,
        user_specific_id: userSpecificId 
      });
      
      // Add userSpecificId to params
      const response = await axiosInstance.put('/update-password/', null, {
        params: { 
          email, 
          new_password: newPassword,
          user_specific_id: userSpecificId 
        }
      });
      
      console.log('Password update response:', response.data);
      
      // Store the actual updated password in the response for direct use
      return { 
        success: true, 
        message: response.data.message,
        updatedPassword: newPassword // Include the new password in the response
      };
    } catch (error) {
      console.error('Update password error:', error);
      
      if (error.response && error.response.status === 401) {
        // Token expired or invalid
        authService.logout();
        throw new Error('Session expired. Please login again.');
      }
      
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to update password');
      } else {
        throw new Error(error.message || 'Network error');
      }
    }
  },

  // Delete password
  async deletePassword(userSpecificId) {
    try {
      const response = await axiosInstance.delete(`/delete-password-entry/${userSpecificId}`);
      return { success: true, message: response.data.message };
    } catch (error) {
      console.error('Delete password error:', error);
      
      if (error.response && error.response.status === 401) {
        // Token expired or invalid
        authService.logout();
        throw new Error('Session expired. Please login again.');
      }
      
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to delete password');
      } else {
        throw new Error(error.message || 'Network error');
      }
    }
  },

  // Update user website password
  async updateWebsitePassword(website, newPassword) {
    try {
      console.log('Updating website password with params:', { 
        website,
        new_password: newPassword
      });
      
      const response = await axiosInstance.put('/update-website-password/', null, {
        params: { 
          website, 
          new_password: newPassword
        }
      });
      
      console.log('Website password update response:', response.data);
      
      return { 
        success: true, 
        message: response.data.message,
        updatedPassword: newPassword // Include the new password in the response
      };
    } catch (error) {
      console.error('Update website password error:', error);
      
      if (error.response && error.response.status === 401) {
        // Token expired or invalid
        authService.logout();
        throw new Error('Session expired. Please login again.');
      }
      
      if (error.response && error.response.status === 404) {
        throw new Error(error.response.data.detail || 'Website not found');
      }
      
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to update password');
      } else {
        throw new Error(error.message || 'Network error');
      }
    }
  }
};

// Admin service
export const adminService = {
  // Get all users
  async getAllUsers() {
    try {
      const response = await axiosInstance.get('/get-all-users/');
      return response.data;
    } catch (error) {
      console.error('Get all users error:', error);
      
      if (error.response && error.response.status === 401) {
        // Token expired or invalid
        authService.logout();
        throw new Error('Session expired. Please login again.');
      }
      
      if (error.response && error.response.status === 403) {
        throw new Error('Access denied. Admin only.');
      }
      
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to get users');
      } else {
        throw new Error(error.message || 'Network error');
      }
    }
  },

  // Add user
  async addUser(email, password, role) {
    try {
      // Change to query parameters format which FastAPI will accept
      const response = await axiosInstance.post('/admin/', null, {
        params: { 
          email,
          hashed_password: password, 
          role 
        }
      });
      
      return response.data;
    } catch (error) {
      console.error('Add user error:', error);
      
      if (error.response && error.response.status === 401) {
        // Token expired or invalid
        authService.logout();
        throw new Error('Session expired. Please login again.');
      }
      
      if (error.response && error.response.status === 403) {
        throw new Error('Access denied. Admin only.');
      }
      
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to add user');
      } else {
        throw new Error(error.message || 'Network error');
      }
    }
  },

  // Delete user
  async deleteUser(email) {
    try {
      const response = await axiosInstance.delete(`/admin/delete-user/${email}`);
      return response.data;
    } catch (error) {
      console.error('Delete user error:', error);
      
      if (error.response && error.response.status === 401) {
        // Token expired or invalid
        authService.logout();
        throw new Error('Session expired. Please login again.');
      }
      
      if (error.response && error.response.status === 403) {
        throw new Error('Access denied. Admin only.');
      }
      
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to delete user');
      } else {
        throw new Error(error.message || 'Network error');
      }
    }
  },

  // Create master user
  async createMasterUser(email, password) {
    try {
      // Change to query parameters format which FastAPI will accept
      const response = await axiosInstance.post('/admin/create-master/', null, {
        params: { email, password }
      });
      
      return response.data;
    } catch (error) {
      console.error('Create master user error:', error);
      
      if (error.response && error.response.status === 401) {
        // Token expired or invalid
        authService.logout();
        throw new Error('Session expired. Please login again.');
      }
      
      if (error.response && error.response.status === 403) {
        throw new Error('Access denied. Admin only.');
      }
      
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to create master user');
      } else {
        throw new Error(error.message || 'Network error');
      }
    }
  },

  // Update user role
  async updateUserRole(email, newRole) {
    try {
      const response = await axiosInstance.put('/update-user-role/', null, {
        params: { email, new_role: newRole }
      });
      
      if (response.status === 200) {
        return { message: 'User role updated successfully' };
      } else {
        throw new Error('Failed to update user role');
      }
    } catch (error) {
      console.error('Update user role error:', error);
      
      if (error.response && error.response.status === 401) {
        // Token expired or invalid
        authService.logout();
        throw new Error('Session expired. Please login again.');
      }
      
      if (error.response && error.response.status === 403) {
        throw new Error('Access denied. Admin only.');
      }
      
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to update user role');
      } else {
        throw new Error(error.message || 'Network error');
      }
    }
  },
  
  // Update user's website password (for admin)
  async updateUserWebsitePassword(email, website, newPassword) {
    try {
      console.log('Admin updating password with params:', { 
        email, 
        website,
        new_password: newPassword
      });
      
      const response = await axiosInstance.put('/admin/update-user-password/', null, {
        params: { 
          email, 
          website,
          new_password: newPassword
        }
      });
      
      console.log('Admin password update response:', response.data);
      
      return { 
        success: true, 
        message: response.data.message,
        updatedPassword: newPassword // Include the new password in the response
      };
    } catch (error) {
      console.error('Admin update password error:', error);
      
      if (error.response && error.response.status === 401) {
        // Token expired or invalid
        authService.logout();
        throw new Error('Session expired. Please login again.');
      }
      
      if (error.response && error.response.status === 403) {
        throw new Error('Access denied. Admin only.');
      }
      
      if (error.response && error.response.status === 404) {
        throw new Error(error.response.data.detail || 'User or website not found');
      }
      
      if (error.response) {
        throw new Error(error.response.data.detail || 'Failed to update password');
      } else {
        throw new Error(error.message || 'Network error');
      }
    }
  }
};

// Create named object before exporting
const apiServices = {
  auth: authService,
  password: passwordService,
  admin: adminService
};

export default apiServices; 