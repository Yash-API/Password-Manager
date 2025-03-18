import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { authService } from '../services/api';
import '../styles/Auth.css';

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Clear any existing tokens on component mount
    if (authService.isLoggedIn()) {
      authService.logout();
    }
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!email || !password) {
      setError('Please enter both email and password');
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      console.log('Attempting login for:', email);
      const result = await authService.login(email, password);
      
      if (result.success) {
        setSuccess('Login successful! Redirecting...');
        
        // Force token check and get user role
        const isAdmin = authService.isAdmin();
        const redirectPath = isAdmin ? '/admin' : '/dashboard';
        console.log('Login successful, redirecting to:', redirectPath);
        
        // Immediate redirect
        window.location.href = redirectPath;
      }
    } catch (err) {
      console.error('Login error:', err);
      setError(err.message || 'Network error. Please try again.');
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h2>Password Manager Login</h2>
        
        {error && <div className="error-message">{error}</div>}
        {success && <div className="success-message">{success}</div>}
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={loading || !!success}
              required
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading || !!success}
              required
            />
          </div>
          
          <button type="submit" className="primary-btn" disabled={loading || !!success}>
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
        
        <div className="auth-footer">
          Don't have an account? <Link to="/register">Register here</Link>
        </div>
      </div>
    </div>
  );
};

export default Login; 