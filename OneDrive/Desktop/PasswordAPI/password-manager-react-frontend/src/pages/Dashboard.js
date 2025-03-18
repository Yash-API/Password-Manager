import React, { useState, useEffect } from 'react';
import { authService, passwordService } from '../services/api';
import '../styles/Dashboard.css';

const Dashboard = () => {
  const [passwords, setPasswords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);
  const [visiblePasswordIndex, setVisiblePasswordIndex] = useState(null);
  
  // Form state for adding a new password
  const [newWebsite, setNewWebsite] = useState('');
  const [newPassword, setNewPassword] = useState('');
  
  // Get user info from token
  const userInfo = authService.getUserInfo();
  
  // Fetch passwords when component mounts
  useEffect(() => {
    fetchPasswords();
  }, []);
  
  // Fetch passwords from API
  const fetchPasswords = async () => {
    setLoading(true);
    setError('');
    
    try {
      const response = await passwordService.getUserPasswords();
      
      if (response.success) {
        setPasswords(response.passwords || []);
      } else {
        setError('Failed to fetch passwords');
      }
    } catch (err) {
      setError(err.message || 'An error occurred while fetching passwords');
      
      // If session expired, user will be redirected by the API service
    } finally {
      setLoading(false);
    }
  };
  
  // Handle form submission for adding a new password
  const handleAddPassword = async (e) => {
    e.preventDefault();
    
    if (!newWebsite || !newPassword) {
      setError('Website and password are required');
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const response = await passwordService.addWebsitePassword(newWebsite, newPassword);
      
      if (response.success) {
        setSuccess(`Password for ${newWebsite} added successfully!`);
        setNewWebsite('');
        setNewPassword('');
        setShowAddForm(false);
        
        // Refresh the password list
        await fetchPasswords();
        
        // Clear success message after 3 seconds
        setTimeout(() => {
          setSuccess('');
        }, 3000);
      } else {
        setError('Failed to add password');
      }
    } catch (err) {
      setError(err.message || 'An error occurred while adding the password');
    } finally {
      setLoading(false);
    }
  };
  
  // Toggle password visibility
  const togglePasswordVisibility = (index) => {
    if (visiblePasswordIndex === index) {
      setVisiblePasswordIndex(null);
    } else {
      setVisiblePasswordIndex(index);
    }
  };
  
  // Handle logout
  const handleLogout = () => {
    authService.logout();
    window.location.href = '/login';
  };
  
  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <h1>Password Manager</h1>
        <div className="user-section">
          <span className="welcome-message">Welcome, {userInfo?.sub || 'User'}</span>
          <button className="logout-btn" onClick={handleLogout}>Logout</button>
        </div>
      </header>
      
      <main className="dashboard-content">
        <div className="dashboard-card">
          <div className="card-header">
            <h2>Your Saved Passwords</h2>
            <button 
              className="add-btn" 
              onClick={() => setShowAddForm(!showAddForm)}
            >
              {showAddForm ? 'Cancel' : 'Add New Password'}
            </button>
          </div>
          
          {error && <div className="error-message">{error}</div>}
          {success && <div className="success-message">{success}</div>}
          
          {/* Add Password Form */}
          {showAddForm && (
            <div className="add-password-form">
              <h3>Add New Password</h3>
              <form onSubmit={handleAddPassword}>
                <div className="form-group">
                  <label htmlFor="website">Website</label>
                  <input
                    type="text"
                    id="website"
                    value={newWebsite}
                    onChange={(e) => setNewWebsite(e.target.value)}
                    disabled={loading}
                    required
                    placeholder="e.g., twitter.com"
                  />
                </div>
                
                <div className="form-group">
                  <label htmlFor="password">Password</label>
                  <input
                    type="password"
                    id="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    disabled={loading}
                    required
                    placeholder="Enter password to save"
                  />
                </div>
                
                <div className="form-actions">
                  <button 
                    type="button" 
                    className="cancel-btn" 
                    onClick={() => setShowAddForm(false)}
                    disabled={loading}
                  >
                    Cancel
                  </button>
                  <button 
                    type="submit" 
                    className="save-btn" 
                    disabled={loading}
                  >
                    {loading ? 'Saving...' : 'Save Password'}
                  </button>
                </div>
              </form>
            </div>
          )}
          
          {/* Password List */}
          {loading && !showAddForm ? (
            <div className="loading">Loading passwords...</div>
          ) : passwords.length === 0 ? (
            <div className="no-passwords">
              You haven't saved any passwords yet. Click "Add New Password" to get started.
            </div>
          ) : (
            <div className="password-list">
              <table>
                <thead>
                  <tr>
                    <th>Website</th>
                    <th>Password</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {passwords.map((entry, index) => (
                    <tr key={index}>
                      <td>{entry.website}</td>
                      <td className="password-cell">
                        <div className="password-display">
                          {visiblePasswordIndex === index ? (
                            <span className="password-text">{entry.password}</span>
                          ) : (
                            <span className="password-dots">••••••••••</span>
                          )}
                        </div>
                      </td>
                      <td>
                        <button 
                          className="toggle-btn" 
                          onClick={() => togglePasswordVisibility(index)}
                        >
                          {visiblePasswordIndex === index ? 'Hide' : 'Show'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default Dashboard; 