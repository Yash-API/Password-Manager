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
  const [deletingId, setDeletingId] = useState(null);
  const [updatingPassword, setUpdatingPassword] = useState(null);
  const [newPassword, setNewPassword] = useState('');
  
  // Form state for adding a new password
  const [newWebsite, setNewWebsite] = useState('');
  const [newPasswordValue, setNewPasswordValue] = useState('');
  
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
    
    if (!newWebsite || !newPasswordValue) {
      setError('Website and password are required');
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const response = await passwordService.addWebsitePassword(newWebsite, newPasswordValue);
      
      if (response.success) {
        setSuccess(`Password for ${newWebsite} added successfully!`);
        setNewWebsite('');
        setNewPasswordValue('');
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

  // Handle password deletion
  const handleDeletePassword = async (userSpecificId, website) => {
    // Ask for confirmation
    if (!window.confirm(`Are you sure you want to delete the password for ${website}?`)) {
      return;
    }
    
    setDeletingId(userSpecificId);
    setError('');
    setSuccess('');
    
    try {
      const response = await passwordService.deletePassword(userSpecificId);
      
      if (response.success) {
        setSuccess(`Password for ${website} deleted successfully!`);
        
        // Refresh the password list
        await fetchPasswords();
        
        // Clear success message after 3 seconds
        setTimeout(() => {
          setSuccess('');
        }, 3000);
      } else {
        setError('Failed to delete password');
      }
    } catch (err) {
      setError(err.message || 'An error occurred while deleting the password');
    } finally {
      setDeletingId(null);
    }
  };

  // Start updating password
  const startUpdatingPassword = (entry) => {
    setUpdatingPassword(entry);
    setNewPassword('');
  };

  // Cancel updating password
  const cancelUpdatingPassword = () => {
    setUpdatingPassword(null);
    setNewPassword('');
  };

  // Handle password update
  const handleUpdatePassword = async (userSpecificId, website) => {
    if (!newPassword) {
      setError('New password is required');
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      // Use the new method to update by website name instead of userSpecificId
      const response = await passwordService.updateWebsitePassword(website, newPassword);
      
      if (response.success) {
        setSuccess(`Password for ${website} updated successfully!`);
        setUpdatingPassword(null);
        setNewPassword('');
        
        // Update the password directly in state first for immediate feedback
        const updatedPasswords = passwords.map(pass => {
          if (pass.user_specific_id === userSpecificId) {
            // Create a new object with the updated password
            return { ...pass, password: response.updatedPassword };
          }
          return pass;
        });
        
        // Set the updated passwords
        setPasswords(updatedPasswords);
        
        // Find the index of the updated password to show it
        const updatedIndex = updatedPasswords.findIndex(p => p.user_specific_id === userSpecificId);
        if (updatedIndex !== -1) {
          setVisiblePasswordIndex(updatedIndex);
          
          // Hide the password after 3 seconds
          setTimeout(() => {
            setVisiblePasswordIndex(null);
          }, 3000);
        }
        
        // Also fetch the passwords from server to ensure sync
        const serverPasswords = await passwordService.getUserPasswords();
        if (serverPasswords.success) {
          setPasswords(serverPasswords.passwords || []);
        }
        
        // Clear success message after 3 seconds
        setTimeout(() => {
          setSuccess('');
        }, 3000);
      } else {
        setError('Failed to update password');
      }
    } catch (err) {
      setError(err.message || 'An error occurred while updating the password');
    } finally {
      setLoading(false);
    }
  };
  
  // Generate random password
  const generateRandomPassword = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+';
    let password = '';
    for (let i = 0; i < 12; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    if (updatingPassword) {
      setNewPassword(password);
    } else {
      setNewPasswordValue(password);
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
                  <div className="password-input-group">
                    <input
                      type="text"
                      id="password"
                      value={newPasswordValue}
                      onChange={(e) => setNewPasswordValue(e.target.value)}
                      disabled={loading}
                      required
                      placeholder="Enter password to save"
                    />
                    <button 
                      type="button"
                      className="generate-btn"
                      onClick={generateRandomPassword}
                      disabled={loading}
                    >
                      Generate
                    </button>
                  </div>
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
              <div className="empty-state">
                <i className="empty-icon">🔒</i>
                <p>You haven't saved any passwords yet.</p>
                <button 
                  className="add-btn-empty" 
                  onClick={() => setShowAddForm(true)}
                >
                  Add Your First Password
                </button>
              </div>
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
                      <td className="website-cell">
                        <span className="website-favicon">
                          {entry.website.charAt(0).toUpperCase()}
                        </span>
                        {entry.website}
                      </td>
                      <td className="password-cell">
                        {updatingPassword?.user_specific_id === entry.user_specific_id ? (
                          <div className="password-input-group">
                            <input
                              type="text"
                              value={newPassword}
                              onChange={(e) => setNewPassword(e.target.value)}
                              placeholder="Enter new password"
                              disabled={loading}
                            />
                            <button 
                              type="button"
                              className="generate-btn"
                              onClick={generateRandomPassword}
                              disabled={loading}
                            >
                              Generate
                            </button>
                          </div>
                        ) : (
                          <div className="password-display">
                            {visiblePasswordIndex === index ? (
                              <span className="password-text">{entry.password}</span>
                            ) : (
                              <span className="password-dots">••••••••••</span>
                            )}
                          </div>
                        )}
                      </td>
                      <td className="actions-cell">
                        {updatingPassword?.user_specific_id === entry.user_specific_id ? (
                          <>
                            <button 
                              className="save-btn" 
                              onClick={() => handleUpdatePassword(entry.user_specific_id, entry.website)}
                              disabled={loading || !newPassword}
                            >
                              {loading ? 'Updating...' : 'Save'}
                            </button>
                            <button 
                              className="cancel-btn" 
                              onClick={cancelUpdatingPassword}
                              disabled={loading}
                            >
                              Cancel
                            </button>
                          </>
                        ) : (
                          <>
                            <button 
                              className="toggle-btn" 
                              onClick={() => togglePasswordVisibility(index)}
                              title={visiblePasswordIndex === index ? "Hide password" : "Show password"}
                            >
                              {visiblePasswordIndex === index ? 'Hide' : 'Show'}
                            </button>
                            <button 
                              className="edit-btn" 
                              onClick={() => startUpdatingPassword(entry)}
                              title="Update password"
                            >
                              Update
                            </button>
                            <button 
                              className="delete-btn" 
                              onClick={() => handleDeletePassword(entry.user_specific_id, entry.website)}
                              disabled={deletingId === entry.user_specific_id}
                              title="Delete password"
                            >
                              {deletingId === entry.user_specific_id ? 'Deleting...' : 'Delete'}
                            </button>
                          </>
                        )}
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