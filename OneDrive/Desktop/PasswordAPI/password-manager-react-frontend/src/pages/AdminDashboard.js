import React, { useState, useEffect } from 'react';
import { authService, adminService, passwordService } from '../services/api';
import '../styles/AdminDashboard.css';

const AdminDashboard = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [visiblePasswordIndex, setVisiblePasswordIndex] = useState(null);
  const [deletingPasswordId, setDeletingPasswordId] = useState(null);
  const [updatingPasswordId, setUpdatingPasswordId] = useState(null);
  const [newPasswordValue, setNewPasswordValue] = useState('');
  
  // Form state for adding a new user
  const [newUser, setNewUser] = useState({
    email: '',
    website: '',
    password: '',
    role: 'user'
  });
  
  const [editingUser, setEditingUser] = useState(null);
  const [newRole, setNewRole] = useState('');
  
  // Get user info from token
  const userInfo = authService.getUserInfo();
  
  // Fetch users when component mounts
  useEffect(() => {
    fetchAllUsers();
  }, []);
  
  // Fetch all users from API
  const fetchAllUsers = async () => {
    setLoading(true);
    setError('');
    
    try {
      const response = await adminService.getAllUsers();
      
      if (response.success) {
        setUsers(response.data || []);
      } else {
        setError('Failed to fetch users');
      }
    } catch (err) {
      setError(err.message || 'An error occurred while fetching users');
      
      // If session expired, user will be redirected by the API service
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
    setNewUser({ ...newUser, password });
  };
  
  // Handle form input change for adding a new user
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setNewUser({ ...newUser, [name]: value });
  };
  
  // Handle form submission for adding a new user
  const handleAddUser = async (e) => {
    e.preventDefault();
    
    if (!newUser.email || !newUser.password) {
      setError('Email and password are required');
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const response = await adminService.addUser(
        newUser.email,
        newUser.password,
        newUser.role
      );
      
      if (response.message === 'User added successfully') {
        setSuccess('User added successfully!');
        setNewUser({
          email: '',
          website: '',
          password: '',
          role: 'user'
        });
        setShowAddForm(false);
        
        // Refresh the user list
        await fetchAllUsers();
        
        // Clear success message after 3 seconds
        setTimeout(() => {
          setSuccess('');
        }, 3000);
      } else {
        setError('Failed to add user');
      }
    } catch (err) {
      setError(err.message || 'An error occurred while adding the user');
    } finally {
      setLoading(false);
    }
  };
  
  // Handle user deletion
  const handleDeleteUser = async (email) => {
    if (!window.confirm(`Are you sure you want to delete user ${email}?`)) {
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const response = await adminService.deleteUser(email);
      
      if (response.message === 'User deleted successfully') {
        setSuccess(`User ${email} deleted successfully!`);
        
        // Refresh the user list
        await fetchAllUsers();
        
        // Clear success message after 3 seconds
        setTimeout(() => {
          setSuccess('');
        }, 3000);
      } else {
        setError('Failed to delete user');
      }
    } catch (err) {
      setError(err.message || 'An error occurred while deleting the user');
    } finally {
      setLoading(false);
    }
  };
  
  // Handle password deletion
  const handleDeletePassword = async (userSpecificId, website) => {
    if (!window.confirm(`Are you sure you want to delete the password for ${website}?`)) {
      return;
    }
    
    setDeletingPasswordId(userSpecificId);
    setError('');
    setSuccess('');
    
    try {
      const response = await passwordService.deletePassword(userSpecificId);
      
      if (response.success) {
        setSuccess(`Password for ${website} deleted successfully!`);
        
        // Refresh the user data
        await fetchAllUsers();
        
        // If we're viewing a user's passwords, update the selected user
        if (selectedUser) {
          const updatedUser = users.find(u => u.email === selectedUser.email);
          if (updatedUser) {
            setSelectedUser(updatedUser);
          } else {
            setSelectedUser(null);
          }
        }
        
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
      setDeletingPasswordId(null);
    }
  };
  
  // Handle viewing user passwords
  const handleViewUserPasswords = (user) => {
    setSelectedUser(user);
    setVisiblePasswordIndex(null);
  };
  
  // Close the password modal
  const handleCloseModal = () => {
    setSelectedUser(null);
    setVisiblePasswordIndex(null);
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
  
  // Handle role change
  const handleRoleChange = async (user, role) => {
    if (!window.confirm(`Are you sure you want to change ${user.email}'s role to ${role}?`)) {
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const response = await adminService.updateUserRole(user.email, role);
      
      if (response.message === 'User role updated successfully') {
        setSuccess(`Role for ${user.email} updated to ${role} successfully!`);
        setEditingUser(null);
        
        // Refresh the user list
        await fetchAllUsers();
        
        // Clear success message after 3 seconds
        setTimeout(() => {
          setSuccess('');
        }, 3000);
      } else {
        setError('Failed to update user role');
      }
    } catch (err) {
      setError(err.message || 'An error occurred while updating the user role');
    } finally {
      setLoading(false);
    }
  };
  
  // Start editing role
  const startEditingRole = (user) => {
    setEditingUser(user);
    setNewRole(user.role);
  };
  
  // Cancel editing role
  const cancelEditingRole = () => {
    setEditingUser(null);
    setNewRole('');
  };
  
  // Start updating password
  const startUpdatingPassword = (entry) => {
    setUpdatingPasswordId(entry.user_specific_id);
    setNewPasswordValue('');
  };

  // Cancel updating password
  const cancelUpdatingPassword = () => {
    setUpdatingPasswordId(null);
    setNewPasswordValue('');
  };

  // Handle password update
  const handleUpdatePassword = async (entry) => {
    if (!newPasswordValue) {
      setError('New password is required');
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      // Use the new admin-specific method for updating passwords by website
      const response = await adminService.updateUserWebsitePassword(
        selectedUser.email,
        entry.website,
        newPasswordValue
      );
      
      if (response.success) {
        setSuccess(`Password for ${entry.website} updated successfully!`);
        setUpdatingPasswordId(null);
        setNewPasswordValue('');
        
        // Update the user passwords directly in state first for immediate feedback
        if (selectedUser) {
          // Create a new user object with updated password
          const updatedUser = { ...selectedUser };
          
          // Update the password in the saved_websites array
          updatedUser.saved_websites = selectedUser.saved_websites.map(website => {
            if (website.website === entry.website) {
              return { ...website, password: response.updatedPassword };
            }
            return website;
          });
          
          // Update the selectedUser state
          setSelectedUser(updatedUser);
          
          // Also update in the users array
          const updatedUsers = users.map(user => {
            if (user.email === selectedUser.email) {
              return updatedUser;
            }
            return user;
          });
          setUsers(updatedUsers);
          
          // Find the index of the updated password to show it
          const updatedIndex = updatedUser.saved_websites.findIndex(
            p => p.website === entry.website
          );
          
          if (updatedIndex !== -1) {
            // Show the updated password
            setVisiblePasswordIndex(updatedIndex);
            
            // Hide the password after 3 seconds
            setTimeout(() => {
              setVisiblePasswordIndex(null);
            }, 3000);
          }
          
          // Also fetch from server to ensure data is synced
          const allUsersResponse = await adminService.getAllUsers();
          if (allUsersResponse.success) {
            setUsers(allUsersResponse.data || []);
            // Update the selected user with fresh data
            const freshUser = allUsersResponse.data.find(u => u.email === selectedUser.email);
            if (freshUser) {
              setSelectedUser(freshUser);
            }
          }
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
  
  // Clear messages after 3 seconds
  useEffect(() => {
    if (success || error) {
      const timer = setTimeout(() => {
        setSuccess('');
        setError('');
      }, 3000);
      return () => clearTimeout(timer);
    }
  }, [success, error]);
  
  return (
    <div className="admin-dashboard-container">
      <header className="admin-header">
        <h1>Admin Dashboard</h1>
        <div className="user-section">
          <span className="welcome-message">Admin: {userInfo?.sub || 'User'}</span>
          <button className="dashboard-link" onClick={() => window.location.href = '/dashboard'}>User Dashboard</button>
          <button className="logout-btn" onClick={handleLogout}>Logout</button>
        </div>
      </header>
      
      <main className="admin-content">
        <div className="admin-card">
          <div className="card-header">
            <h2>User Management</h2>
            <button 
              className="add-btn" 
              onClick={() => setShowAddForm(!showAddForm)}
            >
              {showAddForm ? 'Cancel' : 'Add New User'}
            </button>
          </div>
          
          {error && <div className="error-message">{error}</div>}
          {success && <div className="success-message">{success}</div>}
          
          {/* Add User Form */}
          {showAddForm && (
            <div className="add-user-form">
              <h3>Add New User</h3>
              <form onSubmit={handleAddUser}>
                <div className="form-group">
                  <label htmlFor="email">Email</label>
                  <input
                    type="email"
                    id="email"
                    name="email"
                    value={newUser.email}
                    onChange={handleInputChange}
                    disabled={loading}
                    required
                    placeholder="user@example.com"
                  />
                </div>
                
                <div className="form-group">
                  <label htmlFor="password">Password</label>
                  <div className="password-input-group">
                    <input
                      type="text"
                      id="password"
                      name="password"
                      value={newUser.password}
                      onChange={handleInputChange}
                      disabled={loading}
                      required
                      placeholder="Enter password"
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
                
                <div className="form-group">
                  <label htmlFor="role">Role</label>
                  <select
                    id="role"
                    name="role"
                    value={newUser.role}
                    onChange={handleInputChange}
                    disabled={loading}
                  >
                    <option value="user">User</option>
                    <option value="master">Admin</option>
                  </select>
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
                    {loading ? 'Adding...' : 'Add User'}
                  </button>
                </div>
              </form>
            </div>
          )}
          
          {/* User List */}
          {loading && !showAddForm ? (
            <div className="loading">Loading users...</div>
          ) : users.length === 0 ? (
            <div className="no-passwords">
              <div className="empty-state">
                <i className="empty-icon">👤</i>
                <p>No users found.</p>
                <button 
                  className="add-btn-empty" 
                  onClick={() => setShowAddForm(true)}
                >
                  Add Your First User
                </button>
              </div>
            </div>
          ) : (
            <div className="user-list">
              <table>
                <thead>
                  <tr>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Saved Passwords</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user, index) => (
                    <tr key={index}>
                      <td className="email-cell">
                        <span className="email-icon">
                          {user.email.charAt(0).toUpperCase()}
                        </span>
                        {user.email}
                      </td>
                      <td>
                        {editingUser?.email === user.email ? (
                          <select 
                            value={newRole} 
                            onChange={(e) => setNewRole(e.target.value)}
                            disabled={loading}
                          >
                            <option value="user">User</option>
                            <option value="master">Admin</option>
                          </select>
                        ) : (
                          <span className={`user-role ${user.role === 'master' ? 'role-master' : 'role-user'}`}>
                            {user.role}
                          </span>
                        )}
                      </td>
                      <td>{user.saved_websites?.length || 0} passwords</td>
                      <td className="action-buttons">
                        {editingUser?.email === user.email ? (
                          <>
                            <button 
                              className="save-btn btn" 
                              onClick={() => handleRoleChange(user, newRole)}
                              disabled={loading || newRole === user.role}
                            >
                              Save
                            </button>
                            <button 
                              className="cancel-btn btn" 
                              onClick={cancelEditingRole}
                              disabled={loading}
                            >
                              Cancel
                            </button>
                          </>
                        ) : (
                          <>
                            <button 
                              className="edit-role-btn btn" 
                              onClick={() => startEditingRole(user)}
                              disabled={userInfo?.sub === user.email}
                              title="Change user role"
                            >
                              Change Role
                            </button>
                            <button 
                              className="view-btn btn" 
                              onClick={() => handleViewUserPasswords(user)}
                              title="View user passwords"
                            >
                              View Passwords
                            </button>
                            
                            {/* Don't allow deletion of the current admin user */}
                            {(user.role !== 'master' || userInfo?.sub !== user.email) && (
                              <button 
                                className="delete-btn btn" 
                                onClick={() => handleDeleteUser(user.email)}
                                title="Delete user"
                              >
                                Delete
                              </button>
                            )}
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
      
      {/* User Passwords Modal */}
      {selectedUser && (
        <div className="modal-backdrop" onClick={handleCloseModal}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Passwords for {selectedUser.email}</h3>
              <button className="close-btn" onClick={handleCloseModal}>&times;</button>
            </div>
            <div className="modal-body">
              {error && <div className="error-message">{error}</div>}
              {success && <div className="success-message">{success}</div>}
              
              {selectedUser.saved_websites?.length === 0 ? (
                <div className="no-passwords">
                  This user has no saved passwords.
                </div>
              ) : (
                <div className="user-passwords">
                  {selectedUser.saved_websites?.map((entry, index) => (
                    <div className="password-item" key={index}>
                      <div className="website-info">
                        <span className="website-favicon">
                          {entry.website.charAt(0).toUpperCase()}
                        </span>
                        <span>{entry.website}</span>
                      </div>
                      <div className="password-value">
                        {updatingPasswordId === entry.user_specific_id ? (
                          <div className="password-input-group">
                            <input
                              type="text"
                              value={newPasswordValue}
                              onChange={(e) => setNewPasswordValue(e.target.value)}
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
                          visiblePasswordIndex === index ? (
                            <span className="password-text">{entry.password}</span>
                          ) : (
                            <span className="password-dots">••••••••••</span>
                          )
                        )}
                      </div>
                      <div className="password-actions">
                        {updatingPasswordId === entry.user_specific_id ? (
                          <>
                            <button 
                              className="save-btn btn" 
                              onClick={() => handleUpdatePassword(entry)}
                              disabled={loading || !newPasswordValue}
                            >
                              {loading ? 'Saving...' : 'Save'}
                            </button>
                            <button 
                              className="cancel-btn btn" 
                              onClick={cancelUpdatingPassword}
                              disabled={loading}
                            >
                              Cancel
                            </button>
                          </>
                        ) : (
                          <>
                            <button 
                              className="toggle-btn btn" 
                              onClick={() => togglePasswordVisibility(index)}
                              title={visiblePasswordIndex === index ? "Hide password" : "Show password"}
                            >
                              {visiblePasswordIndex === index ? 'Hide' : 'Show'}
                            </button>
                            <button 
                              className="edit-btn btn" 
                              onClick={() => startUpdatingPassword(entry)}
                              title="Update password"
                            >
                              Update
                            </button>
                            <button 
                              className="delete-password-btn btn" 
                              onClick={() => handleDeletePassword(entry.user_specific_id, entry.website)}
                              disabled={deletingPasswordId === entry.user_specific_id}
                              title="Delete password"
                            >
                              {deletingPasswordId === entry.user_specific_id ? 'Deleting...' : 'Delete'}
                            </button>
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminDashboard; 