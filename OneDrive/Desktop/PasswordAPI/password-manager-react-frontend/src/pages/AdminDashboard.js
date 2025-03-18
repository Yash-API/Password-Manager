import React, { useState, useEffect } from 'react';
import { authService, adminService } from '../services/api';
import '../styles/AdminDashboard.css';

const AdminDashboard = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [visiblePasswordIndex, setVisiblePasswordIndex] = useState(null);
  
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
  
  // Handle form input change for adding a new user
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setNewUser({ ...newUser, [name]: value });
  };
  
  // Handle form submission for adding a new user
  const handleAddUser = async (e) => {
    e.preventDefault();
    
    if (!newUser.email || !newUser.website || !newUser.password) {
      setError('All fields are required');
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const response = await adminService.addUser(
        newUser.email,
        newUser.website,
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
      } else {
        setError('Failed to delete user');
      }
    } catch (err) {
      setError(err.message || 'An error occurred while deleting the user');
    } finally {
      setLoading(false);
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
                  />
                </div>
                
                <div className="form-group">
                  <label htmlFor="website">Default Website</label>
                  <input
                    type="text"
                    id="website"
                    name="website"
                    value={newUser.website}
                    onChange={handleInputChange}
                    disabled={loading}
                    required
                  />
                </div>
                
                <div className="form-group">
                  <label htmlFor="password">Password</label>
                  <input
                    type="password"
                    id="password"
                    name="password"
                    value={newUser.password}
                    onChange={handleInputChange}
                    disabled={loading}
                    required
                  />
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
            <div className="no-users">
              No users found. Click "Add New User" to create one.
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
                      <td>{user.email}</td>
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
                          <span className={user.role === 'master' ? 'admin-badge' : 'user-badge'}>
                            {user.role}
                          </span>
                        )}
                      </td>
                      <td>{user.saved_websites?.length || 0} passwords</td>
                      <td className="action-buttons">
                        {editingUser?.email === user.email ? (
                          <>
                            <button 
                              className="save-btn" 
                              onClick={() => handleRoleChange(user, newRole)}
                              disabled={loading || newRole === user.role}
                            >
                              Save
                            </button>
                            <button 
                              className="cancel-btn" 
                              onClick={cancelEditingRole}
                              disabled={loading}
                            >
                              Cancel
                            </button>
                          </>
                        ) : (
                          <>
                            <button 
                              className="edit-role-btn" 
                              onClick={() => startEditingRole(user)}
                              disabled={userInfo?.sub === user.email}
                            >
                              Change Role
                            </button>
                            <button 
                              className="view-btn" 
                              onClick={() => handleViewUserPasswords(user)}
                            >
                              View Passwords
                            </button>
                            
                            {/* Don't allow deletion of the current admin user */}
                            {(user.role !== 'master' || userInfo?.sub !== user.email) && (
                              <button 
                                className="delete-btn" 
                                onClick={() => handleDeleteUser(user.email)}
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
      
      {/* Password Modal */}
      {selectedUser && (
        <div className="modal-overlay">
          <div className="password-modal">
            <div className="modal-header">
              <h3>Passwords for {selectedUser.email}</h3>
              <button className="close-btn" onClick={handleCloseModal}>&times;</button>
            </div>
            
            <div className="modal-content">
              {selectedUser.saved_websites?.length > 0 ? (
                <table>
                  <thead>
                    <tr>
                      <th>Website</th>
                      <th>Password</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedUser.saved_websites.map((entry, index) => (
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
              ) : (
                <div className="no-passwords">
                  This user has no saved passwords.
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