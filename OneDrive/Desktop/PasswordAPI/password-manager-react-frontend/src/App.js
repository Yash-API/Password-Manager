import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate } from 'react-router-dom';
import './styles/App.css';

// Import pages
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import AdminDashboard from './pages/AdminDashboard';

// Import components
import ProtectedRoute from './components/ProtectedRoute';

// Import services
import { authService } from './services/api';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const checkAuth = () => {
      const isLoggedIn = authService.isLoggedIn();
      setIsAuthenticated(isLoggedIn);
      setIsAdmin(isLoggedIn && authService.isAdmin());
      setIsLoading(false);
    };

    checkAuth();
  }, []);

  const handleLogout = () => {
    authService.logout();
    setIsAuthenticated(false);
    setIsAdmin(false);
    window.location.href = '/login';
  };

  if (isLoading) {
    return <div className="app-loading">Loading...</div>;
  }

  return (
    <Router>
      <div className="app">
        <nav className="nav-bar">
          {isAuthenticated ? (
            <>
              <Link to="/dashboard">Dashboard</Link>
              {isAdmin && <Link to="/admin">Admin Dashboard</Link>}
              <button onClick={handleLogout} className="logout-btn">Logout</button>
            </>
          ) : (
            <>
              <Link to="/login">Login</Link>
              <Link to="/register">Register</Link>
            </>
          )}
        </nav>

        <Routes>
          <Route 
            path="/login" 
            element={isAuthenticated ? <Navigate to="/dashboard" /> : <Login />} 
          />
          <Route 
            path="/register" 
            element={isAuthenticated ? <Navigate to="/dashboard" /> : <Register />} 
          />
          <Route 
            path="/dashboard" 
            element={isAuthenticated ? <Dashboard /> : <Navigate to="/login" />} 
          />
          <Route 
            path="/admin" 
            element={
              isAuthenticated ? (
                isAdmin ? <AdminDashboard /> : <Navigate to="/dashboard" />
              ) : (
                <Navigate to="/login" />
              )
            } 
          />
          <Route 
            path="/" 
            element={<Navigate to={isAuthenticated ? "/dashboard" : "/login"} />} 
          />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
