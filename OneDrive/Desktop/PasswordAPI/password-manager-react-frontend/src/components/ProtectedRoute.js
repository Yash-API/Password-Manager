import React, { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { authService } from '../services/api';

// ProtectedRoute component to handle authentication and authorization
const ProtectedRoute = ({ children, requiresAdmin = false }) => {
  const location = useLocation();
  const [isAuthenticated, setIsAuthenticated] = useState(null);
  const [isAuthorized, setIsAuthorized] = useState(null);

  // Verify authentication and authorization on component mount
  useEffect(() => {
    const checkAuth = () => {
      const loggedIn = authService.isLoggedIn();
      console.log("ProtectedRoute: isLoggedIn =", loggedIn);
      setIsAuthenticated(loggedIn);

      if (loggedIn && requiresAdmin) {
        const admin = authService.isAdmin();
        console.log("ProtectedRoute: isAdmin =", admin);
        setIsAuthorized(admin);
      } else {
        setIsAuthorized(true);
      }
    };

    checkAuth();
  }, [requiresAdmin, location.pathname]);

  // Show loading while checking authentication
  if (isAuthenticated === null) {
    return <div>Checking authentication...</div>;
  }

  // If user is not logged in, redirect to login
  if (!isAuthenticated) {
    console.log("ProtectedRoute: Redirecting to login");
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  }

  // If route requires admin and user is not admin, redirect to dashboard
  if (requiresAdmin && !isAuthorized) {
    console.log("ProtectedRoute: User is not admin, redirecting to dashboard");
    return <Navigate to="/dashboard" replace />;
  }

  // If authentication and authorization pass, render the children
  console.log("ProtectedRoute: Authentication successful, rendering children");
  return children;
};

export default ProtectedRoute; 