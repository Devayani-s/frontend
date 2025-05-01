import { Navigate } from 'react-router-dom';
import authService from '../authService';

const PrivateRoute = ({ children, requiredRole }) => {
  const user = authService.getCurrentUser();
  
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  
  if (requiredRole && user.role !== requiredRole) {
    return <Navigate to="/unauthorized" replace />;
  }
  
  return children;
};

export default PrivateRoute;