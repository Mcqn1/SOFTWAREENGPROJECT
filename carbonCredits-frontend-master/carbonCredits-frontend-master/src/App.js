import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';

import LoginPage from './pages/LoginPage';

import EmployerLayout from './layouts/EmployerLayout';
import EmployerDashboard from './pages/employer/Dashboard';
import EmployerProfile from './pages/employer/Profile';
import EmployerRequests from './pages/employer/Requests';

import EmployeeLayout from './layouts/EmployeeLayout';
import EmployeeDashboard from './pages/employee/Dashboard'; // ✅
// root level
import EmployeeProfile from './pages/employee/Profile';
import EmployeeRequests from './pages/employee/Requests';
import EmployeeWallet from './pages/employee/Wallet';

const App = () => {
  return (
    <Router>
      <Routes>
        {/* Login route */}
        <Route path="/" element={<LoginPage />} />

        

        {/* Employer routes */}
        <Route path="/employer" element={<EmployerLayout />}>
          <Route index element={<Navigate to="dashboard" replace />} />
          <Route path="dashboard" element={<EmployerDashboard />} />
          <Route path="profile" element={<EmployerProfile />} />
          <Route path="requests" element={<EmployerRequests />} />
        </Route>

        {/* Employee routes */}
        <Route path="/employee" element={<EmployeeLayout />}>
          <Route index element={<Navigate to="dashboard" replace />} />
          <Route path="dashboard" element={<EmployeeDashboard />} />
          <Route path="profile" element={<EmployeeProfile />} />
          <Route path="requests" element={<EmployeeRequests />} />
          <Route path="wallet" element={<EmployeeWallet />} />
        </Route>

        {/* Catch-all fallback route (optional) */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
};

export default App;
