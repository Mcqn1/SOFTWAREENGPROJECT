import React, { useEffect, useState } from 'react';
import {
  Box, Typography, AppBar, IconButton,
  Avatar, Button, Tooltip
} from '@mui/material';
import LogoutIcon from '@mui/icons-material/Logout';
import MonetizationOnIcon from '@mui/icons-material/MonetizationOn';
import { useNavigate, Outlet } from 'react-router-dom';
import axios from '../axios';
import Sidebar from '../components/Sidebar';

const EmployeeLayout = () => {
  const [user, setUser] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await axios.post('/auth/token/me');
        setUser(res.data);
      } catch {
        navigate('/login');
      }
    };
    fetchUser();
  }, [navigate]);

  const handleLogout = async () => {
    try {
      await axios.post('/auth/logout');
      localStorage.clear();
      navigate('/login');
    } catch (err) {
      console.error('Logout failed', err);
    }
  };
  

  const handleProfileClick = () => {
    navigate('/employee/profile');
  };

  if (!user) return null;

  return (
    <Box sx={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      <Sidebar isEmployer={false} />

      <Box sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
        {/* Top Header */}
        <AppBar
          position="static"
          color="default"
          elevation={1}
          sx={{
            borderBottom: '1px solid #e0e0e0',
            backgroundColor: '#fff',
            px: 3,
            py: 1.5,
            display: 'flex',
            flexDirection: 'row',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <Box display="flex" alignItems="center" gap={2}>
            <Typography variant="h6" fontWeight="500">
              Welcome, <strong>{user.fullName}</strong>
            </Typography>
            <Box display="flex" alignItems="center" gap={0.5}>
              <MonetizationOnIcon color="primary" />
              <Typography variant="subtitle1" fontWeight="bold">
                {user.points}
              </Typography>
            </Box>
          </Box>

          <Box display="flex" alignItems="center" gap={2}>
            <Tooltip title="Profile">
              <IconButton onClick={handleProfileClick}>
                <Avatar>{user.fullName.charAt(0).toUpperCase()}</Avatar>
              </IconButton>
            </Tooltip>
            <Tooltip title="Logout">
              <Button
                variant="outlined"
                color="error"
                size="small"
                startIcon={<LogoutIcon />}
                onClick={handleLogout}
              >
                Logout
              </Button>
            </Tooltip>
          </Box>
        </AppBar>

        {/* Page Content */}
        <Box
          component="main"
          sx={{
            flexGrow: 1,
            overflowY: 'auto',
            backgroundColor: '#fafafa',
            p: 3,
          }}
        >
          <Outlet context={{ user }} />
        </Box>
      </Box>
    </Box>
  );
};

export default EmployeeLayout;
