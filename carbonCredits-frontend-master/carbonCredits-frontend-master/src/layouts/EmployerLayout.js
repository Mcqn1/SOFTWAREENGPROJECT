import React, { useEffect, useState } from 'react';
import Sidebar from '../components/Sidebar';
import {
  Box, Toolbar, AppBar, IconButton,
  Typography, Avatar, Tooltip, Button
} from '@mui/material';
import axios from '../axios';
import { Outlet, useNavigate } from 'react-router-dom';
import LogoutIcon from '@mui/icons-material/Logout';

const EmployerLayout = () => {
  const [pendingCount, setPendingCount] = useState(0);
  const [user, setUser] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchUserAndPending = async () => {
      try {
        const [userRes, pendingRes] = await Promise.all([
          axios.post('/auth/token/me'),
          axios.get('/api/requests/employer'),
        ]);
        setUser(userRes.data);
        setPendingCount(pendingRes.data.length);
      } catch (err) {
        console.error('Error loading data', err);
        navigate('/login');
      }
    };
    fetchUserAndPending();
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

  if (!user) return null;

  return (
    <Box sx={{ display: 'flex' }}>
      <Sidebar isEmployer={true} pendingCount={pendingCount} />

      <Box sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
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
          <Typography variant="h6" fontWeight="500">
            Welcome, <strong>{user.fullName}</strong>
          </Typography>

          <Box display="flex" alignItems="center" gap={2}>
            <Tooltip title="Profile">
              <IconButton onClick={() => navigate('/employer/profile')}>
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

        <Box component="main" sx={{ flexGrow: 1, p: 3, backgroundColor: '#fafafa' }}>
          <Outlet />
        </Box>
      </Box>
    </Box>
  );
};

export default EmployerLayout;
