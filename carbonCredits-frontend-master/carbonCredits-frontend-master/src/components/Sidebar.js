import React from 'react';
import {
  Drawer, List, ListItem, ListItemIcon, ListItemText,
  Toolbar, Typography, Box
} from '@mui/material';
import {
  Dashboard, AccountCircle, AssignmentTurnedIn, AccountBalanceWallet
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';

const Sidebar = ({ isEmployer, pendingCount }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const basePath = isEmployer ? '/employer' : '/employee';

  const items = isEmployer ? [
    { text: 'Dashboard', icon: <Dashboard />, path: `${basePath}/dashboard` },
    { text: 'Profile', icon: <AccountCircle />, path: `${basePath}/profile` },
    { text: 'Requests', icon: <AssignmentTurnedIn />, path: `${basePath}/requests` },
  ] : [
    { text: 'Dashboard', icon: <Dashboard />, path: `${basePath}/dashboard` },
    { text: 'Profile', icon: <AccountCircle />, path: `${basePath}/profile` },
    { text: 'Requests', icon: <AssignmentTurnedIn />, path: `${basePath}/requests` },
    { text: 'Wallet', icon: <AccountBalanceWallet />, path: `${basePath}/wallet` },
  ];

  return (
    <Drawer variant="permanent" anchor="left" sx={{
      width: 240,
      '& .MuiDrawer-paper': {
        width: 240,
        backgroundColor: '#f9f9f9',
        borderRight: '1px solid #e0e0e0',
      },
    }}>
      <Toolbar>
        <Typography variant="h6" fontWeight="bold" color="#333">
          Carbon Admin
        </Typography>
      </Toolbar>
      <Box sx={{ px: 1 }}>
        <List>
          {items.map(({ text, icon, path }) => (
            <ListItem
              button
              key={text}
              selected={location.pathname === path}
              onClick={() => navigate(path)}
              sx={{
                borderRadius: 1,
                mb: 1,
                '&.Mui-selected': {
                  backgroundColor: '#e3f2fd',
                  color: '#1976d2',
                },
              }}
            >
              <ListItemIcon sx={{ minWidth: 36 }}>{icon}</ListItemIcon>
              <ListItemText primary={text} />
            </ListItem>
          ))}
        </List>
      </Box>
    </Drawer>
  );
};

export default Sidebar;
