import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Avatar,
  Typography,
  IconButton,
  TextField,
  Button,
  Stack,
  CircularProgress,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import SaveIcon from '@mui/icons-material/Check';
import CancelIcon from '@mui/icons-material/Close';
import axios from '../../axios';

const EmployerProfile = () => {
  const [employer, setEmployer] = useState(null);
  const [editing, setEditing] = useState(false);
  const [formData, setFormData] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchEmployer = async () => {
      try {
        const res = await axios.post('/auth/token/me');
        setEmployer(res.data);
        setFormData({
          fullName: res.data.fullName,
          email: res.data.email,
        });
      } catch (err) {
        console.error('Error fetching employer info', err);
      } finally {
        setLoading(false);
      }
    };
    fetchEmployer();
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSave = async () => {
    try {
      const res = await axios.put('/auth/me', formData);
      setEmployer(res.data);
      setEditing(false);
    } catch (err) {
      console.error('Error saving profile:', err);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" mt={6}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box display="flex" justifyContent="center" mt={4}>
      <Paper
        elevation={4}
        sx={{
          borderRadius: 4,
          p: 4,
          width: '100%',
          maxWidth: 460,
          background: 'linear-gradient(to bottom right, #e8f5e9, #f1fdf3)',
          position: 'relative',
        }}
      >
        <Box position="absolute" top={16} right={16}>
          <IconButton onClick={() => setEditing((prev) => !prev)}>
            <EditIcon />
          </IconButton>
        </Box>
        <Stack spacing={3} alignItems="center">
          <Avatar
            sx={{
              width: 100,
              height: 100,
              fontSize: 36,
              fontWeight: 600,
              bgcolor: '#43a047',
            }}
          >
            {employer?.fullName?.charAt(0).toUpperCase() || '?'}
          </Avatar>
          <Typography variant="h5" fontWeight="bold" textAlign="center" color="green">
            Employer Profile
          </Typography>
          {editing ? (
            <Stack spacing={2} width="100%" alignItems="center">
              <TextField
                label="Full Name"
                name="fullName"
                value={formData.fullName}
                onChange={handleChange}
                fullWidth
              />
              <TextField
                label="Email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                fullWidth
              />
              <Stack direction="row" spacing={2} justifyContent="center" mt={2}>
                <Button
                  variant="contained"
                  startIcon={<SaveIcon />}
                  onClick={handleSave}
                >
                  Save
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<CancelIcon />}
                  onClick={() => {
                    setEditing(false);
                    setFormData({
                      fullName: employer.fullName,
                      email: employer.email,
                    });
                  }}
                >
                  Cancel
                </Button>
              </Stack>
            </Stack>
          ) : (
            <Stack spacing={1} alignItems="center">
              <Typography>
                <strong>Name:</strong> {employer.fullName}
              </Typography>
              <Typography>
                <strong>Email:</strong> {employer.email}
              </Typography>
            </Stack>
          )}
        </Stack>
      </Paper>
    </Box>
  );
};

export default EmployerProfile;
