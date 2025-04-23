import React, { useEffect, useState } from 'react';
import {
  Box,
  Paper,
  Avatar,
  Typography,
  CircularProgress,
  Stack,
  Divider,
  IconButton,
  TextField,
  Button
} from '@mui/material';
import EmailIcon from '@mui/icons-material/Email';
import WorkIcon from '@mui/icons-material/Work';
import StarsIcon from '@mui/icons-material/Stars';
import PersonIcon from '@mui/icons-material/Person';
import EditIcon from '@mui/icons-material/Edit';
import SaveIcon from '@mui/icons-material/Check';
import CancelIcon from '@mui/icons-material/Close';
import axios from '../../axios';

const EmployeeProfile = () => {
  const [user, setUser] = useState(null);
  const [formData, setFormData] = useState({});
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await axios.post('/auth/token/me');
        setUser(res.data);
        setFormData({
          fullName: res.data.fullName,
          email: res.data.email,
          employerName: res.data.employerName,
          points: res.data.points,
        });
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchUser();
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    if (name === 'fullName' && value.length > 20) return;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      const res = await axios.put('/auth/me', formData); // Send PUT request to update user profile
      setUser(res.data);
      setEditing(false); // Stop editing mode
    } catch (err) {
      console.error('Error saving profile:', err);
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    setEditing(false);
    setFormData({
      fullName: user.fullName,
      email: user.email,
      employerName: user.employerName,
      points: user.points,
    });
  };

  if (loading || !user) {
    return (
      <Box display="flex" justifyContent="center" mt={6}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box display="flex" justifyContent="center" alignItems="center" height="100%" mt={3}>
      <Paper elevation={4} sx={{ borderRadius: 4, p: 4, width: '100%', maxWidth: 350, background: 'linear-gradient(to right, #e8f5e9, #f1f8e9)' }}>
        <Stack spacing={3} alignItems="center" sx={{ position: 'relative', width: '100%' }}>
          {/* Edit Icon Button in Top Right Corner */}
          {!editing && (
            <IconButton
              onClick={() => setEditing(true)}
              sx={{
                position: 'absolute',
                top: 10,
                right: 10,
                backgroundColor: '#43a047',
                color: 'white',
                '&:hover': {
                  backgroundColor: '#2e7d32',
                },
              }}
            >
              <EditIcon />
            </IconButton>
          )}

          <Avatar
            sx={{
              width: 100,
              height: 100,
              fontSize: 36,
              fontWeight: 600,
              background: 'linear-gradient(to right, #43a047, #66bb6a)',
              color: '#fff',
            }}
          >
            {user.fullName.charAt(0).toUpperCase()}
          </Avatar>

          <Typography variant="h5" fontWeight="bold" color="green" textAlign="center">
            Employee Profile
          </Typography>

          <Divider sx={{ width: '100%' }} />

          {editing ? (
            // Edit Form Fields
            <>
              <Stack spacing={2} width="100%" alignItems="center">
                <Box display="flex" alignItems="center" gap={1}>
                  <PersonIcon />
                  <TextField
                    name="fullName"
                    value={formData.fullName}
                    onChange={handleChange}
                    variant="outlined"
                    size="small"
                    fullWidth
                    sx={{ mb: 2 }}
                    label="Full Name"
                  />
                </Box>
                <Box display="flex" alignItems="center" gap={1}>
                  <EmailIcon />
                  <TextField
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    variant="outlined"
                    size="small"
                    fullWidth
                    sx={{ mb: 2 }}
                    label="Email"
                  />
                </Box>
                <Box display="flex" alignItems="center" gap={1}>
                  <WorkIcon />
                  <TextField
                    name="employerName"
                    value={formData.employerName}
                    onChange={handleChange}
                    variant="outlined"
                    size="small"
                    fullWidth
                    sx={{ mb: 2 }}
                    label="Employer"
                  />
                </Box>
                <Box display="flex" alignItems="center" gap={1}>
                  <StarsIcon color="primary" />
                  <Typography><strong>Total Points:</strong> {user.points}</Typography>
                </Box>
              </Stack>

              {/* Save and Cancel buttons */}
              <Box display="flex" gap={2} justifyContent="center" mt={2}>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={handleSave}
                  disabled={saving}
                  startIcon={<SaveIcon />}
                >
                  Save
                </Button>
                <Button
                  variant="outlined"
                  color="secondary"
                  onClick={handleCancel}
                  startIcon={<CancelIcon />}
                >
                  Cancel
                </Button>
              </Box>
            </>
          ) : (
            // View Mode
            <Stack spacing={2} width="100%" alignItems="center">
              <Box display="flex" alignItems="center" gap={1}>
                <PersonIcon />
                <Typography><strong>Name:</strong> {user.fullName}</Typography>
              </Box>
              <Box display="flex" alignItems="center" gap={1}>
                <EmailIcon />
                <Typography><strong>Email:</strong> {user.email}</Typography>
              </Box>
              <Box display="flex" alignItems="center" gap={1}>
                <WorkIcon />
                <Typography><strong>Employer:</strong> {user.employerName}</Typography>
              </Box>
              <Box display="flex" alignItems="center" gap={1}>
                <StarsIcon color="primary" />
                <Typography><strong>Total Points:</strong> {user.points}</Typography>
              </Box>
            </Stack>
          )}
        </Stack>
      </Paper>
    </Box>
  );
};

export default EmployeeProfile;
