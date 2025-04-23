import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  TextField,
  Button,
  MenuItem,
  Box,
  Link,
  Stack,
  Divider
} from '@mui/material';
import LoginIcon from '@mui/icons-material/Login';
import GoogleIcon from '@mui/icons-material/Google';
import PersonAddAlt1Icon from '@mui/icons-material/PersonAddAlt1';
import LockOpenIcon from '@mui/icons-material/LockOpen';

import { useNavigate } from 'react-router-dom';
import axios from '../axios';


const LoginPage = () => {
  const [isNew, setIsNew] = useState(false);
  const [form, setForm] = useState({ role: 'employee' });
  const navigate = useNavigate();

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleLogin = async () => {
    try {
      const res = await axios.post('/auth/login', form);
      const role = res.data.role;
      setTimeout(() => {
        navigate(role === 'employee' ? '/employee/dashboard' : '/employer/dashboard');
      }, 200);
    } catch (err) {
      alert(err.response?.data?.message || 'Login failed');
    }
  };

  const handleRegister = async () => {
    try {
      await axios.post('/auth/register', form);
      alert('Registration successful. Now login.');
      setIsNew(false);
    } catch (err) {
      alert(err.response?.data?.message || 'Registration failed');
    }
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('error') === 'notregistered') {
      alert('This email is not registered. Please register to continue.');
      const emailFromURL = params.get('email');
      if (emailFromURL) {
        setForm((prev) => ({ ...prev, email: emailFromURL }));
        setIsNew(true);
      }
    }
  }, []);

  return (
    <Container maxWidth="xs">
      <Paper elevation={6} sx={{ mt: 8, p: 4, borderRadius: 4, textAlign: 'center' }}>
        <Box display="flex" justifyContent="center" alignItems="center" mb={1}>
        <LockOpenIcon sx={{ fontSize: 40, color: '#1976d2', mb: 1 }} />

          <Typography variant="h5" fontWeight="bold">
            CarbonTrack
          </Typography>
        </Box>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Empowering sustainable travel. Earn carbon credits. Trade responsibly.
        </Typography>

        <Divider sx={{ my: 2 }} />

        <Typography variant="h6" sx={{ mb: 2 }}>
          {isNew ? 'Register to Start Earning Credits' : 'Login to Your Account'}
        </Typography>

        <Stack spacing={2}>
          <TextField
            label="Email"
            name="email"
            fullWidth
            onChange={handleChange}
            value={form.email || ''}
          />
          <TextField
            label="Password"
            name="password"
            type="password"
            fullWidth
            onChange={handleChange}
          />

          {isNew && (
            <>
              <TextField
                label="Full Name"
                name="fullName"
                fullWidth
                onChange={handleChange}
              />
              <TextField
                label="Role"
                name="role"
                select
                fullWidth
                value={form.role}
                onChange={handleChange}
              >
                <MenuItem value="employee">Employee</MenuItem>
                <MenuItem value="employer">Employer</MenuItem>
              </TextField>
              {form.role === 'employee' && (
                <TextField
                  label="Employer Name"
                  name="employerName"
                  fullWidth
                  onChange={handleChange}
                />
              )}
            </>
          )}

          <Button
            variant="contained"
            color="success"
            fullWidth
            size="large"
            startIcon={isNew ? <PersonAddAlt1Icon /> : <LoginIcon />}
            onClick={isNew ? handleRegister : handleLogin}
          >
            {isNew ? 'Register' : 'Login'}
          </Button>

          {!isNew && (
            <Button
              variant="outlined"
              fullWidth
              startIcon={<GoogleIcon />}
              onClick={() => {
                window.location.href = 'https://carboncredits-backend.onrender.com/auth/google';
                // navigate("/auth/google")
              }}
            >
              Login with Google
            </Button>
          )}
        </Stack>

        <Box mt={3}>
          <Typography variant="body2">
            {isNew ? 'Already have an account?' : 'New user?'}{' '}
            <Link component="button" onClick={() => setIsNew(!isNew)}>
              {isNew ? 'Login here' : 'Register here'}
            </Link>
          </Typography>
        </Box>
      </Paper>
    </Container>
  );
};

export default LoginPage;
