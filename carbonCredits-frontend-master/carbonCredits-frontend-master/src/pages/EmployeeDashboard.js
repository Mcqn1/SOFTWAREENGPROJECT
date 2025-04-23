import React, { useEffect, useState } from 'react';
import {
  Container,
  Typography,
  Paper,
  Select,
  MenuItem,
  Button,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Box,
  Divider,
} from '@mui/material';
import axios from '../axios';
import MapTracker from './MapTracker';

const EmployeeDashboard = () => {
  const [user, setUser] = useState(null);
  const [requests, setRequests] = useState([]);
  const [, setTrips] = useState([]);
  const [mode, setMode] = useState('car');
  const [distance, setDistance] = useState('');
  const [startLocation, setStartLocation] = useState(null);
  const [endLocation, setEndLocation] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [startSet, setStartSet] = useState(false);
  const [endSet, setEndSet] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const userRes = await axios.post('/auth/token/me');
        setUser(userRes.data);
        fetchRequests();
        fetchTrips(userRes.data._id);
      } catch (err) {
        console.error('Error fetching user or requests:', err);
      }
    };
    fetchData();
  }, []);

  const fetchRequests = async () => {
    try {
      const res = await axios.get('/api/requests/employee');
      setRequests(res.data);
    } catch (err) {
      console.error('Error fetching requests:', err);
    }
  };

  const fetchTrips = async (userId) => {
    try {
      const res = await axios.get(`/api/trip/employee/${userId}`);
      setTrips(res.data);
    } catch (err) {
      console.error('Error fetching trips:', err);
    }
  };

  const sendRequest = async () => {
    if (!startLocation || !endLocation) {
      alert('Please select both start and end locations.');
      return;
    }

    const payload = {
      mode,
      distance: parseFloat(distance),
      startLocation: {
        latitude: startLocation.latitude,
        longitude: startLocation.longitude,
      },
      endLocation: {
        latitude: endLocation.latitude,
        longitude: endLocation.longitude,
      },
      location: {
        latitude: endLocation.latitude,
        longitude: endLocation.longitude,
      }
    };

    try {
      setIsSubmitting(true);
      const res = await axios.post('/api/requests', payload, {
        headers: {
          'Content-Type': 'application/json',
        },
      });

      console.log('✅ Request submitted:', res.data);
      setDistance('');
      setStartLocation(null);
      setEndLocation(null);
      setStartSet(false);
      setEndSet(false);
      fetchRequests(); // refresh request list
    } catch (err) {
      console.error('❌ Error submitting request:', err.response?.data || err.message);
      alert(err.response?.data?.message || 'Request failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDismiss = async (id) => {
    try {
      await axios.delete(`/api/requests/${id}`);
      fetchRequests();
    } catch (err) {
      console.error('Error dismissing request:', err);
    }
  };

  return user ? (
    <Container maxWidth="sm" sx={{ mt: 5 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h5" gutterBottom>
          Welcome, {user.fullName}
        </Typography>
        <Typography variant="subtitle1">
          Employer: <strong>{user.employerName}</strong>
        </Typography>
        <Typography variant="subtitle1" gutterBottom>
          Total Points: {user.points}
        </Typography>

        <Divider sx={{ my: 2 }} />

        <Typography variant="h6">New Carbon Credit Request</Typography>
        <Box display="flex" gap={2} mb={2}>
          <Select value={mode} onChange={(e) => setMode(e.target.value)} fullWidth>
            <MenuItem value="car">Car (10 pts/mile)</MenuItem>
            <MenuItem value="bus">Bus (20 pts/mile)</MenuItem>
            <MenuItem value="bike">Bike (30 pts/mile)</MenuItem>
          </Select>
          <Button
            variant="contained"
            onClick={sendRequest}
            disabled={isSubmitting || !startSet || !endSet}
          >
            {isSubmitting ? 'Submitting...' : 'Submit'}
          </Button>
        </Box>

        <Box mb={2}>
          <Typography variant="subtitle2">Track your trip</Typography>
          <MapTracker
            setDistance={setDistance}
            setStartLocation={(loc) => {
              setStartLocation(loc);
              setStartSet(true);
            }}
            setEndLocation={(loc) => {
              setEndLocation(loc);
              setEndSet(true);
            }}
            startSet={startSet}
            endSet={endSet}
          />
          {distance && (
            <Typography sx={{ mt: 1 }}>
              Distance detected: <strong>{distance} km</strong>
            </Typography>
          )}
        </Box>

        <Divider sx={{ my: 2 }} />

        <Typography variant="h6">Your Requests</Typography>
        {requests.length > 0 ? (
          <List>
            {requests.map((req) => (
              <ListItem key={req._id} divider>
                <ListItemText
                  primary={`${req.mode.toUpperCase()} - ${req.points} pts`}
                  secondary={`Distance: ${req.distance} km | Status: ${req.status}`}
                />
                <ListItemSecondaryAction>
                  <Button
                    variant="outlined"
                    color="error"
                    disabled={req.status === 'approved'}
                    onClick={() => handleDismiss(req._id)}
                  >
                    Dismiss
                  </Button>
                </ListItemSecondaryAction>
              </ListItem>
            ))}
          </List>
        ) : (
          <Typography>No requests submitted yet.</Typography>
        )}
      </Paper>
    </Container>
  ) : (
    <Typography sx={{ mt: 5, textAlign: 'center' }}>Loading...</Typography>
  );
};

export default EmployeeDashboard;
