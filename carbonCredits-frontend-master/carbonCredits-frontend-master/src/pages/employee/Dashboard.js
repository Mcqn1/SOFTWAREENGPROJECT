import React, { useEffect, useState } from 'react';
import {
  Typography,
  Paper,
  Select,
  MenuItem,
  Button,
  Box,
  Divider,
  Stack,
  Snackbar,
  Alert,
  Collapse,
} from '@mui/material';
import axios from '../../axios';
import MapTracker from '../MapTracker';
import L from 'leaflet';

const EmployeeDashboard = () => {
  const [user, setUser] = useState(null);
  const [mode, setMode] = useState('car');
  const [distance, setDistance] = useState('');
  const [startLocation, setStartLocation] = useState(null);
  const [endLocation, setEndLocation] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [startSet, setStartSet] = useState(false);
  const [endSet, setEndSet] = useState(false);
  const [showRequestForm, setShowRequestForm] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await axios.post('/auth/token/me');
        setUser(res.data);
      } catch (err) {
        console.error('Error fetching user:', err);
      }
    };
    fetchUser();
  }, []);

  const sendRequest = async () => {
    if (!startLocation || !endLocation) {
      setSnackbar({ open: true, message: 'Please select both start and end locations.', severity: 'error' });
      return;
    }

    const payload = {
      mode,
      distance: parseFloat(distance),
      startLocation,
      endLocation,
      location: endLocation,
    };

    try {
      setIsSubmitting(true);
      await axios.post('/api/requests', payload);
      setDistance('');
      setStartLocation(null);
      setEndLocation(null);
      setStartSet(false);
      setEndSet(false);
      setShowRequestForm(false);
      setSnackbar({ open: true, message: 'Request submitted successfully!', severity: 'success' });
    } catch (err) {
      setSnackbar({ open: true, message: err.response?.data?.message || 'Request failed', severity: 'error' });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const setMapPoint = (isStart = true) => {
    navigator.geolocation.getCurrentPosition(
      (position) => {
        const { latitude, longitude } = position.coords;
        const coords = [latitude, longitude];
        const label = isStart ? 'Start Point' : 'End Point';

        if (window._leafletMap) {
          const marker = L.marker(coords).addTo(window._leafletMap).bindPopup(label).openPopup();
          if (isStart) {
            if (window._startMarker) window._leafletMap.removeLayer(window._startMarker);
            window._startMarker = marker;
            setStartLocation({ latitude, longitude });
            setStartSet(true);
          } else {
            if (window._endMarker) window._leafletMap.removeLayer(window._endMarker);
            window._endMarker = marker;
            setEndLocation({ latitude, longitude });
            setEndSet(true);

            if (startLocation) {
              const dist = calculateDistance(
                [startLocation.latitude, startLocation.longitude],
                [latitude, longitude]
              );
              setDistance(dist.toFixed(2));
            }
          }
          window._leafletMap.setView(coords, 14);
        }
      },
      (err) => console.warn('Geolocation error:', err)
    );
  };

  const goToCurrentLocation = () => {
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        const { latitude, longitude } = pos.coords;
        if (window._leafletMap) {
          window._leafletMap.setView([latitude, longitude], 14);
        }
      },
      (err) => console.warn('Geolocation error:', err)
    );
  };

  const calculateDistance = ([lat1, lon1], [lat2, lon2]) => {
    const R = 6371;
    const dLat = deg2rad(lat2 - lat1);
    const dLon = deg2rad(lon2 - lon1);
    const a =
      Math.sin(dLat / 2) ** 2 +
      Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) * Math.sin(dLon / 2) ** 2;
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  };

  const deg2rad = (deg) => deg * (Math.PI / 180);

  const handleCancel = () => {
    // Reset the form and location states when Cancel is clicked
    setStartLocation(null);
    setEndLocation(null);
    setStartSet(false);
    setEndSet(false);
    setDistance('');
    setShowRequestForm(false); // Hide the request form
    // Remove markers from map
    if (window._startMarker) {
      window._leafletMap.removeLayer(window._startMarker);
      window._startMarker = null;
    }
    if (window._endMarker) {
      window._leafletMap.removeLayer(window._endMarker);
      window._endMarker = null;
    }
  };

  if (!user) return <Typography align="center" sx={{ mt: 5 }}>Loading...</Typography>;

  return (
    <Box maxWidth="md" mx="auto" sx={{ mt: 5 }}>
      <Paper elevation={3} sx={{ p: 4, borderRadius: 3, background: 'linear-gradient(to right, #e8f5e9, #f1f8e9)' }}>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Typography variant="h5" fontWeight="bold" color="green">Request Portal</Typography>
          <Button
            variant={showRequestForm ? 'contained' : 'outlined'}
            color={showRequestForm ? 'error' : 'success'}
            onClick={() => {
              if (showRequestForm) {
                handleCancel();  // Call the handleCancel to reset
              } else {
                setShowRequestForm(true); // Show the form if it's not showing
              }
            }}
          >
            {showRequestForm ? 'Cancel Request' : 'New Request'}
          </Button>
        </Box>

        <Divider sx={{ my: 2 }} />

        <Collapse in={showRequestForm}>
          <Box display="flex" flexDirection={{ xs: 'column', md: 'row' }} gap={4}>
            {/* Left Panel */}
            <Box flex={1}>
              <Select
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                fullWidth
                sx={{ mb: 2 }}
              >
                <MenuItem value="car">Car (10 pts/km)</MenuItem>
                <MenuItem value="bus">Bus (20 pts/km)</MenuItem>
                <MenuItem value="bike">Bike (30 pts/km)</MenuItem>
              </Select>

              <Button
                variant="contained"
                color="success"
                onClick={sendRequest}
                disabled={isSubmitting || !startSet || !endSet}
                fullWidth
                sx={{ mb: 2 }}
              >
                {isSubmitting ? 'Submitting...' : 'Submit'}
              </Button>

              <Stack spacing={1}>
                <Button size="small" variant="outlined" onClick={() => setMapPoint(true)} disabled={startSet}>
                  📍 Set Start
                </Button>
                <Button size="small" variant="outlined" onClick={() => setMapPoint(false)} disabled={endSet}>
                  🏁 Set End
                </Button>
                <Button size="small" variant="outlined" onClick={goToCurrentLocation}>
                  🧭 Current Location
                </Button>
              </Stack>

              {distance && (
                <Typography sx={{ mt: 2 }} color="green">
                  Distance: <strong>{distance} km</strong>
                </Typography>
              )}
            </Box>

            {/* Right Panel */}
            <Box flex={1}>
              <MapTracker />
            </Box>
          </Box>
        </Collapse>

      </Paper>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity={snackbar.severity} variant="filled" onClose={handleCloseSnackbar}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default EmployeeDashboard;
