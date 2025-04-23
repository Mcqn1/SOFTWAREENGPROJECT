import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Grid,
  Stack,
  Button,
  CircularProgress,
  Typography,
  Container,
  Badge,
  Paper,
} from '@mui/material';
import axios from '../../axios';

const EmployerRequests = () => {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchRequests();
  }, []);

  const fetchRequests = async () => {
    try {
      const res = await axios.get('/api/requests/employer');
      setRequests(res.data);
    } catch (err) {
      console.error('Error fetching requests:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleAction = async (id, status) => {
    try {
      await axios.put(`/api/requests/${id}`, { status });
      fetchRequests();
    } catch (err) {
      console.error('Action failed:', err);
    }
  };

  const getModeIcon = (mode) => {
    switch (mode?.toLowerCase()) {
      case 'car':
        return '🚗';
      case 'bike':
        return '🚲';
      case 'bus':
        return '🚌';
      case 'walk':
        return '🚶‍♂️';
      case 'train':
        return '🚆';
      default:
        return '🛣️';
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" sx={{ minHeight: '200px' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Container maxWidth={false} sx={{ px: { xs: 2, sm: 6 }, py: 4 }}>
      <Paper elevation={3} sx={{ p: 2, borderRadius: 2, backgroundColor: '#e8f5e9' }}>
        <Typography variant="h6" gutterBottom>
          Employer Requests
        </Typography>
        <Badge badgeContent={requests.length} color="primary">
          <Typography variant="subtitle1">Total Requests</Typography>
        </Badge>
        <Box sx={{ maxHeight: '60vh', overflowY: 'auto', mt: 2 }}>
          <Stack spacing={1.5}>
            {requests.length === 0 ? (
              <Typography color="text.secondary">No pending requests.</Typography>
            ) : (
              requests.map((req) => {
                const start = req.startLocation?.coordinates || [];
                const end = req.endLocation?.coordinates || [];

                return (
                  <Card
                    key={req._id}
                    elevation={1}
                    sx={{
                      borderRadius: 2,
                      px: 2,
                      py: 1.5,
                      bgcolor: '#f9f9f9',
                      width: '100%',
                      maxWidth: '800px',
                      boxShadow: '0px 1px 3px rgba(0,0,0,0.06)',
                    }}
                  >
                    <CardContent>
                      <Grid container spacing={2} alignItems="center" justifyContent="space-between">
                        <Grid item xs={12} sm={9}>
                          <Typography variant="subtitle1" fontWeight="bold" sx={{ mb: 0.5 }}>
                            {getModeIcon(req.mode)} {req.mode.toUpperCase()} — {req.points} pts
                          </Typography>
                          <Stack spacing={0.3}>
                            <Typography variant="body2">
                              <strong>Employee:</strong> {req.employeeId?.fullName || 'N/A'}
                            </Typography>
                            <Typography variant="body2">
                              <strong>Distance:</strong> {req.distance} km
                            </Typography>
                            <Typography variant="body2">
                              <strong>Status:</strong> {req.status}
                            </Typography>
                            <Typography variant="body2">
                              <strong>Start:</strong>{' '}
                              {start.length === 2 ? `${start[1]}, ${start[0]}` : 'Not set'}
                            </Typography>
                            <Typography variant="body2">
                              <strong>End:</strong> {end.length === 2 ? `${end[1]}, ${end[0]}` : 'Not set'}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              Created: {new Date(req.createdAt).toLocaleString()}
                            </Typography>
                          </Stack>
                        </Grid>

                        <Grid item xs={12} sm="auto">
                          <Stack direction="row" spacing={1} justifyContent="flex-end" sx={{ mt: { xs: 1, sm: 0 } }}>
                            <Button
                              variant="contained"
                              color="success"
                              size="small"
                              onClick={() => handleAction(req._id, 'approved')}
                            >
                              Approve
                            </Button>
                            <Button
                              variant="outlined"
                              color="error"
                              size="small"
                              onClick={() => handleAction(req._id, 'rejected')}
                            >
                              Reject
                            </Button>
                          </Stack>
                        </Grid>
                      </Grid>
                    </CardContent>
                  </Card>
                );
              })
            )}
          </Stack>
        </Box>
      </Paper>
    </Container>
  );
};

export default EmployerRequests;
