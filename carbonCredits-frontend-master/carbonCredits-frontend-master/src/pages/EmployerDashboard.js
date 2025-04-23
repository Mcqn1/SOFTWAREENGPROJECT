import React, { useEffect, useState } from 'react';
import {
  Container,
  Typography,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Button,
  Box,
  Divider,
  CircularProgress,
} from '@mui/material';
import axios from '../axios';

const EmployerDashboard = () => {
  const [requests, setRequests] = useState([]);
  const [employer, setEmployer] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchEmployer();
    fetchRequests();
  }, []);

  const fetchEmployer = async () => {
    try {
      const res = await axios.post('/auth/token/me');
      setEmployer(res.data);
    } catch (err) {
      console.error('Error fetching employer info:', err);
    }
  };

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

  return (
    <Container maxWidth="md" sx={{ mt: 5 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h4" align="center" gutterBottom>
          Employer Dashboard
        </Typography>

        {employer && (
          <Typography variant="subtitle1" align="center" gutterBottom>
            Logged in as: <strong>{employer.fullName}</strong>
          </Typography>
        )}

        <Divider sx={{ my: 3 }} />

        {/* ✅ Show count of pending requests */}
        <Typography variant="h6" gutterBottom>
          Pending Carbon Credit Requests ({requests.length})
        </Typography>

        {loading ? (
          <Box display="flex" justifyContent="center" alignItems="center" sx={{ minHeight: '200px' }}>
            <CircularProgress />
          </Box>
        ) : requests.length === 0 ? (
          <Typography>No pending requests.</Typography>
        ) : (
          <List>
            {requests.map((req) => {
              const start = req.startLocation?.coordinates || [];
              const end = req.endLocation?.coordinates || [];

              return (
                <ListItem key={req._id} divider alignItems="flex-start" sx={{ py: 2, flexDirection: 'column' }}>
                  <ListItemText
                    primary={`${req.mode.toUpperCase()} - ${req.points} pts`}
                    secondary={
                      <>
                        <Typography variant="body2" color="textSecondary">
                          Employee: {req.employeeId?.fullName || 'N/A'}
                        </Typography>
                        <Typography variant="body2" color="textSecondary">
                          Distance: {req.distance} km • Status: {req.status}
                        </Typography>
                        <Typography variant="body2" color="textSecondary">
                          Start: {start.length === 2 ? `${start[1]}, ${start[0]}` : 'Not set'}
                        </Typography>
                        <Typography variant="body2" color="textSecondary">
                          End: {end.length === 2 ? `${end[1]}, ${end[0]}` : 'Not set'}
                        </Typography>
                        <Typography variant="body2" color="textSecondary">
                          Created: {new Date(req.createdAt).toLocaleString()}
                        </Typography>
                      </>
                    }
                  />
                  <ListItemSecondaryAction>
                    <Box display="flex" gap={1}>
                      <Button
                        variant="contained"
                        color="success"
                        onClick={() => handleAction(req._id, 'approved')}
                      >
                        Approve
                      </Button>
                      <Button
                        variant="outlined"
                        color="error"
                        onClick={() => handleAction(req._id, 'rejected')}
                      >
                        Reject
                      </Button>
                    </Box>
                  </ListItemSecondaryAction>
                </ListItem>
              );
            })}
          </List>
        )}
      </Paper>
    </Container>
  );
};

export default EmployerDashboard;
