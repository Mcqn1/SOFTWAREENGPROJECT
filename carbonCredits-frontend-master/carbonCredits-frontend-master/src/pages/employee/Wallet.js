import React, { useEffect, useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Tabs,
  Tab,
  Divider,
  Stack,
  ToggleButtonGroup,
  ToggleButton,
  TextField,
  Button,
  Alert,
  CircularProgress,
  List,
  ListItem,
  ListItemText,
  Chip,
} from '@mui/material';
import axios from '../../axios';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import ArrowUpwardIcon from '@mui/icons-material/ArrowUpward';

const POINT_TO_RUPEE = 1.5;

const Wallet = () => {
  const [user, setUser] = useState(null);
  const [transactions, setTransactions] = useState([]);
  const [tabIndex, setTabIndex] = useState(0);
  const [mode, setMode] = useState('buy');
  const [amount, setAmount] = useState('');
  const [message, setMessage] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchUser = async () => {
    try {
      const res = await axios.post('/auth/token/me');
      setUser(res.data);
    } catch (err) {
      console.error('Failed to load user:', err);
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await axios.get('/api/wallet/history');
      setTransactions(res.data);
    } catch (err) {
      console.error('Failed to load wallet history:', err);
    }
  };

  useEffect(() => {
    fetchUser();
    fetchHistory();
  }, []);

  const handleSubmit = async () => {
    if (!amount || isNaN(amount) || amount <= 0) {
      return setMessage({ type: 'error', text: 'Enter a valid number of points' });
    }

    if (mode === 'sell' && amount > user.points) {
      return setMessage({ type: 'error', text: 'You cannot sell more points than you have.' });
    }

    try {
      setLoading(true);
      await axios.post('/api/wallet', { action: mode, points: Number(amount) });

      const updatedPoints = mode === 'buy'
        ? user.points + Number(amount)
        : user.points - Number(amount);

      setUser({ ...user, points: updatedPoints });
      setAmount('');
      setMessage({ type: 'success', text: `Successfully ${mode === 'buy' ? 'bought' : 'sold'} ${amount} points.` });
      fetchHistory();
    } catch (err) {
      setMessage({ type: 'error', text: 'Transaction failed. Try again later.' });
    } finally {
      setLoading(false);
    }
  };

  if (!user) return <CircularProgress sx={{ m: 4 }} />;

  return (
    <Box p={3}>
      <Paper elevation={3} sx={{ p: 3 }}>
        <Tabs value={tabIndex} onChange={(e, newValue) => setTabIndex(newValue)} centered>
          <Tab label="Summary" />
          <Tab label="Buy/Sell" />
          <Tab label="History" />
        </Tabs>
        <Divider sx={{ my: 2 }} />

        {tabIndex === 0 && (
          <Box>
            <Typography variant="h6">Wallet Summary</Typography>
            <Typography variant="body1"><strong>Points:</strong> {user.points}</Typography>
            <Typography variant="body1"><strong>Equivalent in ₹:</strong> ₹{(user.points * POINT_TO_RUPEE).toFixed(2)}</Typography>
          </Box>
        )}

        {tabIndex === 1 && (
          <Box>
            <Typography variant="h6">Buy/Sell Points</Typography>
            <Stack spacing={2} mt={2}>
              <ToggleButtonGroup
                fullWidth
                color="primary"
                value={mode}
                exclusive
                onChange={(e, newMode) => newMode && setMode(newMode)}
              >
                <ToggleButton value="buy">BUY</ToggleButton>
                <ToggleButton value="sell">SELL</ToggleButton>
              </ToggleButtonGroup>

              <TextField
                label="Carbon Credits"
                type="number"
                fullWidth
                variant="outlined"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
              />

              <Button
                variant="contained"
                fullWidth
                onClick={handleSubmit}
                disabled={loading}
                size="large"
              >
                {loading ? 'Processing...' : mode === 'buy' ? 'Buy Points' : 'Sell Points'}
              </Button>

              {message && (
                <Alert severity={message.type}>{message.text}</Alert>
              )}
            </Stack>
          </Box>
        )}

        {tabIndex === 2 && (
          <Box>
            <Typography variant="h6" gutterBottom>Transaction History</Typography>
            <Divider sx={{ mb: 2 }} />
            {transactions.length === 0 ? (
              <Typography color="text.secondary">No transactions found.</Typography>
            ) : (
              <List sx={{ maxHeight: 300, overflowY: 'auto' }}>
                {transactions.map((txn) => (
                  <ListItem key={txn._id} divider>
                    <ListItemText
                      primary={
                        <Box display="flex" alignItems="center" gap={1}>
                          {txn.type === 'buy' ? (
                            <ArrowDownwardIcon color="success" fontSize="small" />
                          ) : (
                            <ArrowUpwardIcon color="error" fontSize="small" />
                          )}
                          <Typography variant="body1" fontWeight="bold">
                            {txn.type === 'buy' ? 'Credited' : 'Debited'}: {txn.points} pts
                          </Typography>
                        </Box>
                      }
                      secondary={txn.createdAt ? new Date(txn.createdAt).toLocaleString() : 'Date not available'}

                    />
                    <Chip
                      label={txn.type.toUpperCase()}
                      color={txn.type === 'buy' ? 'success' : 'error'}
                      size="small"
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </Box>
        )}
      </Paper>
    </Box>
  );
};

export default Wallet;
