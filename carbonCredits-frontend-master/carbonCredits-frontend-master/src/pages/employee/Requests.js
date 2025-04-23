import React, { useEffect, useState } from "react";
import {
  Typography,
  Paper,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Button,
  Box,
  Divider,
  CircularProgress,
  Stack,
} from "@mui/material";
import DeleteIcon from "@mui/icons-material/Delete";
import CloseIcon from "@mui/icons-material/Close";
import axios from "../../axios";

const EmployeeRequests = () => {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchRequests();
  }, []);

  const fetchRequests = async () => {
    try {
      const res = await axios.get("/api/requests/employee");
      setRequests(res.data);
    } catch (err) {
      console.error("Error fetching employee requests:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleDismiss = async (id) => {
    try {
      await axios.delete(`/api/requests/${id}`);
      fetchRequests();
    } catch (err) {
      console.error("Error dismissing request:", err);
    }
  };

  const handleDelete = async (id, status) => {
    if (status === "approved") {
      // Only remove from UI
      setRequests((prev) => prev.filter((r) => r._id !== id));
      return;
    }

    try {
      await axios.delete(`/api/requests/${id}`);
      setRequests((prev) => prev.filter((r) => r._id !== id)); // Remove from UI after DB delete
    } catch (err) {
      console.error("Delete failed:", err);
    }
  };

  return (
    <main>
      <Paper
        elevation={3}
        sx={{
          borderRadius: 2,
          p: 3,
          height: "75vh",
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <Box sx={{ mb: 2 }}>
          <Typography variant="h5" gutterBottom>
            My Requests
          </Typography>
          <Divider />
        </Box>

        <Box sx={{ overflowY: "auto", flexGrow: 1, pr: 1 }}>
          {loading ? (
            <Box display="flex" justifyContent="center">
              <CircularProgress />
            </Box>
          ) : requests.length === 0 ? (
            <Typography>You are done.</Typography>
          ) : (
            <List>
              {requests.map((req) => (
                <ListItem
                  key={req._id}
                  divider
                  alignItems="flex-start"
                  sx={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "flex-start",
                  }}
                >
                  <Box
                    sx={{
                      width: "100%",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <Typography variant="subtitle1" fontWeight="bold">
                      {req.mode.toUpperCase()} - {req.points} pts
                    </Typography>
                    <Stack direction="row" spacing={1}>
                      <IconButton
                        color="error"
                        size="small"
                        disabled={req.status === "approved"}
                        onClick={() => handleDismiss(req._id)}
                      >
                        <CloseIcon />
                      </IconButton>
                      <IconButton
                        color="secondary"
                        size="small"
                        onClick={() => handleDelete(req._id, req.status)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Stack>
                  </Box>
                  <Box sx={{ mt: 1 }}>
                    <Typography variant="body2">
                      Distance: {req.distance} km
                    </Typography>
                    <Typography variant="body2">Status: {req.status}</Typography>
                    <Typography variant="body2">
                      Submitted on: {new Date(req.createdAt).toLocaleString()}
                    </Typography>
                  </Box>
                </ListItem>
              ))}
            </List>
          )}
        </Box>
      </Paper>
    </main>
  );
};

export default EmployeeRequests;
