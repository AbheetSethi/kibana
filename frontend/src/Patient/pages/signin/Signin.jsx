import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Container, Box, Typography, TextField, Button, Link, Paper, Alert, CircularProgress
} from "@mui/material";
import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import { toast } from "react-toastify";
import signin from "../../services/Signin";

const Signin = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSignin = async (e) => {
    e.preventDefault();

    if (!username || !password) {
      setError("Please enter both username and password");
      return;
    }

    setLoading(true);
    setError("");

    try {
      // Send credentials to backend - backend determines role
      const response = await signin.login({ username, password });

      if (response.status === 200 && response.data) {
        const { role, pid } = response.data;
        toast.success("Login successful!");
        if (role === "doctor") {
          console.log("Navigating to doctor:", role === "doctor", "pid:", pid);
          localStorage.setItem('doctor', 'true');
          navigate("/doctor/home");
        } else if (role === "patient" && pid) {
          navigate(`/home/${pid}`);
        } else {
          setError("Unknown user role.");
        }
      } else {
        setError("Invalid credentials. Please try again.");
      }
    } catch (err) {
      if (err.code === "ERR_NETWORK") {
        setError("Cannot connect to backend. Please make sure the Flask server is running and the API URL is correct.");
      } else if (err.response && err.response.data && err.response.data.error) {
        setError(err.response.data.error);
      } else {
        setError("Login failed. Please check your credentials and try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container component="main" maxWidth="xs">
      <Paper
        elevation={3}
        sx={{
          marginTop: 8,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          padding: 4,
          borderRadius: 2
        }}
      >
        <Box
          sx={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            width: "100%"
          }}
        >
          <LockOutlinedIcon sx={{ color: "#4051B5", fontSize: 40, mb: 1 }} />
          <Typography component="h1" variant="h5" sx={{ mb: 1, fontWeight: 600 }}>
            Welcome to DermaCare
          </Typography>
          <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
            Sign in to your account
          </Typography>

          {error && (
            <Alert severity="error" sx={{ width: "100%", mb: 2 }}>
              {error}
            </Alert>
          )}

          <Box component="form" onSubmit={handleSignin} sx={{ width: "100%" }}>
            <TextField
              margin="normal"
              required
              fullWidth
              label="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
            />

            <TextField
              margin="normal"
              required
              fullWidth
              label="Password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />

            <Button
              type="submit"
              fullWidth
              variant="contained"
              disabled={loading}
              sx={{
                mt: 3,
                mb: 2,
                backgroundColor: "#1976d2",
                "&:hover": {
                  backgroundColor: "#1565c0"
                }
              }}
            >
              {loading ? <CircularProgress size={24} color="inherit" /> : "SIGN IN"}
            </Button>

            <Box sx={{ textAlign: "center" }}>
              <Link
                href="#"
                variant="body2"
                onClick={() => navigate("/register")}
                sx={{ color: "#1976d2" }}
              >
                Don't have an account? Register
              </Link>
            </Box>
          </Box>
        </Box>
      </Paper>
    </Container>
  );
};

export default Signin;
