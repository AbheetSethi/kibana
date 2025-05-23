import React from 'react';
import { AppBar, Toolbar, Typography, Button, Box } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import HealthAndSafetyIcon from '@mui/icons-material/HealthAndSafety';

const DoctorNavbar = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('doctor');
    navigate('/signin');
  };

  return (
    <AppBar position="static" sx={{ backgroundColor: '#4051B5', color: '#fff' }} elevation={2}>
      <Toolbar>
        <Typography
          variant="h6"
          sx={{
            fontWeight: 'bold',
            fontSize: '1.5rem',
            display: 'flex',
            alignItems: 'center',
            flexGrow: 1,
          }}
        >
          <HealthAndSafetyIcon sx={{ mr: 1 }} /> 
          Teledermatology System - Doctor Portal
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            sx={{
              backgroundColor: 'rgba(255,255,255,0.1)',
              color: '#fff',
              borderRadius: '5px',
              textTransform: 'none',
              fontWeight: 500,
              fontSize: '1rem',
              '&:hover': { backgroundColor: 'rgba(255,255,255,0.2)' },
            }}
            onClick={handleLogout}
          >
            Logout
          </Button>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default DoctorNavbar;
