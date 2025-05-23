import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';


const login = async (credentials) => {
  try {
    const response = await axios.post(`${API_URL}/verify`, credentials, {
      headers: { 'Content-Type': 'application/json' },
    });

    if (response.data && response.data.token) {
      const { token, role, pid: userId } = response.data;

      if (role === 'doctor') {
        // console.log(token);
        localStorage.setItem('token_doctor', token);
      } else if (role === 'patient') {
        // console.log(token);
        localStorage.setItem(`token_patient_${userId}`, token);
      }

      localStorage.setItem(`user_${role}_${userId}`, JSON.stringify(response.data));
      localStorage.setItem('current_role', role);
      localStorage.setItem('current_user_id', userId);
    }

    return response;
  } catch (error) {
    if (error.response) {
      console.error('Login error:', error.response.data);
    } else if (error.request) {
      console.error('Login error: No response from server.');
    } else {
      console.error('Login error:', error.message);
    }
    throw error;
  }
};

export default {
  login,
};
