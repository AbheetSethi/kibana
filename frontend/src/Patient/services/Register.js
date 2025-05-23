import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

const registerUser = async (userData) => {
  try {
    const response = await axios.post(`${API_URL}/register`, userData, {
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (response.data.access_token) {
      // Store JWT in localStorage for future requests
      localStorage.setItem('token', response.data.access_token);
    }

    return response;
  } catch (error) {
    console.error('Error registering user:', error);
    throw error;
  }
};

export default {
  registerUser,
};

