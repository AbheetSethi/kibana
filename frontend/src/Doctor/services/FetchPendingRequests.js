import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

const getPendingRequests = async () => {
  try {
    const role = 'doctor';  // fixed role

    // console.log('Using role:', role);

    const tokenKey = `token_${role}`;  
    const token = localStorage.getItem(tokenKey);

    if (!token) {
      throw new Error('Token not found for doctor');
    }

    const response = await axios.get(`${API_URL}/get-pending-requests`, {
      headers: {
        Authorization: `Bearer ${token}`,  // use token_doctor
      },
    });

    return response;
  } catch (error) {
    console.error('Error fetching pending requests:', error);
    throw error;
  }
};

export default {
  getPendingRequests,
};
