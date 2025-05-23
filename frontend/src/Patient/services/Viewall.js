import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

const pastdata = async (pid) => {
  try {
    const role = 'patient';  // hardcoded role
    const userId = pid;      // use pid as userId

    // console.log('Using role:', role);
    // console.log('Using userId:', userId);

    // Construct the token key using hardcoded role and pid
    const tokenKey = `token_${role}_${userId}`;

    // Retrieve the token for this patient
    const token = localStorage.getItem(tokenKey);

    if (!token) {
      throw new Error('No token found for current patient');
    }

    const response = await axios.get(`${API_URL}/get_data/${pid}`, {
      headers: {
        Authorization: `Bearer ${token}` // Add JWT to headers
      }
    });

    return response;
  } catch (error) {
    console.error('Error fetching past data:', error);
    throw error;
  }
};

export default {
  pastdata,
};
