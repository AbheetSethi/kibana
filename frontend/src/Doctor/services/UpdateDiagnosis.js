import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

const updateDiagnosis = async (diagnosisData) => {
  try {
    const role = 'doctor';  // fixed role

    const tokenKey = `token_${role}`;  
    const token = localStorage.getItem(tokenKey);

    if (!token) {
      throw new Error('Token not found for current user');
    }

    const response = await axios.post(`${API_URL}/update-diagnosis`, diagnosisData, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    return response;
  } catch (error) {
    console.error('Error updating diagnosis:', error);
    throw error;
  }
};

export default {
  updateDiagnosis,
};
