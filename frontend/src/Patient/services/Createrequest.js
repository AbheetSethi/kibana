import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

const createRequest = async ({ patientId, comments, image }) => {
  try {
    const role = 'patient'; // hardcoded role
    const userId = patientId; // use patientId as userId

    console.log('Using role:', role);
    console.log('Using userId:', userId);

    const tokenKey = `token_${role}_${userId}`;
    const token = localStorage.getItem(tokenKey);

    if (!token) {
      throw new Error('No token found for current user');
    }

    const formData = new FormData();
    formData.append('patientId', patientId);
    formData.append('comments', comments);

    console.log("Image FOUND:", image);
    if (image) {
      formData.append('image', image);
    }

    const response = await axios.post(`${API_URL}/create-request`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
        Authorization: `Bearer ${token}`,  // Add token here
      },
    });

    return response;
  } catch (error) {
    console.error('Error creating request:', error);
    throw error;
  }
};

export default {
  createRequest,
};
