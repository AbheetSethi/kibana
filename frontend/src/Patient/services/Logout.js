const logout = () => {
    // Clear all local storage items related to authentication
    localStorage.removeItem('token');
    localStorage.removeItem('pid');
  };
  
  export default {
    logout,
  };
  