import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './App.css';

// Corrected imports based on your exact folder structure:
import Signin from './Patient/pages/signin/Signin';
import Register from './Patient/pages/register/Register';
import PatientHome from './Patient/pages/home/Home';
import DoctorHome from './Doctor/pages/home/Home';
import CreateRequest from './Patient/pages/createrequest/CreateRequest';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/signin" replace />} />
        <Route path="/signin" element={<Signin />} />
        <Route path="/register" element={<Register />} />
        <Route path="/home/:pid" element={<PatientHome />} />
        <Route path="/doctor/home" element={<DoctorHome />} />
        <Route path="/createrequest/:pid" element={<CreateRequest />} />
        <Route path="*" element={<Navigate to="/signin" replace />} />
      </Routes>
      <ToastContainer position="bottom-right" />
    </Router>
  );
}

export default App;
