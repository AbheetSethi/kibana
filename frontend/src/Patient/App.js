import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './App.css';

// Import context provider
import MyContextProvider from './components/MyContext/MyContextProvider';

// Import pages
import Home from './pages/home/Home';
import Signin from './pages/signin/Signin';
import Register from './pages/register/Register';
import CreateRequest from './pages/createrequest/CreateRequest';

function App() {
  return (
    <MyContextProvider>
      <Router>
        <Routes>
          <Route path="/" element={<Navigate to="/signin" />} />
          <Route path="/signin" element={<Signin />} />
          <Route path="/register" element={<Register />} />
          <Route path="/home/:pid" element={<Home />} />
          <Route path="/createrequest/:pid" element={<CreateRequest />} />
        </Routes>
        <ToastContainer position="bottom-right" />
      </Router>
    </MyContextProvider>
  );
}

export default App;
