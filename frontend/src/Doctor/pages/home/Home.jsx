import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Typography, Container, Paper, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, CircularProgress, Box, Button, FormControl, TextField, MenuItem
} from "@mui/material";
import moment from "moment";
import { toast } from "react-toastify";
import DoctorNavbar from "../../components/navbar/DoctorNavbar";
import FetchPendingRequests from "../../services/FetchPendingRequests";
import UpdateDiagnosis from "../../services/UpdateDiagnosis";

const DISEASE_CATEGORIES = [
  "Enfeksiyonel",
  "Acne",
  "Ekzama",
  "Benign",
  "Malign",
  "Pigment"
];

const Home = () => {
  const navigate = useNavigate();
  const [pendingRequests, setPendingRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [diagnoses, setDiagnoses] = useState({});

  useEffect(() => {
    const isDoctor = localStorage.getItem('doctor');
    if (!isDoctor) {
      navigate('/signin');
    }
  }, [navigate]);

  useEffect(() => {
    const fetchPendingRequests = async () => {
      try {
        const response = await FetchPendingRequests.getPendingRequests();
        if (response.data && Array.isArray(response.data.data)) {
          setPendingRequests(response.data.data);
          const initialDiagnoses = {};
          response.data.data.forEach(req => {
            initialDiagnoses[req.appointment_id] = {
              diagnosis: DISEASE_CATEGORIES[0],
              comments: ""
            };
          });
          setDiagnoses(initialDiagnoses);
        } else {
          toast.error("Failed to load pending requests: Invalid data format");
        }
        setLoading(false);
      } catch (error) {
        console.error("Error fetching pending requests:", error);
        toast.error("Failed to load pending requests");
        setLoading(false);
      }
    };

    fetchPendingRequests();
    const intervalId = setInterval(fetchPendingRequests, 30000);
    return () => clearInterval(intervalId);
  }, []);

  const handleDiagnosisChange = (appointmentId, value) => {
    setDiagnoses(prev => ({
      ...prev,
      [appointmentId]: {
        ...prev[appointmentId],
        diagnosis: value
      }
    }));
  };

  const handleCommentsChange = (appointmentId, value) => {
    setDiagnoses(prev => ({
      ...prev,
      [appointmentId]: {
        ...prev[appointmentId],
        comments: value
      }
    }));
  };

  const handleSubmit = async (appointmentId) => {
    try {
      setLoading(true);
      const diagnosisData = {
        appointment_id: appointmentId,
        doctorDiagnosis: diagnoses[appointmentId]?.diagnosis || DISEASE_CATEGORIES[0],
        doctorComments: diagnoses[appointmentId]?.comments || ""
      };
      const response = await UpdateDiagnosis.updateDiagnosis(diagnosisData);
      if (response.status === 200) {
        toast.success("Diagnosis submitted successfully");
        setPendingRequests(prev => prev.filter(req => req.appointment_id !== appointmentId));
      } else {
        toast.error("Failed to submit diagnosis");
      }
    } catch (error) {
      console.error("Error submitting diagnosis:", error);
      toast.error("An error occurred while submitting diagnosis");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <DoctorNavbar />
      <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
        <Paper elevation={3} sx={{ p: 4, mb: 4, backgroundColor: "#f8f9fa" }}>
          <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: "#4051B5", mb: 3 }}>
            Patient Request
          </Typography>
          {loading && pendingRequests.length === 0 ? (
            <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}>
              <CircularProgress sx={{ color: "#4051B5" }} />
            </Box>
          ) : pendingRequests.length === 0 ? (
            <Paper elevation={2} sx={{ p: 4, textAlign: "center" }}>
              <Typography variant="body1" color="textSecondary">
                No pending requests to review
              </Typography>
            </Paper>
          ) : (
            <TableContainer component={Paper} elevation={2}>
              <Table>
                <TableHead sx={{ backgroundColor: "#e8eaf6" }}>
                  <TableRow>
                    <TableCell>Date</TableCell>
                    <TableCell>Patient ID</TableCell>
                    <TableCell>Patient Comments</TableCell>
                    <TableCell>ML Diagnosis</TableCell>
                    <TableCell>Image</TableCell>
                    <TableCell>Doctor Diagnosis</TableCell>
                    <TableCell>Doctor Comments</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pendingRequests.map((request) => (
                    <TableRow key={request.appointment_id}>
                      <TableCell>{moment(request.date).format("MMM D, YYYY")}</TableCell>
                      <TableCell>{request.patientId}</TableCell>
                      <TableCell>{request.patientComments}</TableCell>
                      <TableCell>{request.mlDiagnosis || "Processing..."}</TableCell>
                      <TableCell>
                        {request.imagePath ? (
                          <img
                            src={`data:image/jpeg;base64,${request.imagePath}`}
                            alt="Patient"
                            style={{ width: "100px", height: "auto", borderRadius: 8, border: "1px solid #ddd" }}
                          />
                        ) : (
                          "No image"
                        )}
                      </TableCell>
                      <TableCell>
                        <FormControl fullWidth>
                          <TextField
                            select
                            label="Select Disease"
                            value={diagnoses[request.appointment_id]?.diagnosis || DISEASE_CATEGORIES[0]}
                            onChange={(e) => handleDiagnosisChange(request.appointment_id, e.target.value)}
                            sx={{ minWidth: 180 }}
                          >
                            {DISEASE_CATEGORIES.map((cat) => (
                              <MenuItem key={cat} value={cat}>
                                {cat}
                              </MenuItem>
                            ))}
                          </TextField>
                        </FormControl>
                      </TableCell>
                      <TableCell>
                        <TextField
                          variant="outlined"
                          placeholder="Enter comments..."
                          value={diagnoses[request.appointment_id]?.comments || ""}
                          onChange={(e) => handleCommentsChange(request.appointment_id, e.target.value)}
                          multiline
                          minRows={2}
                          maxRows={4}
                          sx={{
                            width: 180,
                            background: "#f7fafd",
                            borderRadius: 2,
                            "& .MuiOutlinedInput-root": {
                              "& fieldset": {
                                borderColor: "#bdbdbd"
                              },
                              "&:hover fieldset": {
                                borderColor: "#4051B5"
                              },
                              "&.Mui-focused fieldset": {
                                borderColor: "#4051B5"
                              }
                            }
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="contained"
                          color="primary"
                          onClick={() => handleSubmit(request.appointment_id)}
                          disabled={loading}
                          sx={{ mt: 1 }}
                        >
                          Submit Diagnosis
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Paper>
      </Container>
    </>
  );
};

export default Home;

