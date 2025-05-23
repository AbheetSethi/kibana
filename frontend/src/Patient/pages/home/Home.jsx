import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { 
  Typography, Container, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, CircularProgress, Box
} from "@mui/material";
import moment from "moment";
import { toast } from "react-toastify";
import viewall from "../../services/Viewall";
import HomeNavbar from "../../components/navbar/HomeNavbar";
import "./home.css";

const Home = () => {
  const { pid } = useParams();
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await viewall.pastdata(pid);
        console.log("API Response:", response.data); // Log the data to inspect
        if (response.data && Array.isArray(response.data.data)) {
          setRecords(response.data.data);
        } else {
          toast.error("Failed to load diagnosis history: Invalid data format");
        }
        setLoading(false);
      } catch (error) {
        console.error("Error fetching data:", error);
        toast.error("Failed to load diagnosis history");
        setLoading(false);
      }
    };
    fetchData();
  }, [pid]);

  // const getStatusBadgeStyle = (status) => {
  //   const styles = {
  //     Completed: { backgroundColor: "#e6f7ee", color: "#0d904f" },
  //     "In Progress": { backgroundColor: "#fff4e5", color: "#ab6100" },
  //     Pending: { backgroundColor: "#f8f9fa", color: "#666" }
  //   };
  //   return styles[status] || styles.Pending;
  // };

  const getStatusBadgeStyle = (status) => {
    const styles = {
      Pending: { backgroundColor: "#f8f9fa", color: "#666" },
      Reviewed: { backgroundColor: "#e6f7ee", color: "#0d904f" }
    };
    return styles[status] || styles.Pending; // Default to 'Pending' style
  };
  

  return (
    <>
      <HomeNavbar />
      <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
        <Paper elevation={3} sx={{ p: 4, mb: 4, backgroundColor: "#f8f9fa" }}>
          <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: "#4051B5", mb: 3 }}>
            Previous Diagnoses
          </Typography>
          {loading ? (
            <Box sx={{ display: "flex", justifyContent: "center" }}>
              <CircularProgress sx={{ color: "#4051B5" }} />
            </Box>
          ) : records.length === 0 ? (
            <Paper elevation={2} sx={{ p: 4, textAlign: "center" }}>
              <Typography variant="body1" color="textSecondary">
                No previous diagnoses found
              </Typography>
            </Paper>
          ) : (
            <TableContainer component={Paper} elevation={2}>
            <Table>
              <TableHead sx={{ backgroundColor: "#e8eaf6" }}>
                <TableRow>
                  <TableCell>Date</TableCell>
                  <TableCell>Image</TableCell>
                  <TableCell>Patient Comments</TableCell> 
                  <TableCell>ML Diagnosis</TableCell>
                  <TableCell>Doctor Diagnosis</TableCell>
                  <TableCell>Doctor Comments</TableCell>
                  <TableCell>Status</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {Array.isArray(records) && records.length > 0 ? (
                  records.map((record) => (
                    <TableRow key={record.appointment_id}>
                      <TableCell>{moment(record.date).format("MMM D, YYYY")}</TableCell>
                      <TableCell>
                        {record.imagePath ? (
                          <img
                            src={`data:image/jpeg;base64,${record.imagePath}`}
                            alt="Patient"
                            style={{ width: "100px", height: "auto" }}
                          />
                        ) : (
                          "No image"
                        )}
                      </TableCell>
                      <TableCell>{record.patientComments || "No patient comments yet"}</TableCell> 
                      <TableCell>{record.mlDiagnosis || "No ML diagnosis yet"}</TableCell>
                      <TableCell>{record.doctorDiagnosis || "No doctor diagnosis yet"}</TableCell>
                      <TableCell>{record.doctorComments || "No comments yet"}</TableCell>
                      <TableCell>
                        <Box sx={{ 
                          display: "inline-block",
                          px: 1.5,
                          py: 0.5,
                          borderRadius: 1,
                          ...getStatusBadgeStyle(record.status),
                          fontWeight: 500
                        }}>
                          {record.status || "Pending"}
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={7} style={{ textAlign: "center" }}> {/* Updated colspan */}
                      No records found
                    </TableCell>
                  </TableRow>
                )}
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
