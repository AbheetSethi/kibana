import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  Box,
  Container,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Modal,
  CircularProgress,
  Grid,
} from "@mui/material";
import moment from "moment";
import HomeNavbar from '../../components/navbar/HomeNavbar';
import { toast } from "react-toastify";
import viewall from "../../services/Viewall";
import fetchImage from "../../services/Fetchimage";
import "./viewdiagnosis.css";

const ViewDiagnosis = () => {
  const { pid } = useParams();
  const [loading, setLoading] = useState(true);
  const [records, setRecords] = useState([]);
  const [imageData, setImageData] = useState("");
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [modalIsOpen, setModalIsOpen] = useState(false);
  const modalStyle = {
    position: "absolute",
    top: "50%",
    left: "50%",
    transform: "translate(-50%, -50%)",
    width: "70%",
    maxWidth: "800px",
    bgcolor: "#fff",
    border: "1px solid #ddd",
    boxShadow: 24,
    borderRadius: 2,
    p: 4,
    maxHeight: "90vh",
    overflow: "auto",
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await viewall.pastdata(pid);
        setRecords(response.data);
        if (response.status === 200) {
          toast.success("Successfully fetched diagnoses history");
        }
      } catch (error) {
        console.error("Error fetching data:", error);
        toast.error("Failed to fetch diagnosis history");
      }
      setLoading(false);
    };
    fetchData();
  }, [pid]);

  const handleViewImage = async (record) => {
    setSelectedRecord(record);
    setModalIsOpen(true);
    setImageData("");
    
    try {
      const response = await fetchImage.fetchimage(record.aid);
      const blob = response.data;
      const reader = new FileReader();
      reader.onloadend = () => {
        setImageData(reader.result);
      };
      reader.readAsDataURL(blob);
    } catch (error) {
      console.error("Error fetching image:", error);
      toast.error("Failed to load image");
    }
  };

  const handleCloseModal = () => {
    setModalIsOpen(false);
    setSelectedRecord(null);
    setImageData("");
  };

  const getStatusBadgeStyle = (status) => {
    if (status === "Completed") {
      return {
        backgroundColor: "#e6f7ee",
        color: "#0d904f"
      };
    } else if (status === "In Progress") {
      return {
        backgroundColor: "#fff4e5",
        color: "#ab6100"
      };
    } else {
      return {
        backgroundColor: "#f8f9fa",
        color: "#666"
      };
    }
  };

  return (
    <>
      <HomeNavbar />
      <Container maxWidth="lg" sx={{ mt: 5, mb: 5 }}>
        <Typography
          variant="h4"
          gutterBottom
          sx={{ fontWeight: 600, color: "#4051B5", mb: 3 }}
        >
          View Past Diagnoses
        </Typography>
        
        {loading ? (
          <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
            <CircularProgress sx={{ color: "#4051B5" }} />
          </Box>
        ) : records.length === 0 ? (
          <Paper
            elevation={2}
            sx={{ p: 4, textAlign: "center", backgroundColor: "#f8f9fa" }}
          >
            <Typography variant="h6" color="textSecondary">
              No diagnosis records found
            </Typography>
          </Paper>
        ) : (
          <TableContainer component={Paper} sx={{ borderRadius: 2, boxShadow: 2 }}>
            <Table sx={{ minWidth: 650 }}>
              <TableHead sx={{ backgroundColor: "#e8eaf6" }}>
                <TableRow>
                  <TableCell sx={{ fontWeight: "bold" }}>Appointment ID</TableCell>
                  <TableCell sx={{ fontWeight: "bold" }}>Date</TableCell>
                  <TableCell sx={{ fontWeight: "bold" }}>Image</TableCell>
                  <TableCell sx={{ fontWeight: "bold" }}>ML Diagnosis</TableCell>
                  <TableCell sx={{ fontWeight: "bold" }}>Doctor Diagnosis</TableCell>
                  <TableCell sx={{ fontWeight: "bold" }}>Status</TableCell>
                  <TableCell sx={{ fontWeight: "bold" }}>Doctor Comments</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {records.map((record) => (
                  <TableRow 
                    key={record.aid}
                    hover
                    sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                  >
                    <TableCell>{record.aid}</TableCell>
                    <TableCell>{moment(record.createdate).format("MMM D, YYYY")}</TableCell>
                    <TableCell>
                      <Button
                        variant="outlined"
                        size="small"
                        onClick={() => handleViewImage(record)}
                        sx={{ 
                          borderRadius: 2,
                          textTransform: "none",
                          borderColor: "#4051B5",
                          color: "#4051B5",
                          '&:hover': {
                            borderColor: "#303f9f",
                            backgroundColor: "rgba(64, 81, 181, 0.05)",
                          }
                        }}
                      >
                        View Image
                      </Button>
                    </TableCell>
                    <TableCell>{record.mldiagnosis || "Pending"}</TableCell>
                    <TableCell>{record.docdiagnosis || "Pending"}</TableCell>
                    <TableCell>
                      <Box
                        sx={{
                          display: "inline-block",
                          px: 1.5,
                          py: 0.5,
                          borderRadius: 1,
                          ...getStatusBadgeStyle(record.status),
                          fontWeight: 500,
                          fontSize: "0.875rem",
                        }}
                      >
                        {record.status || "Pending"}
                      </Box>
                    </TableCell>
                    <TableCell>{record.dcomments || "No comments yet"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Container>

      <Modal
        open={modalIsOpen}
        onClose={handleCloseModal}
        aria-labelledby="diagnosis-modal-title"
      >
        <Box sx={modalStyle}>
          <Typography
            id="diagnosis-modal-title"
            variant="h6"
            component="h2"
            sx={{ fontWeight: 600, mb: 2, color: "#4051B5" }}
          >
            Diagnosis Details
          </Typography>
          
          {selectedRecord && (
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                {imageData ? (
                  <Box sx={{ textAlign: "center" }}>
                    <img
                      src={imageData}
                      alt="Diagnosis"
                      style={{
                        maxWidth: "100%",
                        maxHeight: "400px",
                        borderRadius: 8,
                        border: "1px solid #ddd",
                      }}
                    />
                  </Box>
                ) : (
                  <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", height: 200 }}>
                    <CircularProgress sx={{ color: "#4051B5" }} />
                  </Box>
                )}
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="textSecondary">
                    Appointment ID
                  </Typography>
                  <Typography variant="body1">
                    {selectedRecord.aid}
                  </Typography>
                </Box>
                
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="textSecondary">
                    Date Created
                  </Typography>
                  <Typography variant="body1">
                    {moment(selectedRecord.createdate).format("MMMM D, YYYY")}
                  </Typography>
                </Box>
                
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="textSecondary">
                    ML Diagnosis
                  </Typography>
                  <Typography variant="body1">
                    {selectedRecord.mldiagnosis || "Pending"}
                  </Typography>
                </Box>
                
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="textSecondary">
                    Doctor Diagnosis
                  </Typography>
                  <Typography variant="body1">
                    {selectedRecord.docdiagnosis || "Pending"}
                  </Typography>
                </Box>
                
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="textSecondary">
                    Status
                  </Typography>
                  <Box
                    sx={{
                      display: "inline-block",
                      px: 1.5,
                      py: 0.5,
                      borderRadius: 1,
                      ...getStatusBadgeStyle(selectedRecord.status),
                      fontWeight: 500,
                      fontSize: "0.875rem",
                    }}
                  >
                    {selectedRecord.status || "Pending"}
                  </Box>
                </Box>
                
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="textSecondary">
                    Your Comments
                  </Typography>
                  <Typography variant="body1">
                    {selectedRecord.pcomments || "No comments provided"}
                  </Typography>
                </Box>
                
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="textSecondary">
                    Doctor Comments
                  </Typography>
                  <Typography variant="body1">
                    {selectedRecord.dcomments || "No comments yet"}
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          )}
          
          <Box sx={{ mt: 3, textAlign: "right" }}>
            <Button 
              onClick={handleCloseModal}
              variant="contained"
              sx={{
                backgroundColor: "#4051B5",
                textTransform: "none",
                borderRadius: 2,
                '&:hover': {
                  backgroundColor: "#303f9f",
                },
              }}
            >
              Close
            </Button>
          </Box>
        </Box>
      </Modal>
    </>
  );
};

export default ViewDiagnosis;
