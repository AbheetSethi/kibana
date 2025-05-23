import React, { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  Box,
  Button,
  Container,
  Paper,
  TextField,
  Typography,
  CircularProgress,
  Alert,
} from "@mui/material";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import CreateRequestNavbar from "../../components/navbar/CreateRequestNavbar";
import { toast } from "react-toastify";
import createrequest from "../../services/Createrequest";

const UPLOAD_WIDTH = 220;

const CreateRequest = () => {
  const navigate = useNavigate();
  const { pid } = useParams();

  const [file, setFile] = useState(null);
  const [comments, setComments] = useState("");
  const [uploading, setUploading] = useState(false);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile?.type?.includes("image/")) {
      setFile(selectedFile);
      setErrorMsg("");
      const reader = new FileReader();
      reader.onloadend = () => setPreviewUrl(reader.result);
      reader.readAsDataURL(selectedFile);
    } else {
      setErrorMsg("Please select a valid image file (JPEG, PNG, JPG)");
      setFile(null);
      setPreviewUrl(null);
    }
  };

  const handleCommentsChange = (e) => setComments(e.target.value);

  const handleSubmit = async () => {
    if (!comments.trim()) return setErrorMsg("Please enter your query");
    if (!file) return setErrorMsg("Please upload an image");

    setUploading(true);
    setErrorMsg("");

    try {
      const createRes = await createrequest.createRequest({
        patientId: pid,
        comments,
        image: file,
      });

      if (createRes.status === 200) {
        toast.success("Request created successfully!");
        navigate(`/home/${pid}`, { replace: true });
      } else {
        toast.error("Failed to create request");
      }
    } catch (err) {
      console.error("Request error:", err);
      toast.error("An unexpected error occurred.");
    } finally {
      setUploading(false);
    }
  };

  return (
    <>
      <CreateRequestNavbar />
      <Container maxWidth="sm" sx={{ mt: 6, mb: 6 }}>
        <Paper
          elevation={3}
          sx={{
            p: 4,
            borderRadius: 3,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            background: "linear-gradient(135deg, #e3eaff 0%, #f8f9fa 100%)",
          }}
        >
          <Typography
            variant="h4"
            sx={{ fontWeight: 700, color: "#4051B5", mb: 2, textAlign: "center" }}
          >
            Create New Request
          </Typography>
          <Typography variant="subtitle1" sx={{ mb: 4, color: "#555", textAlign: "center" }}>
            Upload an image and submit your query for diagnosis
          </Typography>

          <Box sx={{ width: "100%" }}>
            <TextField
              fullWidth
              label="Patient Query"
              variant="outlined"
              multiline
              rows={6}
              value={comments}
              onChange={handleCommentsChange}
              placeholder="Please describe your symptoms or concerns..."
              sx={{ mb: 3 }}
            />

            <Box
              sx={{
                width: `${UPLOAD_WIDTH}px`,
                mx: "auto",
                border: "2px dashed #1976d2",
                borderRadius: 3,
                p: 2,
                textAlign: "center",
                backgroundColor: "#f5f7fa",
                cursor: "pointer",
                "&:hover": { borderColor: "#4051B5" },
                mb: 3,
              }}
              onClick={() => document.getElementById("file-upload").click()}
            >
              <input
                id="file-upload"
                type="file"
                style={{ display: "none" }}
                accept="image/*"
                onChange={handleFileChange}
              />
              <CloudUploadIcon sx={{ fontSize: 40, color: "#1976d2", mb: 1 }} />
              <Typography variant="body1" sx={{ fontWeight: 600 }}>
                {file ? file.name : "Choose file or drag & drop"}
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Supported formats: JPEG, PNG, JPG
              </Typography>
            </Box>

            {previewUrl && (
              <Box sx={{ textAlign: "center", mb: 3 }}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  Image Preview:
                </Typography>
                <img
                  src={previewUrl}
                  alt="Preview"
                  style={{
                    maxWidth: "100%",
                    maxHeight: "300px",
                    borderRadius: 8,
                    border: "1px solid #ddd",
                  }}
                />
              </Box>
            )}

            {errorMsg && (
              <Alert severity="error" sx={{ mb: 2, width: `${UPLOAD_WIDTH}px`, mx: "auto" }}>
                {errorMsg}
              </Alert>
            )}

            <Box sx={{ display: "flex", justifyContent: "center" }}>
              <Button
                variant="contained"
                disabled={uploading}
                onClick={handleSubmit}
                sx={{
                  width: `${UPLOAD_WIDTH}px`,
                  mt: 2,
                  fontSize: "1.1rem",
                  borderRadius: "8px",
                  textTransform: "none",
                  background: "linear-gradient(90deg, #4051B5 60%, #1976d2 100%)",
                  fontWeight: 600,
                  "&:hover": {
                    background: "linear-gradient(90deg, #303f9f 60%, #1565c0 100%)",
                  },
                }}
              >
                {uploading ? <CircularProgress size={24} color="inherit" /> : "Create Request"}
              </Button>
            </Box>

          </Box>
        </Paper>
      </Container>
    </>
  );
};

export default CreateRequest;
