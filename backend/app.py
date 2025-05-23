from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
from pymongo import MongoClient
from datetime import datetime
import base64
import os
from bson import ObjectId
import requests
from io import BytesIO

import logging
from logstash import TCPLogstashHandler  # Logstash logging
import socket

from cred import url
from encryption import encrypt_data, decrypt_data
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
import jwt_config

# pip install cryptography
# pip install pymongo
# pip install flask
# pip install flask_cors
# pip install flask-jwt-extended
# pip install python-logstash

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Configure JWT
app.config.from_object(jwt_config)
jwt = JWTManager(app)

# Get the ML service URL from environment variable
ml_service_url = os.getenv("ML_SERVICE_URL")

# MongoDB Config
client = MongoClient(url)

try:
    client.admin.command('ping')
    print("Connected to MongoDB")
except Exception as e:
    print("MongoDB connection failed:", e)
    raise

db = client["Patient"]
counter_collection = db["counters"]
user_collection = db["Login"]
patient_collection = db["Patient_info"]
diagnosis_result_collection = db["Diagnosis_Result"]
request_collection = db["Request"]

# Initialize counters if not present
if counter_collection.count_documents({"_id": "user_pid"}) == 0:
    counter_collection.insert_one({"_id": "user_pid", "seq": 1000})
if counter_collection.count_documents({"_id": "patient_id"}) == 0:
    counter_collection.insert_one({"_id": "patient_id", "seq": 1000})

# Logging configuration for Logstash
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# File handler - this logs to a local file
file_handler = logging.FileHandler('/var/log/backend/backend.log')
file_handler.setLevel(logging.INFO)

# Optional: add formatting
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

logstash_handler = TCPLogstashHandler(
    host='host.docker.internal',
    port=5044,
    version=1
)
logger.addHandler(logstash_handler)

logger.info('Flask app started from Kubernetes!')

# Auto-increment functions
def get_next_user_pid():
    counter = counter_collection.find_one_and_update(
        {"_id": "user_pid"},
        {"$inc": {"seq": 1}},
        return_document=True
    )
    return str(counter["seq"])

def get_next_patient_id():
    counter = counter_collection.find_one_and_update(
        {"_id": "patient_id"},
        {"$inc": {"seq": 1}},
        return_document=True
    )
    return str(counter["seq"])

# User registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    name = data.get('name')

    if not all([username, password, email, name]):
        logger.warning("Registration failed: Missing fields")
        return jsonify({"error": "All fields (username, password, email, name) are required"}), 400

    existing_user = user_collection.find_one({"username": username})
    if existing_user:
        logger.warning(f"Registration failed: User {username} already exists")
        return jsonify({"error": "User already exists"}), 409

    encrypted_password = encrypt_data(password)
    pid = get_next_user_pid()

    document = {
        "username": username,
        "password": encrypted_password,
        "email": email,
        "name": name,
        "pid": pid
    }

    user_collection.insert_one(document)
    logger.info(f"User registered: {username}")
    return jsonify({"message": f"User {username} registered successfully", "pid": pid}), 201

# User login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        logger.warning("Login failed: Missing username or password")
        return jsonify({"error": "Username and password are required"}), 400

    user = user_collection.find_one({"username": username})
    if not user or decrypt_data(user["password"]) != password:
        logger.warning(f"Login failed for user: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=username)
    logger.info(f"User logged in: {username}")
    return jsonify({"access_token": access_token, "pid": user["pid"]}), 200

# Add patient information
@app.route('/add_patient_info', methods=['POST'])
@jwt_required()
def add_patient_info():
    current_user = get_jwt_identity()
    data = request.json

    patient_id = get_next_patient_id()
    data["patient_id"] = patient_id
    data["created_by"] = current_user
    data["timestamp"] = datetime.now()

    patient_collection.insert_one(data)
    logger.info(f"Patient info added by {current_user} with ID {patient_id}")
    return jsonify({"message": "Patient info added successfully", "patient_id": patient_id}), 201

# Get all patient info
@app.route('/get_patient_info', methods=['GET'])
@jwt_required()
def get_patient_info():
    current_user = get_jwt_identity()
    patients = list(patient_collection.find({"created_by": current_user}))
    for p in patients:
        p["_id"] = str(p["_id"])
    logger.info(f"Fetched patient info for user {current_user}")
    return jsonify(patients), 200

# Upload image and send to ML model
@app.route('/upload_image/<patient_id>', methods=['POST'])
@jwt_required()
def upload_image(patient_id):
    if 'image' not in request.files:
        logger.warning("Upload failed: No image file found")
        return jsonify({"error": "No image file found"}), 400

    image_file = request.files['image']
    img_bytes = image_file.read()

    files = {'file': (image_file.filename, BytesIO(img_bytes), image_file.mimetype)}

    try:
        response = requests.post(f"{ml_service_url}/predict", files=files)
        if response.status_code == 200:
            prediction = response.json().get("prediction")
            result = {
                "patient_id": patient_id,
                "prediction": prediction,
                "timestamp": datetime.now()
            }
            diagnosis_result_collection.insert_one(result)
            logger.info(f"Prediction saved for patient {patient_id}")
            return jsonify({"prediction": prediction}), 200
        else:
            logger.error(f"ML service error: {response.text}")
            return jsonify({"error": "ML service error"}), 500
    except Exception as e:
        logger.error(f"Error connecting to ML service: {e}")
        return jsonify({"error": "Error connecting to ML service"}), 500

# Get diagnosis result
@app.route('/get_diagnosis/<patient_id>', methods=['GET'])
@jwt_required()
def get_diagnosis(patient_id):
    results = list(diagnosis_result_collection.find({"patient_id": patient_id}))
    for r in results:
        r["_id"] = str(r["_id"])
    logger.info(f"Diagnosis results fetched for patient {patient_id}")
    return jsonify(results), 200

# Request diagnosis
@app.route('/request_diagnosis', methods=['POST'])
@jwt_required()
def request_diagnosis():
    data = request.json
    data["timestamp"] = datetime.now()
    data["requested_by"] = get_jwt_identity()
    request_collection.insert_one(data)
    logger.info(f"Diagnosis requested by {data['requested_by']}")
    return jsonify({"message": "Diagnosis request submitted"}), 201

# View diagnosis requests
@app.route('/get_requests', methods=['GET'])
@jwt_required()
def get_requests():
    requests_data = list(request_collection.find())
    for r in requests_data:
        r["_id"] = str(r["_id"])
    logger.info("Diagnosis requests fetched")
    return jsonify(requests_data), 200

# Main entry point
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
