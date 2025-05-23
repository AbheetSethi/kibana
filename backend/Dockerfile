# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libgl1-mesa-glx \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements.txt and install Python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Set environment variable (NOT recommended for secrets)
ENV ENCRYPTION_KEY="bVck39AsLz8KNJY_UIT3uhZfRuFNDBRWv91lFEq4bF0="

# Expose the port the app runs on
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
