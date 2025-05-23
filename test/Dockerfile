FROM python:3.9-slim

WORKDIR /app

# Copy and install requirements
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy test script and images
COPY test_model.py .
COPY img/ img/

# Run test
CMD ["python", "test_model.py"]
