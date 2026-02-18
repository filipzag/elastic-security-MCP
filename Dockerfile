# Use a lightweight Python image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code
COPY server.py .

# Expose port (facultative, usually stdio is used for MCP but good practice)
# ENV PORT=8000 
# EXPOSE 8000

# Run the server
ENTRYPOINT ["python", "server.py"]
