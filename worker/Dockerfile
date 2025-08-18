FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the ChatGPT security scanner
COPY worker/main.py .

# Set environment variables for multiple API keys (4 per worker)
ENV OPENAI_API_KEY=""
ENV OPENAI_API_KEY_1=""
ENV OPENAI_API_KEY_2=""
ENV OPENAI_API_KEY_3=""
ENV OPENAI_API_KEY_4=""

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Run the application
CMD ["python", "main.py"]
