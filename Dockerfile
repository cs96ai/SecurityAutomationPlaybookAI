# Multi-stage Dockerfile for Security Automation Platform
# Runs both API and UI in a single container using supervisord

# Stage 1: Build the Vue.js UI
FROM node:18-alpine AS ui-builder

WORKDIR /ui

COPY SecurityAutomation_UI/package*.json ./
RUN npm ci

COPY SecurityAutomation_UI/ ./
RUN npm run build

# Stage 2: Final runtime image
FROM python:3.11-slim

# Install Node.js for serving the UI and supervisord
RUN apt-get update && apt-get install -y \
    nodejs \
    npm \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Install a simple static file server
RUN npm install -g serve

WORKDIR /app

# Copy API files
COPY SecurityAutomation_API/requirements.txt ./api/
RUN pip install --no-cache-dir -r ./api/requirements.txt

COPY SecurityAutomation_API/ ./api/

# Copy built UI from builder stage
COPY --from=ui-builder /ui/dist ./ui/dist

# Copy supervisord configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Create .env file with default values
RUN echo "BEARER_TOKEN=your-secret-token-123" > ./api/.env

# Expose ports
# 8000 for API, 3000 for UI
EXPOSE 8000 3000

# Start supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
