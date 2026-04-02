# Deployment Guide - Fly.io

This guide covers deploying the Security Automation Platform to Fly.io using a single container with supervisord.

## Prerequisites

- [Fly.io CLI](https://fly.io/docs/hands-on/install-flyctl/) installed
- Docker installed (for local testing)
- Fly.io account (free tier available)

## Architecture

The application runs in a single container with two processes managed by supervisord:
- **API** (FastAPI) on port 8000
- **UI** (Vue 3 SPA served via `serve`) on port 3000

## Local Testing

Before deploying to Fly.io, test the Docker container locally:

```bash
# Build the Docker image
docker build -t security-automation .

# Run the container
docker run -p 8000:8000 -p 3000:3000 \
  -e BEARER_TOKEN=test-token-123 \
  -e OPENAI_API_KEY=your-key-here \
  security-automation

# Test the endpoints
curl http://localhost:8000/health
# Open http://localhost:3000 in your browser
```

## Fly.io Deployment

### 1. Initial Setup

```bash
# Login to Fly.io
fly auth login

# Launch the app (creates fly.toml if needed)
fly launch --name security-automation-playbook --region iad
```

When prompted:
- Choose "No" for PostgreSQL database
- Choose "No" for Redis
- Review the generated `fly.toml` and confirm

### 2. Set Environment Variables

```bash
# Set the bearer token (change this!)
fly secrets set BEARER_TOKEN=your-secure-token-here

# Set OpenAI API key (optional, for ChatOps)
fly secrets set OPENAI_API_KEY=sk-your-openai-key
```

### 3. Deploy

```bash
# Deploy the application
fly deploy

# Monitor the deployment
fly status

# View logs
fly logs
```

### 4. Access Your Application

```bash
# Open the app in your browser
fly open

# Or get the URL
fly info
```

Your app will be available at: `https://security-automation-playbook.fly.dev`

## Configuration

### fly.toml

The `fly.toml` file configures:
- **Auto-stop/start**: Machines stop when idle and start on request (free tier friendly)
- **Regions**: Primary region is `iad` (US East)
- **Ports**: Exposes both 8000 (API) and 3000 (UI)
- **Health checks**: TCP checks on port 8000

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `BEARER_TOKEN` | Yes | API authentication token |
| `OPENAI_API_KEY` | No | OpenAI API key for ChatOps agent |

## Monitoring

```bash
# View real-time logs
fly logs

# Check application status
fly status

# View resource usage
fly dashboard
```

## Scaling

```bash
# Scale to multiple machines (if needed)
fly scale count 2

# Scale machine size
fly scale vm shared-cpu-1x --memory 512

# Scale back to free tier
fly scale count 1
fly scale vm shared-cpu-1x --memory 256
```

## Troubleshooting

### Container won't start

```bash
# Check logs
fly logs

# SSH into the container
fly ssh console

# Check supervisord status
supervisorctl status
```

### API not responding

```bash
# Check if API process is running
fly ssh console
supervisorctl status api

# View API logs
cat /var/log/supervisor/api.err.log
```

### UI not loading

```bash
# Check if UI process is running
fly ssh console
supervisorctl status ui

# View UI logs
cat /var/log/supervisor/ui.err.log
```

## Cost Optimization

The application is optimized for Fly.io's free tier:
- **Auto-stop**: Machines stop when idle
- **Auto-start**: Machines start on first request
- **Single container**: Both API and UI in one container
- **Minimal resources**: 256MB RAM, shared CPU

Free tier includes:
- Up to 3 shared-cpu-1x VMs with 256MB RAM
- 160GB outbound data transfer
- Automatic SSL certificates

## Updates

```bash
# Deploy new version
fly deploy

# Rollback to previous version
fly releases
fly rollback <version>
```

## Cleanup

```bash
# Destroy the app (if needed)
fly apps destroy security-automation-playbook
```
