/**
 * Environment Configuration
 * Securely manages environment variables and API keys
 */

export const config = {
  portal: {
    url: import.meta.env.VITE_PORTAL_URL || 'http://localhost:8000',
    bearerToken: import.meta.env.VITE_BEARER_TOKEN || 'your-secret-token-123'
  }
}
