/**
 * Frontend Health Check API Endpoint
 * Used for Docker healthcheck and monitoring
 */
export async function GET() {
  return Response.json({
    status: 'healthy',
    service: 'frontend',
    timestamp: new Date().toISOString(),
  });
}
