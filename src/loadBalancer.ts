// Load Balancer Service for Multi-Cloud Backend
class LoadBalancerService {
  private endpoints: string[] = [
    'http://localhost:3001', // Local backend (working) - TEMPORARY for testing
    // Cloud backends are down - need redeployment
    // 'https://jobsemble-lf37e.ondigitalocean.app', // DigitalOcean - 404 errors
    // 'https://jobsemble-backend-392242000457.us-central1.run.app', // GCP - 404 errors
  ];
  
  private currentIndex = 0;
  private failedEndpoints = new Set<string>();
  private lastHealthCheck = new Map<string, number>();
  private healthCheckInterval = 30000; // 30 seconds

  constructor() {
    // Start health checking
    this.startHealthChecking();
  }

  private async startHealthChecking() {
    setInterval(() => {
      this.checkEndpointHealth();
    }, this.healthCheckInterval);
  }

  private async checkEndpointHealth() {
    for (const endpoint of this.endpoints) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
        
        const response = await fetch(`${endpoint}/api/health`, {
          signal: controller.signal,
          headers: {
            'Content-Type': 'application/json',
          },
        });
        
        clearTimeout(timeoutId);
        
        if (response.ok) {
          // Endpoint is healthy, remove from failed list
          this.failedEndpoints.delete(endpoint);
          this.lastHealthCheck.set(endpoint, Date.now());
          console.log(`✅ Health check passed: ${endpoint}`);
        } else {
          throw new Error(`Health check failed with status: ${response.status}`);
        }
      } catch (error) {
        // Endpoint is unhealthy, add to failed list
        this.failedEndpoints.add(endpoint);
        console.warn(`❌ Health check failed: ${endpoint}`, error);
      }
    }
  }

  private getHealthyEndpoints(): string[] {
    return this.endpoints.filter(endpoint => !this.failedEndpoints.has(endpoint));
  }

  private getNextEndpoint(): string {
    const healthyEndpoints = this.getHealthyEndpoints();
    
    if (healthyEndpoints.length === 0) {
      // All endpoints failed, use original list as fallback
      console.warn('⚠️ All endpoints failed, using fallback');
      return this.endpoints[0];
    }

    // Round-robin through healthy endpoints
    const endpoint = healthyEndpoints[this.currentIndex % healthyEndpoints.length];
    this.currentIndex++;
    
    return endpoint;
  }

  async makeRequest(path: string, options: RequestInit = {}): Promise<Response> {
    const maxRetries = this.endpoints.length;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const endpoint = this.getNextEndpoint();
      const url = `${endpoint}${path}`;

      try {
        console.log(`🌐 Attempting request to: ${endpoint}${path}`);
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
        
        const response = await fetch(url, {
          ...options,
          signal: controller.signal,
        });
        
        clearTimeout(timeoutId);
        
        if (response.ok) {
          console.log(`✅ Request successful: ${endpoint}`);
          return response;
        } else {
          throw new Error(`Request failed with status: ${response.status}`);
        }
      } catch (error) {
        console.warn(`❌ Request failed to ${endpoint}:`, error);
        lastError = error as Error;
        
        // Mark endpoint as failed temporarily
        this.failedEndpoints.add(endpoint);
        
        // Remove from failed list after 1 minute to allow recovery
        setTimeout(() => {
          this.failedEndpoints.delete(endpoint);
        }, 60000);
      }
    }

    // All endpoints failed
    throw new Error(`All backend endpoints failed. Last error: ${lastError?.message}`);
  }

  // Get status of all endpoints
  getStatus() {
    return {
      endpoints: this.endpoints.map(endpoint => ({
        url: endpoint,
        healthy: !this.failedEndpoints.has(endpoint),
        lastHealthCheck: this.lastHealthCheck.get(endpoint) || 0,
      })),
      currentEndpoint: this.getNextEndpoint(),
      healthyCount: this.getHealthyEndpoints().length,
      totalCount: this.endpoints.length,
    };
  }

  // Add endpoint dynamically
  addEndpoint(endpoint: string) {
    if (!this.endpoints.includes(endpoint)) {
      this.endpoints.push(endpoint);
      console.log(`➕ Added endpoint: ${endpoint}`);
    }
  }

  // Remove endpoint
  removeEndpoint(endpoint: string) {
    const index = this.endpoints.indexOf(endpoint);
    if (index > -1) {
      this.endpoints.splice(index, 1);
      this.failedEndpoints.delete(endpoint);
      this.lastHealthCheck.delete(endpoint);
      console.log(`➖ Removed endpoint: ${endpoint}`);
    }
  }
}

// Export singleton instance
export const loadBalancer = new LoadBalancerService();
export default loadBalancer;
