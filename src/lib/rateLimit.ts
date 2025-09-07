// Simple client-side rate limiting utility
export class RateLimiter {
  private lastActionTime: { [key: string]: number } = {};
  private cooldownPeriods: { [key: string]: number } = {};

  constructor() {
    // Set default cooldown periods (in milliseconds)
    this.cooldownPeriods = {
      'auth-login': 2000,      // 2 seconds between login attempts
      'auth-signup': 3000,     // 3 seconds between signup attempts
      'auth-general': 1000,    // 1 second for general auth operations
    };
  }

  // Check if action is allowed
  canPerformAction(actionKey: string, customCooldown?: number): boolean {
    const now = Date.now();
    const cooldown = customCooldown || this.cooldownPeriods[actionKey] || 1000;
    const lastTime = this.lastActionTime[actionKey] || 0;
    
    return (now - lastTime) >= cooldown;
  }

  // Record that action was performed
  recordAction(actionKey: string): void {
    this.lastActionTime[actionKey] = Date.now();
  }

  // Get remaining cooldown time
  getRemainingCooldown(actionKey: string, customCooldown?: number): number {
    const now = Date.now();
    const cooldown = customCooldown || this.cooldownPeriods[actionKey] || 1000;
    const lastTime = this.lastActionTime[actionKey] || 0;
    const elapsed = now - lastTime;
    
    return Math.max(0, cooldown - elapsed);
  }

  // Reset cooldown for specific action
  resetCooldown(actionKey: string): void {
    delete this.lastActionTime[actionKey];
  }

  // Reset all cooldowns
  resetAllCooldowns(): void {
    this.lastActionTime = {};
  }
}

// Export singleton instance
export const rateLimiter = new RateLimiter();
