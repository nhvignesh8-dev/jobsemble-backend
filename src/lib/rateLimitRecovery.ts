// Rate limit recovery utility
export class RateLimitRecovery {
  private static readonly STORAGE_KEY = 'appwrite_rate_limit_recovery';
  private static readonly RECOVERY_TIME = 5 * 60 * 1000; // 5 minutes

  // Check if we're in recovery mode
  static isInRecoveryMode(): boolean {
    const recoveryData = this.getRecoveryData();
    if (!recoveryData) return false;

    const now = Date.now();
    return now < recoveryData.recoveryUntil;
  }

  // Get remaining recovery time in milliseconds
  static getRemainingRecoveryTime(): number {
    const recoveryData = this.getRecoveryData();
    if (!recoveryData) return 0;

    const now = Date.now();
    return Math.max(0, recoveryData.recoveryUntil - now);
  }

  // Enter recovery mode
  static enterRecoveryMode(): void {
    const now = Date.now();
    const recoveryData = {
      enteredAt: now,
      recoveryUntil: now + this.RECOVERY_TIME,
      attemptCount: this.getAttemptCount() + 1
    };

    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(recoveryData));
    console.log(`Entering rate limit recovery mode for ${this.RECOVERY_TIME / 1000} seconds`);
  }

  // Exit recovery mode
  static exitRecoveryMode(): void {
    localStorage.removeItem(this.STORAGE_KEY);
    console.log('Exiting rate limit recovery mode');
  }

  // Get attempt count
  static getAttemptCount(): number {
    const recoveryData = this.getRecoveryData();
    return recoveryData?.attemptCount || 0;
  }

  // Get recovery data from localStorage
  private static getRecoveryData(): { enteredAt: number; recoveryUntil: number; attemptCount: number } | null {
    try {
      const data = localStorage.getItem(this.STORAGE_KEY);
      return data ? JSON.parse(data) : null;
    } catch {
      return null;
    }
  }

  // Get user-friendly recovery message
  static getRecoveryMessage(): string {
    const remainingTime = this.getRemainingRecoveryTime();
    const minutes = Math.ceil(remainingTime / (60 * 1000));
    
    if (minutes <= 1) {
      return 'Please wait about 1 minute before trying again.';
    }
    
    return `Please wait about ${minutes} minutes before trying again.`;
  }

  // Check and automatically exit recovery if time has passed
  static checkAndExitRecovery(): boolean {
    if (this.isInRecoveryMode()) {
      return false; // Still in recovery
    }
    
    // Recovery time has passed, clean up
    if (this.getRecoveryData()) {
      this.exitRecoveryMode();
    }
    
    return true; // Recovery complete
  }
}

// Export singleton functions
export const rateLimitRecovery = {
  isInRecoveryMode: () => RateLimitRecovery.isInRecoveryMode(),
  getRemainingRecoveryTime: () => RateLimitRecovery.getRemainingRecoveryTime(),
  enterRecoveryMode: () => RateLimitRecovery.enterRecoveryMode(),
  exitRecoveryMode: () => RateLimitRecovery.exitRecoveryMode(),
  getAttemptCount: () => RateLimitRecovery.getAttemptCount(),
  getRecoveryMessage: () => RateLimitRecovery.getRecoveryMessage(),
  checkAndExitRecovery: () => RateLimitRecovery.checkAndExitRecovery()
};
