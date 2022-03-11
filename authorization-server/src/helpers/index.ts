/**
 * Detects if process is executed in test or CI environment
 */
export function isCI(): boolean {
  return process.env.NODE_ENV === 'test';
}
