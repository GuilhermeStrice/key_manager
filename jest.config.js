/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/src/**/*.spec.ts', '**/src/**/*.test.ts'],
  clearMocks: true, // Automatically clear mock calls and instances between every test
  resetMocks: true, // Automatically reset mock state between every test
  restoreMocks: true, // Automatically restore mock state and implementation between every test
};
