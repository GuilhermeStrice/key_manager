import fs from 'fs';
import path from 'path';

const CONFIG_DIR = path.join(__dirname, '../../../data'); // Relative to src/lib, so ../../data
const CONFIG_FILE_PATH = path.join(CONFIG_DIR, 'runtime-config.json');

export interface AppConfig {
  jwtSecret: string;
  autoApproveWebSocketRegistrations: boolean;
  httpPort: number;
  wsPort: number;
  adminPasswordHash?: string; // Optional: if we ever move admin password here
  wsAdminPasswordHash?: string; // Optional: if we ever move ws admin password here
}

const DEFAULT_CONFIG: AppConfig = {
  jwtSecret: 'DEFAULT_FALLBACK_SECRET_DO_NOT_USE_IN_PROD',
  autoApproveWebSocketRegistrations: false,
  httpPort: 3000,
  wsPort: 3001,
};

let currentConfig: AppConfig;

function ensureDirExists(dirPath: string) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
    console.log(`Created directory: ${dirPath}`);
  }
}

export function saveConfig(configToSave: AppConfig): void {
  ensureDirExists(CONFIG_DIR);
  try {
    fs.writeFileSync(CONFIG_FILE_PATH, JSON.stringify(configToSave, null, 2));
    console.log(`Configuration saved to ${CONFIG_FILE_PATH}`);
  } catch (error) {
    console.error(`Error saving configuration to ${CONFIG_FILE_PATH}:`, error);
    // Depending on severity, might want to throw or handle differently
  }
}

export function loadConfig(): AppConfig {
  ensureDirExists(CONFIG_DIR);
  let loadedConfig: Partial<AppConfig> = {};
  let needsSave = false;

  try {
    if (fs.existsSync(CONFIG_FILE_PATH)) {
      const fileContent = fs.readFileSync(CONFIG_FILE_PATH, 'utf-8');
      loadedConfig = JSON.parse(fileContent) as Partial<AppConfig>;
    } else {
      console.log(`Configuration file not found at ${CONFIG_FILE_PATH}. Creating with default values.`);
      loadedConfig = {}; // Start fresh to ensure all defaults are applied
      needsSave = true; // Mark that we need to save after defaulting
    }
  } catch (error) {
    console.error(`Error reading or parsing configuration file ${CONFIG_FILE_PATH}. Using defaults. Error:`, error);
    loadedConfig = {}; // Reset to ensure defaults are applied on error
    needsSave = true; // Mark for save if parsing failed
  }

  // Merge with defaults (defaults apply if key is missing in loadedConfig)
  const configWithDefaults: AppConfig = {
    jwtSecret: loadedConfig.jwtSecret ?? DEFAULT_CONFIG.jwtSecret,
    autoApproveWebSocketRegistrations: loadedConfig.autoApproveWebSocketRegistrations ?? DEFAULT_CONFIG.autoApproveWebSocketRegistrations,
    httpPort: loadedConfig.httpPort ?? DEFAULT_CONFIG.httpPort,
    wsPort: loadedConfig.wsPort ?? DEFAULT_CONFIG.wsPort,
    adminPasswordHash: loadedConfig.adminPasswordHash, // Keep undefined if not present
    wsAdminPasswordHash: loadedConfig.wsAdminPasswordHash, // Keep undefined if not present
  };

  // Check if any default values were applied to an existing file or if the file was new
  if (!needsSave) { // Only re-check if not already marked for save (e.g. new file or parse error)
      if (
          configWithDefaults.jwtSecret !== loadedConfig.jwtSecret ||
          configWithDefaults.autoApproveWebSocketRegistrations !== loadedConfig.autoApproveWebSocketRegistrations ||
          configWithDefaults.httpPort !== loadedConfig.httpPort ||
          configWithDefaults.wsPort !== loadedConfig.wsPort
          // We don't check optional fields like adminPasswordHash for needing a save if they were merely defaulted from undefined to undefined
      ) {
          console.log('Configuration file was missing some keys. Applying defaults and saving.');
          needsSave = true;
      }
  }


  if (configWithDefaults.jwtSecret === DEFAULT_CONFIG.jwtSecret) {
    console.warn('WARNING: Using default JWT secret. This is NOT secure for production. Consider setting a unique JWT_SECRET in data/runtime-config.json.');
  }

  if (needsSave) {
    saveConfig(configWithDefaults);
  }

  currentConfig = configWithDefaults;
  console.log('Configuration loaded:', currentConfig);
  return currentConfig;
}

export function getConfig(): AppConfig {
  if (!currentConfig) {
    // This should ideally not be hit if loadConfig is called at startup.
    console.warn("Config not loaded yet. Loading now. Ensure loadConfig() is called at application start.");
    return loadConfig();
  }
  return currentConfig;
}

export function updateAutoApproveSetting(newState: boolean): AppConfig {
  if (!currentConfig) {
    loadConfig(); // Ensure config is loaded
  }
  currentConfig.autoApproveWebSocketRegistrations = newState;
  saveConfig(currentConfig);
  return currentConfig;
}

// Initialize config on module load.
// This ensures that `getConfig` can be called immediately after import.
loadConfig();
