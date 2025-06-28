// src/lib/configManager.ts
import fs from 'fs/promises';
import path from 'path';

const DATA_DIR = path.join(__dirname, '../../data');
const CONFIG_FILE_NAME = 'runtime-config.json';
const CONFIG_FILE_PATH = path.join(DATA_DIR, CONFIG_FILE_NAME);

export interface RuntimeConfig {
  autoApproveWebSocketRegistrations: boolean;
  jwtSecret: string;
  httpPort?: number;
  wsPort?: number;
}

const defaultConfig: RuntimeConfig = {
  autoApproveWebSocketRegistrations: false,
  jwtSecret: 'PLEASE_SET_A_STRONG_JWT_SECRET', // Placeholder, ensure proper handling if used
  // httpPort and wsPort are optional and will be undefined here
  // Their defaults will be handled in main.ts or by environment variables
  // if not specified in the config file.
};

/**
 * Ensures the data directory exists.
 */
async function ensureDataDirExists(): Promise<void> {
  try {
    await fs.access(DATA_DIR);
  } catch {
    await fs.mkdir(DATA_DIR, { recursive: true });
    console.log(`Data directory created at: ${DATA_DIR}`);
  }
}

/**
 * Loads the runtime configuration from `runtime-config.json`.
 * If the file doesn't exist or is invalid, it initializes with default values and saves it.
 * @returns The loaded or default RuntimeConfig object.
 */
export async function loadConfiguration(): Promise<RuntimeConfig> {
  await ensureDataDirExists();
  try {
    const fileContent = await fs.readFile(CONFIG_FILE_PATH, 'utf-8');
    let config = JSON.parse(fileContent) as Partial<RuntimeConfig>; // Parse as partial first

    // Validate and ensure all config fields are present, merging with defaults
    let configChanged = false;
    if (typeof config.autoApproveWebSocketRegistrations !== 'boolean') {
        console.warn(`Invalid or missing 'autoApproveWebSocketRegistrations' in ${CONFIG_FILE_PATH}. Setting to default: ${defaultConfig.autoApproveWebSocketRegistrations}`);
        config.autoApproveWebSocketRegistrations = defaultConfig.autoApproveWebSocketRegistrations;
        configChanged = true;
    }
    if (typeof config.jwtSecret !== 'string' || config.jwtSecret === '') {
        console.warn(`Invalid or missing 'jwtSecret' in ${CONFIG_FILE_PATH}. Setting to default placeholder.`);
        config.jwtSecret = defaultConfig.jwtSecret; // Use placeholder from defaultConfig
        configChanged = true;
    }

    // Optional: Validate httpPort and wsPort if they exist, or remove them if invalid
    // For now, we'll let them be undefined if not present or if they are not numbers.
    // The main.ts will handle default values if these are undefined.
    if (config.httpPort !== undefined && typeof config.httpPort !== 'number') {
        console.warn(`Invalid 'httpPort' in ${CONFIG_FILE_PATH}. It should be a number. Ignoring value.`);
        delete config.httpPort; // Or set to a default, but main.ts handles defaults
        configChanged = true;
    }
    if (config.wsPort !== undefined && typeof config.wsPort !== 'number') {
        console.warn(`Invalid 'wsPort' in ${CONFIG_FILE_PATH}. It should be a number. Ignoring value.`);
        delete config.wsPort; // Or set to a default
        configChanged = true;
    }

    const finalConfig = config as RuntimeConfig; // Now cast to full RuntimeConfig

    if (configChanged) {
        console.log(`Configuration updated (or invalid fields removed) in ${CONFIG_FILE_PATH}. Saving new version.`);
        // Save the corrected/updated config back to the file
        await fs.writeFile(CONFIG_FILE_PATH, JSON.stringify(finalConfig, null, 2), 'utf-8');
    }

    console.log(`Configuration loaded from ${CONFIG_FILE_PATH}`);
    return finalConfig;
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      console.log(`${CONFIG_FILE_PATH} not found. Initializing with default configuration (ports will be undefined).`);
      return await initializeDefaultConfig();
    } else {
      console.error(`Error reading ${CONFIG_FILE_PATH}. Using default configuration. Error:`, error);
      return await initializeDefaultConfig(); // Fallback to default on other errors too (e.g., parse error)
    }
  }
}

/**
 * Initializes the config file with default values.
 */
async function initializeDefaultConfig(): Promise<RuntimeConfig> {
  try {
    await fs.writeFile(CONFIG_FILE_PATH, JSON.stringify(defaultConfig, null, 2), 'utf-8');
    console.log(`Default configuration saved to ${CONFIG_FILE_PATH}`);
    return { ...defaultConfig };
  } catch (saveError) {
    console.error(`Failed to save default configuration to ${CONFIG_FILE_PATH}:`, saveError);
    // Return default config in memory even if save fails, to allow server to run
    return { ...defaultConfig };
  }
}

/**
 * Saves the provided configuration object to `runtime-config.json`.
 * @param config The RuntimeConfig object to save.
 */
export async function saveConfiguration(config: RuntimeConfig): Promise<void> {
  await ensureDataDirExists();
  try {
    await fs.writeFile(CONFIG_FILE_PATH, JSON.stringify(config, null, 2), 'utf-8');
    console.log(`Configuration saved to ${CONFIG_FILE_PATH}`);
  } catch (error) {
    console.error(`Failed to save configuration to ${CONFIG_FILE_PATH}:`, error);
    // Re-throw the error so the caller can handle it
    throw error;
  }
}
