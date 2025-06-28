// src/lib/configManager.ts
import fs from 'fs/promises';
import path from 'path';

const DATA_DIR = path.join(__dirname, '../../data');
const CONFIG_FILE_NAME = 'runtime-config.json';
const CONFIG_FILE_PATH = path.join(DATA_DIR, CONFIG_FILE_NAME);

export interface RuntimeConfig {
  autoApproveWebSocketRegistrations: boolean;
  jwtSecret: string;
}

const defaultConfig: RuntimeConfig = {
  autoApproveWebSocketRegistrations: false,
  jwtSecret: 'PLEASE_SET_A_STRONG_JWT_SECRET', // Placeholder, ensure proper handling if used
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

    const finalConfig = config as RuntimeConfig; // Now cast to full RuntimeConfig

    if (configChanged) {
        console.log(`Configuration updated with default values for missing fields. Saving new version to ${CONFIG_FILE_PATH}`);
        // Save the corrected/updated config back to the file
        // Note: initializeDefaultConfig writes the complete defaultConfig, here we want to preserve existing valid fields.
        await fs.writeFile(CONFIG_FILE_PATH, JSON.stringify(finalConfig, null, 2), 'utf-8');
    }

    console.log(`Configuration loaded from ${CONFIG_FILE_PATH}`);
    return finalConfig;
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      console.log(`${CONFIG_FILE_PATH} not found. Initializing with default configuration.`);
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
