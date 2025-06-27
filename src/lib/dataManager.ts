// Data loading, decryption, encryption, and saving logic
import fs from 'fs/promises';
import path from 'path';
import { encrypt, decrypt, deriveMasterKey, generateSalt } from './encryption';

const DATA_DIR = path.join(__dirname, '../../data');
const DATA_FILE_NAME = 'secrets.json.enc';
const DATA_FILE_PATH = path.join(DATA_DIR, DATA_FILE_NAME);
const SALT_FILE_NAME = 'masterkey.salt';
const SALT_FILE_PATH = path.join(DATA_DIR, SALT_FILE_NAME);

// In-memory store for the decrypted data
let dataStore: Record<string, any> = {};
let masterEncryptionKey: Buffer | null = null;

/**
 * Initializes the DataManager with the server's master password.
 * Derives the master encryption key and loads data.
 */
export async function initializeDataManager(password: string): Promise<void> {
  let salt: Buffer;
  try {
    await fs.access(DATA_DIR);
  } catch {
    await fs.mkdir(DATA_DIR, { recursive: true });
    console.log(`Data directory created at: ${DATA_DIR}`);
  }

  try {
    const saltHex = await fs.readFile(SALT_FILE_PATH, 'utf-8');
    salt = Buffer.from(saltHex, 'hex');
    console.log('Master key salt loaded from file.');
  } catch (error) {
    console.log('Master key salt file not found. Generating a new salt...');
    salt = generateSalt();
    await fs.writeFile(SALT_FILE_PATH, salt.toString('hex'), 'utf-8');
    console.log(`New master key salt generated and saved to: ${SALT_FILE_PATH}`);
  }

  masterEncryptionKey = deriveMasterKey(password, salt);
  console.log('Master encryption key derived.');

  await loadData();
}

/**
 * Loads data from the encrypted file and decrypts it.
 * If the file doesn't exist, initializes with an empty store.
 */
async function loadData(): Promise<void> {
  if (!masterEncryptionKey) {
    throw new Error('DataManager not initialized. Master key is missing.');
  }
  try {
    const encryptedData = await fs.readFile(DATA_FILE_PATH, 'utf-8');
    if (encryptedData.trim() === '') {
        console.log('Data file is empty. Initializing with an empty store.');
        dataStore = {};
        return;
    }
    const decryptedJson = decrypt(encryptedData, masterEncryptionKey);
    if (decryptedJson) {
      dataStore = JSON.parse(decryptedJson);
      console.log('Data loaded and decrypted successfully.');
    } else {
      // This case could mean the file is corrupt or the password was wrong.
      // If password was wrong, masterEncryptionKey would be wrong.
      console.error('Failed to decrypt data. The file might be corrupted or the password was incorrect.');
      // Decide on a recovery strategy:
      // 1. Throw an error and stop the server.
      // 2. Start with an empty data store (potential data loss if password was just mistyped).
      // 3. Backup the corrupted file and start fresh.
      // For now, let's throw, as this is critical.
      throw new Error('Failed to decrypt data file. Check password or file integrity.');
    }
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      console.log(`Data file not found at ${DATA_FILE_PATH}. Initializing with an empty store.`);
      dataStore = {};
      // Optionally save the empty store immediately to create the file
      // await saveData();
    } else {
      console.error('Error loading data:', error);
      throw error; // Re-throw other errors
    }
  }
}

/**
 * Saves the current in-memory data store to the encrypted file.
 */
export async function saveData(): Promise<void> {
  if (!masterEncryptionKey) {
    throw new Error('DataManager not initialized. Master key is missing.');
  }
  try {
    const jsonData = JSON.stringify(dataStore, null, 2); // Pretty print JSON
    const encryptedData = encrypt(jsonData, masterEncryptionKey);
    await fs.writeFile(DATA_FILE_PATH, encryptedData, 'utf-8');
    console.log(`Data saved and encrypted successfully to: ${DATA_FILE_PATH}`);
  } catch (error) {
    console.error('Error saving data:', error);
    throw error;
  }
}

/**
 * Retrieves a value from the data store by key.
 */
export function getItem<T = any>(key: string): T | undefined {
  return dataStore[key] as T | undefined;
}

/**
 * Sets a value in the data store by key.
 * Automatically triggers a save after setting the item.
 */
export async function setItem<T = any>(key: string, value: T): Promise<void> {
  dataStore[key] = value;
  await saveData();
}

/**
 * Deletes an item from the data store by key.
 * Automatically triggers a save after deleting the item.
 */
export async function deleteItem(key: string): Promise<void> {
  if (dataStore.hasOwnProperty(key)) {
    delete dataStore[key];
    await saveData();
  }
}

/**
 * Retrieves all keys from the data store.
 */
export function getAllKeys(): string[] {
  return Object.keys(dataStore);
}

/**
 * Retrieves the entire data store.
 * Use with caution, especially if the data is large.
 */
export function getStore(): Record<string, any> {
    return { ...dataStore }; // Return a copy
}
