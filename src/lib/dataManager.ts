// Data loading, decryption, encryption, and saving logic
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto'; // For generating client IDs and tokens
import { encrypt, decrypt, deriveMasterKey, generateSalt } from './encryption';

const DATA_DIR = path.join(__dirname, '../../data');
const DATA_FILE_NAME = 'secrets.json.enc';
const DATA_FILE_PATH = path.join(DATA_DIR, DATA_FILE_NAME);
const SALT_FILE_NAME = 'masterkey.salt';
const SALT_FILE_PATH = path.join(DATA_DIR, SALT_FILE_NAME);

export type ClientStatus = 'pending' | 'approved' | 'rejected';

export interface ClientInfo {
  id: string; // Unique client identifier (e.g., a UUID)
  name: string; // User-friendly name provided by the client or admin
  status: ClientStatus;
  authToken?: string; // Secure token generated upon approval
  associatedSecretKeys: string[]; // Keys of secrets this client can access
  temporaryId?: string; // Optional: A temporary ID or token given to client during pending state
  requestedSecretKeys?: string[]; // Optional: Keys initially requested by the client
  dateCreated: string; // ISO 8601 date string
  dateUpdated: string; // ISO 8601 date string
}

interface SecureDataStore {
  secrets: Record<string, any>; // Existing secrets key-value store
  clients: Record<string, ClientInfo>; // Keyed by ClientInfo.id
}

// In-memory store for the decrypted data
let dataStore: SecureDataStore = {
  secrets: {},
  clients: {},
};
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
        dataStore = { secrets: {}, clients: {} }; // Ensure it matches SecureDataStore type
        return;
    }
    const decryptedJson = decrypt(encryptedData, masterEncryptionKey);
    if (decryptedJson) {
      const loadedStore = JSON.parse(decryptedJson);
      // Ensure structure compatibility with SecureDataStore
      dataStore = {
        secrets: loadedStore.secrets || (loadedStore.clients ? {} : loadedStore) || {}, // Handle old format where dataStore was just secrets
        clients: loadedStore.clients || {}
      };
      if(!loadedStore.secrets && !loadedStore.clients && Object.keys(loadedStore).length > 0) {
        console.warn("Loaded data seems to be in an older format (only secrets). Migrating to new structure.");
      }
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
      dataStore = { secrets: {}, clients: {} }; // Initialize with new structure
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
 * Retrieves a secret value from the data store by key.
 */
export function getSecretItem<T = any>(key: string): T | undefined {
  return dataStore.secrets[key] as T | undefined;
}

/**
 * Sets a secret value in the data store by key.
 * Automatically triggers a save after setting the item.
 */
export async function setSecretItem<T = any>(key: string, value: T): Promise<void> {
  dataStore.secrets[key] = value;
  await saveData();
}

/**
 * Deletes a secret item from the data store by key.
 * Also removes this secret key from any client's associatedSecretKeys list.
 * Automatically triggers a save after deleting the item.
 */
export async function deleteSecretItem(key: string): Promise<void> {
  if (dataStore.secrets.hasOwnProperty(key)) {
    delete dataStore.secrets[key];
    // Remove this secret key from all clients' associatedSecretKeys
    Object.values(dataStore.clients).forEach(client => {
        const index = client.associatedSecretKeys.indexOf(key);
        if (index > -1) {
            client.associatedSecretKeys.splice(index, 1);
            client.dateUpdated = new Date().toISOString();
        }
    });
    await saveData();
  }
}

/**
 * Retrieves all secret keys from the data store.
 */
export function getAllSecretKeys(): string[] {
  return Object.keys(dataStore.secrets);
}

/**
 * Retrieves the entire data store (secrets and clients).
 * Use with caution, especially if the data is large. Consider specific getters instead.
 */
export function getEntireStore(): SecureDataStore {
    return JSON.parse(JSON.stringify(dataStore)); // Return a deep copy
}

// --- Client Management Functions ---

function generateRandomToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Adds a new client in a 'pending' state.
 * @param clientName User-friendly name for the client.
 * @param requestedSecretKeys Optional array of secret keys the client is requesting access to.
 * @returns The newly created ClientInfo object.
 */
export async function addPendingClient(
  clientName: string,
  requestedSecretKeys?: string[]
): Promise<ClientInfo> {
  if (!clientName || typeof clientName !== 'string' || clientName.trim() === "") {
    throw new Error("Client name must be a non-empty string.");
  }

  const clientId = `client_${generateRandomToken(8)}`; // Shorter, more manageable ID
  const temporaryId = `temp_${generateRandomToken(16)}`; // Token for client to hold while pending
  const now = new Date().toISOString();

  const newClient: ClientInfo = {
    id: clientId,
    name: clientName.trim(),
    status: 'pending',
    associatedSecretKeys: [],
    temporaryId: temporaryId,
    requestedSecretKeys: requestedSecretKeys || [],
    dateCreated: now,
    dateUpdated: now,
  };

  if (dataStore.clients[clientId]) {
    // Extremely unlikely with random generation, but good practice
    throw new Error("Client ID collision. Please try again.");
  }

  dataStore.clients[clientId] = newClient;
  await saveData();
  return JSON.parse(JSON.stringify(newClient)); // Return a copy
}

/**
 * Approves a pending client.
 * Generates a permanent authToken for the client.
 * @param clientId The ID of the client to approve.
 * @returns The updated ClientInfo object with the new authToken.
 */
export async function approveClient(clientId: string): Promise<ClientInfo> {
  // Removed duplicated validation and client declaration block
  if (!clientId || typeof clientId !== 'string' || clientId.trim() === "") {
    throw new Error("Client ID must be a non-empty string.");
  }

  const client = dataStore.clients[clientId];
  if (!client) {
    throw new Error(`Client with ID "${clientId}" not found.`);
  }
  if (client.status !== 'pending') {
    // Allow re-approving an already approved client to regenerate token? Or error?
    // For now, let's say it must be pending.
    throw new Error(`Client "${clientId}" is not in 'pending' state. Current state: ${client.status}.`);
  }

  client.status = 'approved';
  client.authToken = `auth_${generateRandomToken(24)}`; // Generate a new auth token
  client.temporaryId = undefined; // Clear temporary ID
  client.dateUpdated = new Date().toISOString();

  await saveData();
  return JSON.parse(JSON.stringify(client));
}

/**
 * Rejects a pending client.
 * @param clientId The ID of the client to reject.
 * @returns The updated ClientInfo object.
 */
export async function rejectClient(clientId: string): Promise<ClientInfo> {
  const client = dataStore.clients[clientId];
  if (!client) {
    throw new Error(`Client with ID "${clientId}" not found.`);
  }
   if (client.status !== 'pending') {
    console.warn(`Client "${clientId}" is not in 'pending' state. Current state: ${client.status}. Still marking as rejected.`);
  }

  client.status = 'rejected';
  client.authToken = undefined; // Ensure no auth token
  client.temporaryId = undefined; // Clear temporary ID
  client.dateUpdated = new Date().toISOString();
  // Consider if associatedSecretKeys or requestedSecretKeys should be cleared.
  // For now, keeping them for audit/history.

  await saveData();
  return JSON.parse(JSON.stringify(client));
}

/**
 * Retrieves a client by their ID.
 * @param clientId The ID of the client.
 * @returns ClientInfo object or undefined if not found.
 */
export function getClient(clientId: string): ClientInfo | undefined {
  const client = dataStore.clients[clientId];
  return client ? JSON.parse(JSON.stringify(client)) : undefined;
}

/**
 * Retrieves all clients.
 * @returns An array of ClientInfo objects.
 */
export function getAllClients(): ClientInfo[] {
  return Object.values(dataStore.clients).map(client => JSON.parse(JSON.stringify(client)));
}

/**
 * Retrieves all clients with 'pending' status.
 */
export function getPendingClients(): ClientInfo[] {
  return Object.values(dataStore.clients)
    .filter(client => client.status === 'pending')
    .map(client => JSON.parse(JSON.stringify(client)));
}

/**
 * Retrieves all clients with 'approved' status.
 */
export function getApprovedClients(): ClientInfo[] {
  return Object.values(dataStore.clients)
    .filter(client => client.status === 'approved')
    .map(client => JSON.parse(JSON.stringify(client)));
}

/**
 * Associates a secret key with an approved client.
 * @param clientId The ID of the client.
 * @param secretKey The secret key to associate.
 */
export async function associateSecretWithClient(clientId: string, secretKey: string): Promise<ClientInfo> {
  const client = dataStore.clients[clientId];
  if (!client) {
    throw new Error(`Client with ID "${clientId}" not found.`);
  }
  if (client.status !== 'approved') {
    throw new Error(`Client "${clientId}" is not approved. Cannot associate secrets.`);
  }
  if (!dataStore.secrets.hasOwnProperty(secretKey)) {
    throw new Error(`Secret with key "${secretKey}" not found.`);
  }

  if (!client.associatedSecretKeys.includes(secretKey)) {
    client.associatedSecretKeys.push(secretKey);
    client.dateUpdated = new Date().toISOString();
    await saveData();
  }
  return JSON.parse(JSON.stringify(client));
}

/**
 * Dissociates a secret key from a client.
 * @param clientId The ID of the client.
 * @param secretKey The secret key to dissociate.
 */
export async function dissociateSecretFromClient(clientId: string, secretKey: string): Promise<ClientInfo> {
  const client = dataStore.clients[clientId];
  if (!client) {
    throw new Error(`Client with ID "${clientId}" not found.`);
  }
  // No status check needed for dissociation, can be done for any client state.

  const index = client.associatedSecretKeys.indexOf(secretKey);
  if (index > -1) {
    client.associatedSecretKeys.splice(index, 1);
    client.dateUpdated = new Date().toISOString();
    await saveData();
  }
  return JSON.parse(JSON.stringify(client));
}

/**
 * Retrieves an approved client by their authToken.
 * @param authToken The authentication token of the client.
 * @returns ClientInfo object or undefined if not found or not approved.
 */
export function getClientByAuthToken(authToken: string): ClientInfo | undefined {
  const client = Object.values(dataStore.clients).find(
    c => c.status === 'approved' && c.authToken === authToken
  );
  return client ? JSON.parse(JSON.stringify(client)) : undefined;
}

/**
 * Deletes a client and their associations.
 * @param clientId The ID of the client to delete.
 */
export async function deleteClient(clientId: string): Promise<void> {
    if (dataStore.clients.hasOwnProperty(clientId)) {
        delete dataStore.clients[clientId];
        // No need to iterate secrets, as associations are on the client record.
        await saveData();
        console.log(`Client "${clientId}" deleted.`);
    } else {
        console.warn(`Client "${clientId}" not found for deletion.`);
    }
}
