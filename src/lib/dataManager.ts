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
  associatedGroupIds: number[]; // IDs of secret groups this client can access
  requestedSecretKeys?: string[]; // Optional: Keys initially requested by the client (legacy, consider removing or adapting for group requests)
  registrationTimestamp?: number; // Timestamp (Date.now()) when client entered pending state, for expiry
  dateCreated: string; // ISO 8601 date string
  dateUpdated: string; // ISO 8601 date string
}

interface SecureDataStore {
  secrets: { [key: string]: { value: any, groupId: number } };
  clients: Record<string, ClientInfo>; // Keyed by ClientInfo.id
  secretGroups: { [groupId: number]: { name: string, keys: string[] } };
  nextGroupId: number;
}

// In-memory store for the decrypted data
let dataStore: SecureDataStore = {
  secrets: {},
  clients: {},
  secretGroups: {},
  nextGroupId: 1,
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

  // Start periodic check for expiring pending clients
  // The interval can be configured as needed. e.g., every 30 seconds.
  const expiryCheckInterval = 30 * 1000; // 30 seconds
  setInterval(checkAndExpirePendingClients, expiryCheckInterval);
  console.log(`Started periodic check for pending client expiry every ${expiryCheckInterval / 1000} seconds.`);
}

const PENDING_CLIENT_EXPIRY_DURATION_MS = 60 * 1000; // 1 minute

/**
 * Checks for pending clients that have exceeded their registration expiry time
 * and updates their status to 'rejected'.
 */
export async function checkAndExpirePendingClients(): Promise<void> {
  let updated = false;
  const now = Date.now();

  for (const clientId in dataStore.clients) {
    const client = dataStore.clients[clientId];
    if (client.status === 'pending' && client.registrationTimestamp) {
      if (now - client.registrationTimestamp > PENDING_CLIENT_EXPIRY_DURATION_MS) {
        console.log(`Pending client "${client.name}" (ID: ${client.id}) has expired. Setting status to rejected.`);
        client.status = 'rejected';
        client.dateUpdated = new Date().toISOString();
        // client.registrationTimestamp = undefined; // Optionally clear it, or keep for audit
        updated = true;
      }
    }
  }

  if (updated) {
    try {
      await saveData();
      console.log('Saved data after expiring pending clients.');
    } catch (error) {
      console.error('Failed to save data after expiring clients:', error);
    }
  }
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
        // Initialize with the full new structure
        dataStore = { secrets: {}, clients: {}, secretGroups: {}, nextGroupId: 1 };
        return;
    }
    const decryptedJson = decrypt(encryptedData, masterEncryptionKey);
    if (decryptedJson) {
      const loadedStore = JSON.parse(decryptedJson) as Partial<SecureDataStore>;

      // Initialize with defaults and then override with loaded data
      dataStore = {
        secrets: loadedStore.secrets || {},
        clients: loadedStore.clients || {}, // Will be further processed below
        secretGroups: loadedStore.secretGroups || {},
        nextGroupId: loadedStore.nextGroupId || 1,
      };

      // Ensure all loaded clients have associatedGroupIds initialized
      for (const clientId in dataStore.clients) {
        if (dataStore.clients.hasOwnProperty(clientId)) {
          const client = dataStore.clients[clientId] as any; // Use 'as any' for transitional period
          if (client.associatedSecretKeys && !client.associatedGroupIds) {
            console.log(`Client ${clientId} has legacy 'associatedSecretKeys'. Initializing 'associatedGroupIds' to empty. Manual group association needed.`);
            client.associatedGroupIds = [];
            // Delete the old key to prevent confusion, or leave for manual inspection
            // delete client.associatedSecretKeys;
          } else if (!client.associatedGroupIds) {
            client.associatedGroupIds = [];
          }
        }
      }

      // Basic migration/check for old secrets structure
      // If secrets are not in the new { value, groupId } format, they will be problematic.
      // For Phase 1, we'll log if an old format secret is detected.
      // A more robust migration would be needed for existing data.
      let oldFormatSecretsDetected = false;
      for (const key in dataStore.secrets) {
        if (typeof dataStore.secrets[key] !== 'object' ||
            dataStore.secrets[key] === null ||
            !dataStore.secrets[key].hasOwnProperty('value') ||
            !dataStore.secrets[key].hasOwnProperty('groupId')) {
          console.warn(`Secret "${key}" has an outdated format and will be ignored or may cause errors. Please re-create it in a group.`);
          // Optionally delete it: delete dataStore.secrets[key];
          oldFormatSecretsDetected = true;
        }
      }
      if (oldFormatSecretsDetected) {
          console.warn("Old format secrets detected. These should be migrated or re-created within groups.");
          // Consider if a saveData() call is needed here if old secrets were deleted.
      }

      console.log('Data loaded and decrypted successfully.');
    } else {
      // This case could mean the file is corrupt or the password was wrong.
      console.error('Failed to decrypt data. The file might be corrupted or the password was incorrect.');
      throw new Error('Failed to decrypt data file. Check password or file integrity.');
    }
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      console.log(`Data file not found at ${DATA_FILE_PATH}. Initializing with an empty store.`);
      // Initialize with the full new structure
      dataStore = { secrets: {}, clients: {}, secretGroups: {}, nextGroupId: 1 };
      // Optionally save the empty store immediately to create the file: await saveData();
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
 * Retrieves a secret's value and its group ID.
 */
export function getSecretWithValue(key: string): { value: any, groupId: number } | undefined {
  return dataStore.secrets[key] ? { ...dataStore.secrets[key] } : undefined; // Return a copy
}

/**
 * Retrieves only the secret value from the data store by key.
 * Note: For new development, prefer getSecretWithValue if groupId is also needed.
 */
export function getSecretItem<T = any>(key: string): T | undefined {
  const secret = dataStore.secrets[key];
  return secret ? secret.value as T : undefined;
}

/**
 * Creates a new secret within a specified group.
 * Throws an error if the group doesn't exist or the secret key already exists.
 */
export async function createSecretInGroup(groupId: number, key: string, value: any): Promise<void> {
  if (!dataStore.secretGroups[groupId]) {
    throw new Error(`Group with ID "${groupId}" not found.`);
  }
  if (dataStore.secrets.hasOwnProperty(key)) {
    throw new Error(`Secret with key "${key}" already exists.`);
  }
  if (!key || typeof key !== 'string' || key.trim() === "") {
    throw new Error("Secret key must be a non-empty string.");
  }

  dataStore.secrets[key] = { value, groupId };
  if (!dataStore.secretGroups[groupId].keys.includes(key)) { // Should not be there, but good check
    dataStore.secretGroups[groupId].keys.push(key);
  }
  await saveData();
  console.log(`Secret "${key}" created in group ID ${groupId}.`);
}

/**
 * Updates the value of an existing secret. The group association does not change.
 */
export async function updateSecretValue(key: string, newValue: any): Promise<void> {
  if (!dataStore.secrets.hasOwnProperty(key)) {
    throw new Error(`Secret with key "${key}" not found.`);
  }
  dataStore.secrets[key].value = newValue;
  await saveData();
  console.log(`Secret "${key}" value updated.`);
}

/**
 * Deletes a secret.
 * It's removed from its group and from the main secrets store.
 */
export async function deleteSecret(key: string): Promise<void> {
  if (!dataStore.secrets.hasOwnProperty(key)) {
    console.warn(`Secret with key "${key}" not found for deletion.`);
    return; // Or throw error if preferred
  }

  const { groupId } = dataStore.secrets[key];
  delete dataStore.secrets[key];

  if (dataStore.secretGroups[groupId]) {
    const keyIndex = dataStore.secretGroups[groupId].keys.indexOf(key);
    if (keyIndex > -1) {
      dataStore.secretGroups[groupId].keys.splice(keyIndex, 1);
    } else {
        console.warn(`Secret key "${key}" was not found in its associated group ID ${groupId}'s key list during deletion.`);
    }
  } else {
    console.warn(`Group ID ${groupId} associated with secret "${key}" was not found during secret deletion.`);
  }

  // Client associations are group-based, so deleting a secret does not directly affect client records here.
  // The secret is simply removed from its group's key list (already done) and from the global secrets list.
  // Any client associated with that group will no longer see this secret via getSecretsForClient.
  // The old logic for removing from client.associatedSecretKeys is confirmed removed.

  await saveData();
  console.log(`Secret "${key}" deleted.`);
}


/**
 * (DEPRECATED - use createSecretInGroup or updateSecretValue)
 * Sets a secret value in the data store by key.
 * Automatically triggers a save after setting the item.
 */
export async function setSecretItem<T = any>(key: string, value: T): Promise<void> {
  // This function is problematic with the new structure as it doesn't know the group.
  // For now, it will log a warning. Ideally, all callers should be updated.
  console.warn(`DEPRECATED: setSecretItem called for key "${key}". This function does not handle group associations. Use createSecretInGroup or updateSecretValue.`);
  // To avoid breaking existing functionality entirely before full migration,
  // we could try to find its group or assign to a default/placeholder if that existed.
  // But the requirement is "secret must belong to exactly one group".
  // If the secret already exists, we can update its value. If not, we can't create it without a group.
  if (dataStore.secrets.hasOwnProperty(key)) {
    dataStore.secrets[key].value = value;
  } else {
    // Cannot create a new secret without a groupId.
    // Option 1: Throw error. Option 2: Log and do nothing for new keys.
    throw new Error(`setSecretItem cannot create new secret "${key}" without a groupId. Use createSecretInGroup.`);
  }
  await saveData();
}

/**
 * (DEPRECATED - use deleteSecret)
 * Deletes a secret item from the data store by key.
 * Also removes this secret key from any client's associatedSecretKeys list.
 * Automatically triggers a save after deleting the item.
 */
export async function deleteSecretItem(key: string): Promise<void> {
  console.warn(`DEPRECATED: deleteSecretItem called for key "${key}". Use deleteSecret instead.`);
  await deleteSecret(key); // Delegate to the new function
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

// --- Secret Group Management Functions ---

function _getNextGroupId(): number {
  // This function assumes dataStore is already initialized.
  // It modifies dataStore directly. The caller that uses this should ensure saveData is called.
  if (dataStore.nextGroupId === undefined) {
    dataStore.nextGroupId = 1; // Should have been initialized by loadData or initial declaration
  }
  const id = dataStore.nextGroupId;
  dataStore.nextGroupId += 1;
  return id;
}

export function getGroupByName(name: string): { id: number, name: string, keys: string[] } | undefined {
    for (const idStr in dataStore.secretGroups) {
        const id = parseInt(idStr, 10);
        if (dataStore.secretGroups[id].name === name) {
            return { id, ...dataStore.secretGroups[id] };
        }
    }
    return undefined;
}

export async function createSecretGroup(name: string): Promise<{ id: number, name: string }> {
  if (!name || typeof name !== 'string' || name.trim() === "") {
    throw new Error("Group name must be a non-empty string.");
  }
  if (getGroupByName(name)) {
    throw new Error(`A secret group with the name "${name}" already exists.`);
  }

  const newGroupId = _getNextGroupId(); // Increments nextGroupId but doesn't save yet
  dataStore.secretGroups[newGroupId] = { name: name.trim(), keys: [] };
  await saveData(); // Now save explicitly
  console.log(`Secret group "${name}" created with ID ${newGroupId}.`);
  return { id: newGroupId, name: dataStore.secretGroups[newGroupId].name };
}

export function getSecretGroupById(groupId: number): { id: number, name: string, keys: string[] } | undefined {
  if (dataStore.secretGroups[groupId]) {
    return { id: groupId, ...dataStore.secretGroups[groupId] };
  }
  return undefined;
}

export function getAllSecretGroups(): { id: number, name: string, keys: string[] }[] {
  return Object.entries(dataStore.secretGroups).map(([idStr, groupData]) => {
    const id = parseInt(idStr, 10);
    return {
      id,
      name: groupData.name,
      keys: [...groupData.keys] // Return a copy of the keys array
    };
  });
}

export async function renameSecretGroup(groupId: number, newName: string): Promise<void> {
  if (!newName || typeof newName !== 'string' || newName.trim() === "") {
    throw new Error("New group name must be a non-empty string.");
  }
  const group = dataStore.secretGroups[groupId];
  if (!group) {
    throw new Error(`Secret group with ID "${groupId}" not found.`);
  }
  const existingGroupWithNewName = getGroupByName(newName.trim());
  if (existingGroupWithNewName && existingGroupWithNewName.id !== groupId) {
    throw new Error(`Another secret group with the name "${newName.trim()}" already exists.`);
  }

  group.name = newName.trim();
  await saveData();
  console.log(`Secret group ID ${groupId} renamed to "${group.name}".`);
}

export async function deleteSecretGroup(groupId: number): Promise<void> {
  const group = dataStore.secretGroups[groupId];
  if (!group) {
    throw new Error(`Secret group with ID "${groupId}" not found.`);
  }

  const keysToDelete = [...group.keys]; // Create a copy as we'll be modifying the secrets store

  console.log(`Deleting group "${group.name}" (ID: ${groupId}) and its ${keysToDelete.length} secret(s)...`);

  for (const key of keysToDelete) {
    if (dataStore.secrets.hasOwnProperty(key)) {
      // Ensure the secret actually belongs to this group before deleting, as a sanity check
      if (dataStore.secrets[key].groupId === groupId) {
        delete dataStore.secrets[key];
        console.log(`  - Deleted secret "${key}" from group ${groupId}.`);
      } else {
        // This case should ideally not happen if data integrity is maintained
        console.warn(`  - Secret "${key}" was listed in group ${groupId} but its record indicates it belongs to group ${dataStore.secrets[key].groupId}. Not deleting from secrets map based on this group's list.`);
        // However, we should remove it from the current group's key list if it's there due to some inconsistency
        const keyIndexInGroup = group.keys.indexOf(key);
        if (keyIndexInGroup > -1) {
            group.keys.splice(keyIndexInGroup, 1);
        }
      }
    } else {
      console.warn(`  - Secret key "${key}" listed in group ${groupId} not found in main secrets store.`);
       // Remove from group's key list if present, to clean up inconsistency
        const keyIndexInGroup = group.keys.indexOf(key);
        if (keyIndexInGroup > -1) {
            group.keys.splice(keyIndexInGroup, 1);
        }
    }
  }

  delete dataStore.secretGroups[groupId];
  console.log(`Group ID ${groupId} ("${group.name}") itself deleted.`);

  // Update clients that were associated with this deleted group
  let clientsUpdated = false;
  for (const clientId in dataStore.clients) {
    const client = dataStore.clients[clientId];
    if (client.associatedGroupIds && client.associatedGroupIds.includes(groupId)) {
      client.associatedGroupIds = client.associatedGroupIds.filter(id => id !== groupId);
      client.dateUpdated = new Date().toISOString();
      clientsUpdated = true;
      console.log(`Removed deleted group ID ${groupId} from client ${clientId}.`);
    }
  }

  await saveData(); // This will save group deletion and any client updates.
  if (clientsUpdated) {
    console.log("Client associations updated due to group deletion.");
  }
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
  // temporaryId removed
  const now = new Date().toISOString();

  const newClient: ClientInfo = {
    id: clientId,
    name: clientName.trim(),
    status: 'pending',
    associatedGroupIds: [], // Initialize with empty group IDs
    // associatedSecretKeys: [], // Removed
    requestedSecretKeys: requestedSecretKeys || [], // Keep for now, may adapt later
    registrationTimestamp: Date.now(),
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
  // client.authToken = `auth_${generateRandomToken(24)}`; // authToken removed
  // client.temporaryId = undefined; // temporaryId removed
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
  // client.authToken = undefined; // authToken removed
  // client.temporaryId = undefined; // temporaryId removed
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

//
// OLD FUNCTIONS - TO BE REMOVED
//
// /**
//  * (REMOVED - Clients are now associated with groups, not individual keys)
//  * Associates a secret key with an approved client.
//  */
// export async function associateSecretWithClient(clientId: string, secretKey: string): Promise<ClientInfo> { ... }

// /**
//  * (REMOVED - Clients are now associated with groups, not individual keys)
//  * Dissociates a secret key from a client.
//  */
// export async function dissociateSecretFromClient(clientId: string, secretKey: string): Promise<ClientInfo> { ... }
//

/**
 * Associates a secret group with an approved client.
 * @param clientId The ID of the client.
 * @param groupId The ID of the group to associate.
 */
export async function associateGroupWithClient(clientId: string, groupId: number): Promise<ClientInfo> {
  const client = dataStore.clients[clientId];
  if (!client) {
    throw new Error(`Client with ID "${clientId}" not found.`);
  }
  if (client.status !== 'approved') {
    throw new Error(`Client "${clientId}" is not approved. Cannot associate groups.`);
  }
  if (!dataStore.secretGroups[groupId]) {
    throw new Error(`Secret group with ID "${groupId}" not found.`);
  }

  if (!client.associatedGroupIds) { // Should be initialized by now, but as a safeguard
    client.associatedGroupIds = [];
  }
  if (!client.associatedGroupIds.includes(groupId)) {
    client.associatedGroupIds.push(groupId);
    client.dateUpdated = new Date().toISOString();
    await saveData();
  }
  return JSON.parse(JSON.stringify(client));
}

/**
 * Dissociates a secret group from a client.
 * @param clientId The ID of the client.
 * @param groupId The ID of the group to dissociate.
 */
export async function dissociateGroupFromClient(clientId: string, groupId: number): Promise<ClientInfo> {
  const client = dataStore.clients[clientId];
  if (!client) {
    throw new Error(`Client with ID "${clientId}" not found.`);
  }
  if (!client.associatedGroupIds) { // Safeguard
    client.associatedGroupIds = [];
    return JSON.parse(JSON.stringify(client)); // Nothing to dissociate
  }

  const index = client.associatedGroupIds.indexOf(groupId);
  if (index > -1) {
    client.associatedGroupIds.splice(index, 1);
    client.dateUpdated = new Date().toISOString();
    await saveData();
  }
  return JSON.parse(JSON.stringify(client));
}

/**
 * Sets the complete list of associated group IDs for a client.
 * @param clientId The ID of the client.
 * @param groupIds An array of group IDs to associate. Old associations are replaced.
 */
export async function setClientAssociatedGroups(clientId: string, groupIds: number[]): Promise<void> {
    const client = dataStore.clients[clientId];
    if (!client) {
        throw new Error(`Client with ID "${clientId}" not found.`);
    }
    if (client.status !== 'approved') {
        throw new Error(`Client "${clientId}" is not approved. Cannot set group associations.`);
    }

    // Validate all group IDs exist before setting
    for (const groupId of groupIds) {
        if (!dataStore.secretGroups[groupId]) {
            throw new Error(`Secret group with ID "${groupId}" not found.`);
        }
    }

    client.associatedGroupIds = [...new Set(groupIds)]; // Ensure unique IDs and copy array
    client.dateUpdated = new Date().toISOString();
    await saveData();
    console.log(`Client ${clientId} associated groups updated to: ${client.associatedGroupIds.join(', ')}`);
}

/**
 * Retrieves all unique secret keys a client has access to through their associated groups.
 * @param clientId The ID of the client.
 * @returns An array of secret keys.
 */
export function getSecretsForClient(clientId: string): string[] {
    const client = dataStore.clients[clientId];
    if (!client || !client.associatedGroupIds || client.associatedGroupIds.length === 0) {
        return [];
    }

    const accessibleKeys = new Set<string>();
    for (const groupId of client.associatedGroupIds) {
        const group = dataStore.secretGroups[groupId];
        if (group && group.keys) {
            group.keys.forEach(key => accessibleKeys.add(key));
        }
    }
    return Array.from(accessibleKeys);
}


/**
 * Retrieves an approved client by their authToken.
 * @param authToken The authentication token of the client.
 * @returns ClientInfo object or undefined if not found or not approved.
 */
// export function getClientByAuthToken(authToken: string): ClientInfo | undefined {
//   const client = Object.values(dataStore.clients).find(
//     c => c.status === 'approved' && c.authToken === authToken
//   );
//   return client ? JSON.parse(JSON.stringify(client)) : undefined;
// }
// This function is now obsolete as authToken is removed.

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

/**
 * Handles a client disconnect. If the client was 'approved',
 * its status is set to 'rejected'.
 * @param clientId The ID of the disconnected client.
 */
export async function handleClientDisconnect(clientId: string): Promise<void> {
  const client = dataStore.clients[clientId];
  if (client) { // Check if client exists, to prevent errors if called with an already deleted/unknown ID
    if (client.status === 'approved') {
      console.log(`Approved client "${client.name}" (ID: ${client.id}) disconnected. Setting status to rejected.`);
      client.status = 'rejected';
      client.dateUpdated = new Date().toISOString();
      // No need to clear associatedSecretKeys, they might be useful if client is re-approved quickly.
      // Or, business logic might dictate clearing them. For now, keep them.
      try {
        await saveData();
        console.log(`Saved data after client ${clientId} disconnect.`);
      } catch (error) {
        console.error(`Failed to save data after client ${clientId} disconnect:`, error);
      }
    } else {
      console.log(`Client "${client.name}" (ID: ${client.id}) disconnected with status: ${client.status}. No status change needed from 'approved'.`);
    }
  } else {
    console.warn(`Attempted to handle disconnect for unknown client ID: ${clientId}`);
  }
}