import * as DataManager from './dataManager';
import { encrypt, decrypt, deriveMasterKey, generateSalt } from './encryption';
import fs from 'fs/promises';
import crypto from 'crypto';

// Mock the dependencies
jest.mock('fs/promises');
jest.mock('./encryption');

// Helper to reset DataManager internal state if needed for some tests, though typically we test its public API.
// This is a bit hacky; ideally, DataManager would be a class or have an explicit reset function for testing.
// For now, we'll rely on Jest's module cache clearing or test individual functions carefully.

const MOCK_PASSWORD = 'testpassword';
const MOCK_MASTER_KEY = Buffer.from('mockMasterKeyDerived');
const MOCK_SALT = Buffer.from('mockSaltForMasterKey');

describe('DataManager', () => {
  let mockEncryptedData: string;

  beforeEach(async () => {
    // Reset mocks for each test
    jest.clearAllMocks();

    // Setup default mock implementations
    (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify(MOCK_SALT.toString('hex'))); // For salt loading
    (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
    (fs.access as jest.Mock).mockResolvedValue(undefined); // Assume data dir exists
    (fs.mkdir as jest.Mock).mockResolvedValue(undefined);


    (generateSalt as jest.Mock).mockReturnValue(MOCK_SALT);
    (deriveMasterKey as jest.Mock).mockReturnValue(MOCK_MASTER_KEY);
    (encrypt as jest.Mock).mockImplementation((text: string, _key: Buffer) => `encrypted:${text}`);
    (decrypt as jest.Mock).mockImplementation((encText: string, _key: Buffer) => {
      if (encText.startsWith('encrypted:')) {
        return encText.substring('encrypted:'.length);
      }
      return null; // Simulate decryption failure for bad data
    });

    // Initialize dataStore to a clean state for relevant tests
    // This is tricky because dataStore is a module-level variable.
    // We re-initialize DataManager which resets its internal store before loading.
    mockEncryptedData = `encrypted:${JSON.stringify({ secrets: {}, clients: {} })}`;
    (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(MOCK_SALT.toString('hex')) // For salt
        .mockResolvedValueOnce(mockEncryptedData); // For data file

    await DataManager.initializeDataManager(MOCK_PASSWORD);
    // Clear fs.writeFile mock calls from initialization
    (fs.writeFile as jest.Mock).mockClear();
  });

  describe('Initialization', () => {
    it('should initialize, create data directory and salt file if they do not exist', async () => {
      (fs.access as jest.Mock).mockRejectedValueOnce(new Error('ENOENT_DIR')).mockRejectedValueOnce(new Error('ENOENT_SALT')); // Dir and salt don't exist
      // Simulate fs.readFile failing for both salt and data files
      const saltError: any = new Error('Salt file not found');
      saltError.code = 'ENOENT';
      const dataError: any = new Error('Data file not found');
      dataError.code = 'ENOENT';
      (fs.readFile as jest.Mock) // Override for this test
        .mockRejectedValueOnce(saltError) // Salt file read fails
        .mockRejectedValueOnce(dataError); // Data file read fails

      await DataManager.initializeDataManager('newpassword');

      expect(fs.mkdir).toHaveBeenCalledWith(expect.stringContaining('data'), { recursive: true });
      expect(generateSalt).toHaveBeenCalled();
      expect(fs.writeFile).toHaveBeenCalledWith(expect.stringContaining('masterkey.salt'), expect.any(String), 'utf-8');
      expect(deriveMasterKey).toHaveBeenCalledWith('newpassword', MOCK_SALT);
      // It will try to load data, fail (ENOENT), and initialize an empty store.
      // A save might be triggered if we decide to save empty store on ENOENT. Current impl does not.
      // So, fs.writeFile for data should not be called if data file doesn't exist and store is just initialized empty.
      // Let's verify no unexpected data write
      const dataWriteCall = (fs.writeFile as jest.Mock).mock.calls.find(call => call[0].endsWith('.enc'));
      expect(dataWriteCall).toBeUndefined();
    });

    it('should load existing salt and data', async () => {
        const initialSecrets = { testSecret: 'value1' };
        const initialClients = { client1: { id: 'client1', name: 'Test Client', status: 'approved', associatedSecretKeys: [], dateCreated: '', dateUpdated: '' } };
        const encryptedExistingData = `encrypted:${JSON.stringify({ secrets: initialSecrets, clients: initialClients })}`;

        (fs.readFile as jest.Mock)
            .mockResolvedValueOnce(MOCK_SALT.toString('hex')) // For salt
            .mockResolvedValueOnce(encryptedExistingData); // For data file

        await DataManager.initializeDataManager(MOCK_PASSWORD);

        expect(generateSalt).not.toHaveBeenCalled(); // Should use existing salt
        expect(deriveMasterKey).toHaveBeenCalledWith(MOCK_PASSWORD, MOCK_SALT);
        expect(decrypt).toHaveBeenCalledWith(encryptedExistingData, MOCK_MASTER_KEY);
        expect(DataManager.getSecretItem('testSecret')).toBe('value1');
        expect(DataManager.getClient('client1')?.name).toBe('Test Client');
    });

    it('should handle old data format (only secrets) during load and migrate', async () => {
        const oldFormatData = { myOldSecret: "oldValue" };
        const encryptedOldFormatData = `encrypted:${JSON.stringify(oldFormatData)}`;

        (fs.readFile as jest.Mock)
            .mockResolvedValueOnce(MOCK_SALT.toString('hex'))
            .mockResolvedValueOnce(encryptedOldFormatData);

        await DataManager.initializeDataManager(MOCK_PASSWORD);
        expect(DataManager.getSecretItem('myOldSecret')).toBe('oldValue');
        expect(DataManager.getAllClients()).toEqual([]); // Clients should be empty
    });
  });

  describe('Secret Management', () => {
    beforeEach(async () => {
      // Ensure a clean state for secrets for each test in this block
      const emptyStore = { secrets: {}, clients: {} };
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(MOCK_SALT.toString('hex')) // For salt
        .mockResolvedValueOnce(`encrypted:${JSON.stringify(emptyStore)}`); // For data file
      await DataManager.initializeDataManager(MOCK_PASSWORD);
      (fs.writeFile as jest.Mock).mockClear(); // Clear init writes
    });

    it('should set and get a secret item', async () => {
      await DataManager.setSecretItem('key1', 'value1');
      expect(DataManager.getSecretItem('key1')).toBe('value1');
      expect(fs.writeFile).toHaveBeenCalledTimes(1); // saveData called
      expect(encrypt).toHaveBeenCalledWith(JSON.stringify({ secrets: { key1: 'value1' }, clients: {} }, null, 2), MOCK_MASTER_KEY);
    });

    it('should delete a secret item and update client associations', async () => {
      // Setup: client associated with the secret to be deleted
      const client = await DataManager.addPendingClient('Test Client For Deletion');
      await DataManager.approveClient(client.id);
      await DataManager.setSecretItem('secretToDelete', 'data');
      await DataManager.associateSecretWithClient(client.id, 'secretToDelete');

      let fetchedClient = DataManager.getClient(client.id);
      expect(fetchedClient?.associatedSecretKeys).toContain('secretToDelete');

      (fs.writeFile as jest.Mock).mockClear(); // Clear previous writes

      await DataManager.deleteSecretItem('secretToDelete');
      expect(DataManager.getSecretItem('secretToDelete')).toBeUndefined();

      fetchedClient = DataManager.getClient(client.id);
      expect(fetchedClient?.associatedSecretKeys).not.toContain('secretToDelete');
      expect(fs.writeFile).toHaveBeenCalledTimes(1); // saveData from deleteSecretItem
    });

    it('should get all secret keys', async () => {
      await DataManager.setSecretItem('key1', 'val1');
      await DataManager.setSecretItem('key2', 'val2');
      expect(DataManager.getAllSecretKeys()).toEqual(expect.arrayContaining(['key1', 'key2']));
    });
  });

  describe('Client Management', () => {
     beforeEach(async () => {
      // Ensure a clean state for clients for each test in this block
      const emptyStore = { secrets: {}, clients: {} };
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(MOCK_SALT.toString('hex'))
        .mockResolvedValueOnce(`encrypted:${JSON.stringify(emptyStore)}`);
      await DataManager.initializeDataManager(MOCK_PASSWORD);
      (fs.writeFile as jest.Mock).mockClear();
    });

    it('should add a pending client', async () => {
      const clientName = 'New App';
      const requestedKeys = ['secretA'];
      const client = await DataManager.addPendingClient(clientName, requestedKeys);

      expect(client.name).toBe(clientName);
      expect(client.status).toBe('pending');
      expect(client.id).toMatch(/^client_/);
      expect(client.temporaryId).toMatch(/^temp_/);
      expect(client.requestedSecretKeys).toEqual(requestedKeys);
      expect(fs.writeFile).toHaveBeenCalledTimes(1); // saveData

      const fetchedClient = DataManager.getClient(client.id);
      expect(fetchedClient).toEqual(client);
    });

    it('should throw error if client name is empty for addPendingClient', async () => {
        await expect(DataManager.addPendingClient('')).rejects.toThrow("Client name must be a non-empty string.");
    });


    it('should approve a pending client', async () => {
      const pendingClient = await DataManager.addPendingClient('AppToApprove');
      (fs.writeFile as jest.Mock).mockClear(); // Clear write from addPendingClient

      const approvedClient = await DataManager.approveClient(pendingClient.id);
      expect(approvedClient.status).toBe('approved');
      expect(approvedClient.authToken).toMatch(/^auth_/);
      expect(approvedClient.temporaryId).toBeUndefined();
      expect(fs.writeFile).toHaveBeenCalledTimes(1); // saveData

      const fetchedClient = DataManager.getClient(approvedClient.id);
      expect(fetchedClient?.status).toBe('approved');
      expect(fetchedClient?.authToken).toBe(approvedClient.authToken);
    });

    it('should throw error when approving non-pending client', async () => {
      const pendingClient = await DataManager.addPendingClient('AppToApproveTwice');
      await DataManager.approveClient(pendingClient.id); // First approval
      await expect(DataManager.approveClient(pendingClient.id)).rejects.toThrow(`Client "${pendingClient.id}" is not in 'pending' state.`);
    });

    it('should throw error when approving non-existent client', async () => {
        await expect(DataManager.approveClient('nonExistentId')).rejects.toThrow('Client with ID "nonExistentId" not found.');
    });

    it('should reject a pending client', async () => {
      const pendingClient = await DataManager.addPendingClient('AppToReject');
      (fs.writeFile as jest.Mock).mockClear();

      const rejectedClient = await DataManager.rejectClient(pendingClient.id);
      expect(rejectedClient.status).toBe('rejected');
      expect(rejectedClient.authToken).toBeUndefined();
      expect(rejectedClient.temporaryId).toBeUndefined(); // Should also clear temporaryId
      expect(fs.writeFile).toHaveBeenCalledTimes(1);

      const fetchedClient = DataManager.getClient(rejectedClient.id);
      expect(fetchedClient?.status).toBe('rejected');
    });

    it('should get various lists of clients', async () => {
      const p1 = await DataManager.addPendingClient('Pending1');
      const p2 = await DataManager.addPendingClient('Pending2');
      const a1 = await DataManager.approveClient(p1.id); // p1 becomes a1 (approved)

      expect(DataManager.getPendingClients().map(c => c.id)).toEqual([p2.id]);
      expect(DataManager.getApprovedClients().map(c => c.id)).toEqual([a1.id]);
      expect(DataManager.getAllClients().length).toBe(2);
    });

    it('should associate and dissociate secrets with an approved client', async () => {
      await DataManager.setSecretItem('s1', 'v1');
      await DataManager.setSecretItem('s2', 'v2');
      const client = await DataManager.addPendingClient('ClientForSecrets');
      await DataManager.approveClient(client.id);
      (fs.writeFile as jest.Mock).mockClear();

      // Associate
      await DataManager.associateSecretWithClient(client.id, 's1');
      let updatedClient = DataManager.getClient(client.id);
      expect(updatedClient?.associatedSecretKeys).toContain('s1');
      expect(fs.writeFile).toHaveBeenCalledTimes(1);
      (fs.writeFile as jest.Mock).mockClear();

      // Dissociate
      await DataManager.dissociateSecretFromClient(client.id, 's1');
      updatedClient = DataManager.getClient(client.id);
      expect(updatedClient?.associatedSecretKeys).not.toContain('s1');
      expect(fs.writeFile).toHaveBeenCalledTimes(1);
    });

    it('should throw error associating secret with non-approved client', async () => {
        const pendingClient = await DataManager.addPendingClient('NonApprovedClient');
        await DataManager.setSecretItem('s3', 'v3');
        await expect(DataManager.associateSecretWithClient(pendingClient.id, 's3'))
            .rejects.toThrow(`Client "${pendingClient.id}" is not approved.`);
    });

    it('should throw error associating non-existent secret', async () => {
        const client = await DataManager.addPendingClient('ClientForSecrets2');
        await DataManager.approveClient(client.id);
        await expect(DataManager.associateSecretWithClient(client.id, 'nonExistentSecret'))
            .rejects.toThrow('Secret with key "nonExistentSecret" not found.');
    });


    it('should get a client by auth token', async () => {
      const client = await DataManager.addPendingClient('ClientWithToken');
      const approved = await DataManager.approveClient(client.id);

      const foundClient = DataManager.getClientByAuthToken(approved.authToken!);
      expect(foundClient?.id).toBe(client.id);
      expect(foundClient?.name).toBe(client.name);

      expect(DataManager.getClientByAuthToken('invalidToken')).toBeUndefined();
    });

    it('should delete a client', async () => {
      const client = await DataManager.addPendingClient('ClientToDelete');
      (fs.writeFile as jest.Mock).mockClear();

      await DataManager.deleteClient(client.id);
      expect(DataManager.getClient(client.id)).toBeUndefined();
      expect(fs.writeFile).toHaveBeenCalledTimes(1);
    });
  });
});

// Helper to simulate dataStore reset for testing purposes if DataManager was a class with instances
// Or if it had an explicit reset function. For module-level state, this is more complex.
// This mock test suite relies on Jest's behavior with module mocks and careful sequencing.
// If DataManager.ts was refactored to be instantiable, testing state would be cleaner.
// e.g., let dataManagerInstance; beforeEach(() => { dataManagerInstance = new DataManager(); ... });
// For now, initializeDataManager is our main point of "resetting" the loaded data.
