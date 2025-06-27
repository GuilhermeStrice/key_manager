// Encryption and decryption utilities
import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const SALT_LENGTH = 16; // For master key derivation
const IV_LENGTH = 12;    // AES-GCM standard IV length
const AUTH_TAG_LENGTH = 16; // AES-GCM standard auth tag length
const PBKDF2_ITERATIONS = 310000; // OWASP recommendation (as of 2023)
const KEY_LENGTH = 32;    // 256 bits for AES-256

/**
 * Derives a master encryption key from a password and salt.
 * This should be done once when the server starts.
 */
export function deriveMasterKey(password: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');
}

/**
 * Generates a new random salt.
 */
export function generateSalt(): Buffer {
  return crypto.randomBytes(SALT_LENGTH);
}

/**
 * Encrypts plaintext using the master key.
 * Prepends a random IV to the ciphertext. Stores IV + AuthTag + Ciphertext.
 * @param text The plaintext string to encrypt.
 * @param masterKey The master encryption key (derived via deriveMasterKey).
 * @returns A string in the format: iv_hex:authTag_hex:ciphertext_hex
 */
export function encrypt(text: string, masterKey: Buffer): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, masterKey, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  // Store IV, authTag, and encrypted data together, all hex encoded
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypts ciphertext using the master key.
 * Expects the input string to be in the format: iv_hex:authTag_hex:ciphertext_hex
 * @param encryptedTextWithIvAndAuthTag The encrypted string.
 * @param masterKey The master encryption key.
 * @returns The decrypted plaintext string, or null if decryption fails.
 */
export function decrypt(encryptedTextWithIvAndAuthTag: string, masterKey: Buffer): string | null {
  try {
    const parts = encryptedTextWithIvAndAuthTag.split(':');
    if (parts.length !== 3) {
      console.error('Invalid encrypted text format. Expected iv:authTag:ciphertext.');
      return null;
    }

    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encryptedData = parts[2];

    if (iv.length !== IV_LENGTH) {
        console.error(`Invalid IV length. Expected ${IV_LENGTH}, got ${iv.length}`);
        return null;
    }
     if (authTag.length !== AUTH_TAG_LENGTH) {
        console.error(`Invalid AuthTag length. Expected ${AUTH_TAG_LENGTH}, got ${authTag.length}`);
        return null;
    }

    const decipher = crypto.createDecipheriv(ALGORITHM, masterKey, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    // Type guard for error
    if (error instanceof Error) {
        console.error('Decryption failed:', error.message);
    } else {
        console.error('Decryption failed with an unknown error:', error);
    }
    return null;
  }
}

// Example usage (for testing, can be removed or moved to a test file):
/*
if (require.main === module) {
    const examplePassword = 'mySuperSecretPassword123!';
    const salt = generateSalt(); // In a real app, this salt for the master key would be stored (e.g., in a config file or alongside the encrypted data if not sensitive)
                               // Or, if the data file itself is the only thing, the salt might need to be hardcoded or configured.
                               // For data at rest where the password is input each time, a fixed salt (or a salt stored with the encrypted blob) is common.
                               // Let's assume a fixed salt for the master key for now for simplicity of this example.
    const fixedSaltForMasterKey = Buffer.from('someFixedSalt12345', 'utf-8').slice(0, SALT_LENGTH); // Ensure it's correct length

    const masterKey = deriveMasterKey(examplePassword, fixedSaltForMasterKey);
    console.log('Master Key (hex):', masterKey.toString('hex'));

    const originalText = "Hello, world! This is a secret message.";
    console.log('\nOriginal Text:', originalText);

    const encryptedText = encrypt(originalText, masterKey);
    console.log('Encrypted Text:', encryptedText);

    if (encryptedText) {
        const decryptedText = decrypt(encryptedText, masterKey);
        console.log('Decrypted Text:', decryptedText);

        if (decryptedText !== originalText) {
            console.error('Decryption Mismatch!');
        }

        // Test with wrong key
        const wrongSalt = generateSalt();
        const wrongMasterKey = deriveMasterKey("wrongPassword!", wrongSalt);
        const decryptedWithWrongKey = decrypt(encryptedText, wrongMasterKey);
        console.log('\nDecrypted with WRONG key:', decryptedWithWrongKey); // Should be null

        // Test tampering (modify ciphertext)
        const parts = encryptedText.split(':');
        const tamperedCiphertext = parts[2].slice(0, -4) + "0000"; // Modify some bytes
        const tamperedEncryptedText = `${parts[0]}:${parts[1]}:${tamperedCiphertext}`;
        const decryptedTampered = decrypt(tamperedEncryptedText, masterKey);
        console.log('Decrypted Tampered Ciphertext:', decryptedTampered); // Should be null due to authTag mismatch

        // Test tampering (modify IV)
        const tamperedIv = crypto.randomBytes(IV_LENGTH).toString('hex');
        const tamperedEncryptedTextIv = `${tamperedIv}:${parts[1]}:${parts[2]}`;
        const decryptedTamperedIv = decrypt(tamperedEncryptedTextIv, masterKey);
        console.log('Decrypted Tampered IV:', decryptedTamperedIv); // Should be null

        // Test tampering (modify authTag)
        const tamperedAuthTag = crypto.randomBytes(AUTH_TAG_LENGTH).toString('hex');
        const tamperedEncryptedTextAuthTag = `${parts[0]}:${tamperedAuthTag}:${parts[2]}`;
        const decryptedTamperedAuthTag = decrypt(tamperedEncryptedTextAuthTag, masterKey);
        console.log('Decrypted Tampered AuthTag:', decryptedTamperedAuthTag); // Should be null
    }
}
*/
