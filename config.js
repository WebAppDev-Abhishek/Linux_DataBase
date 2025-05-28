// config.js
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Load environment variables from .env file
require('dotenv').config();

const DB_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DB_DIR, 'users.json');
const DATABASE_ENCRYPTED_FILE = path.join(DB_DIR, 'database.enc');
const LOG_FILE = path.join(DB_DIR, 'access.log');

// --- IMPORTANT: Master Encryption Key ---
// This key encrypts/decrypts the database content.
// NEVER hardcode this in a production application.
// Use an environment variable (e.g., DB_MASTER_KEY) or a secure key management system.
// Generate a strong key: crypto.randomBytes(32).toString('hex'); (for AES-256)
const DB_MASTER_KEY = process.env.DB_MASTER_KEY || 'your_super_secret_32_byte_key_for_db_encryption_do_not_use_in_prod'; // 32 bytes for AES-256

// Derive a buffer from the hex string
let DB_MASTER_KEY_BUFFER;
try {
    DB_MASTER_KEY_BUFFER = Buffer.from(DB_MASTER_KEY, 'hex');
    if (DB_MASTER_KEY_BUFFER.length !== 32) {
        throw new Error('DB_MASTER_KEY must be a 32-byte (64-character hex) string for AES-256.');
    }
} catch (error) {
    console.error('Error with DB_MASTER_KEY:', error.message);
    console.error('Please generate a 32-byte (64-character hex) key and set it in your .env file or config.js.');
    process.exit(1);
}

module.exports = {
    DB_DIR,
    USERS_FILE,
    DATABASE_ENCRYPTED_FILE,
    LOG_FILE,
    DB_MASTER_KEY_BUFFER,
    ENCRYPTION_ALGO: 'aes-256-cbc',
    IV_LENGTH: 16, // For AES-256-CBC, IV length is block size (16 bytes)
    SALT_LENGTH: 16, // For password hashing salt
    PBKDF2_ITERATIONS: 100000,
    PBKDF2_KEYLEN: 64, // For Scrypt, key length for password hashing
    PBKDF2_DIGEST: 'sha512',
    LOGIN_ATTEMPTS_LIMIT: 3,
    SERVER_PORT: 3000,
};