// server.js
const net = require('net');
const fs = require('fs').promises; // Use promises for async file operations
const path = require('path');
const crypto = require('crypto');
const readlineSync = require('readline-sync'); // For initial setup sync input, run only once

// Load configuration from config.js in the same directory
const config = require('./config'); 

const {
    DB_DIR, USERS_FILE, DATABASE_ENCRYPTED_FILE, LOG_FILE,
    DB_MASTER_KEY_BUFFER, ENCRYPTION_ALGO, IV_LENGTH, SALT_LENGTH,
    PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST,
    LOGIN_ATTEMPTS_LIMIT, SERVER_PORT
} = config;

let decryptedDatabaseContent = ''; // In-memory decrypted DB content

// --- Utility Functions ---

// Secure password hashing using PBKDF2
async function hashPassword(password, salt) {
    // Generate new salt if not provided (for new passwords)
    salt = salt || crypto.randomBytes(SALT_LENGTH).toString('hex');
    const hash = await new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST, (err, derivedKey) => {
            if (err) reject(err);
            resolve(derivedKey.toString('hex'));
        });
    });
    return { salt, hash };
}

// Verify password against stored hash
async function verifyPassword(password, storedSalt, storedHash) {
    const { hash } = await hashPassword(password, storedSalt);
    return hash === storedHash;
}

// Encryption for database content using AES-256-CBC with a master key
async function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGO, DB_MASTER_KEY_BUFFER, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted; // Store IV with encrypted data
}

// Decryption for database content
async function decrypt(encryptedText) {
    const parts = encryptedText.split(':');
    if (parts.length !== 2) {
        throw new Error('Invalid encrypted data format: Missing IV or data parts.');
    }
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];

    if (iv.length !== IV_LENGTH) {
        throw new Error(`Invalid IV length: Expected ${IV_LENGTH} bytes, got ${iv.length}.`);
    }

    try {
        const decipher = crypto.createDecipheriv(ENCRYPTION_ALGO, DB_MASTER_KEY_BUFFER, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        // Catch common decryption errors (e.g., incorrect key, corrupted data)
        console.error('Decryption failed:', error.message);
        throw new Error('Decryption failed: Data might be corrupted or key is incorrect.');
    }
}

// Log access attempts and actions
async function logAccess(username, status, action, clientInfo = '') {
    const timestamp = new Date().toISOString();
    const logEntry = `${timestamp} - User: ${username} - Status: ${status} - Action: ${action} ${clientInfo}\n`;
    await fs.appendFile(LOG_FILE, logEntry);
    console.log(logEntry.trim()); // Also log to console
}

// --- Data Persistence Layer ---

// Load all user data from users.json
async function loadUsers() {
    try {
        const data = await fs.readFile(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return []; // File not found, return empty array for first run
        }
        throw error; // Re-throw other errors
    }
}

// Save all user data to users.json
async function saveUsers(users) {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
    await fs.chmod(USERS_FILE, 0o600); // Set strict permissions (owner read/write)
}

// Load encrypted database content from database.enc
async function loadEncryptedDatabase() {
    try {
        const data = await fs.readFile(DATABASE_ENCRYPTED_FILE, 'utf8');
        return data;
    } catch (error) {
        if (error.code === 'ENOENT') {
            return null; // File not found, return null
        }
        throw error;
    }
}

// Save encrypted database content to database.enc
async function saveEncryptedDatabase(encryptedContent) {
    await fs.writeFile(DATABASE_ENCRYPTED_FILE, encryptedContent, 'utf8');
    await fs.chmod(DATABASE_ENCRYPTED_FILE, 0o600); // Set strict permissions (owner read/write)
}

// Get decrypted database content from memory (or load/decrypt if needed)
async function getDecryptedDatabaseContent() {
    if (!decryptedDatabaseContent) { // If not in memory, load and decrypt
        const encryptedContent = await loadEncryptedDatabase();
        if (encryptedContent) {
            decryptedDatabaseContent = await decrypt(encryptedContent);
        } else {
            // First run: Initialize with default content and encrypt
            const initialContent = 'This is the initial content of your secure database.';
            decryptedDatabaseContent = initialContent;
            await saveEncryptedDatabase(await encrypt(initialContent));
        }
    }
    return decryptedDatabaseContent;
}

// Set new decrypted database content and encrypt it for persistence
async function setDecryptedDatabaseContent(newContent) {
    decryptedDatabaseContent = newContent;
    await saveEncryptedDatabase(await encrypt(newContent));
}

// --- Initialization Logic ---

async function initializeDB() {
    console.log('Initializing database directory and files...');
    await fs.mkdir(DB_DIR, { recursive: true }); // Create directory if it doesn't exist
    await fs.chmod(DB_DIR, 0o700); // Set strict permissions (owner rwx)

    // Initialize users.json
    let users = await loadUsers();
    if (users.length === 0) {
        console.log('Creating default users...');
        const adminPass = readlineSync.question('Enter password for default admin user (adminpass): ', {hideEchoBack: true});
        const userPass = readlineSync.question('Enter password for default regular user (userpass): ', {hideEchoBack: true});

        const adminHash = await hashPassword(adminPass);
        const userHash = await hashPassword(userPass);

        users = [
            { username: 'admin', salt: adminHash.salt, hash: adminHash.hash, role: 'admin' },
            { username: 'user', salt: userHash.salt, hash: userHash.hash, role: 'user' },
        ];
        await saveUsers(users);
        console.log('Default users created: admin, user.');
        console.log('Passwords are securely hashed with PBKDF2/Scrypt.');
    } else {
        console.log('Users file already exists. Skipping default user creation.');
    }

    // Initialize database.enc
    const encryptedContentExists = await loadEncryptedDatabase();
    if (!encryptedContentExists) {
        console.log('Creating initial encrypted database file...');
        await getDecryptedDatabaseContent(); // This function will create and encrypt if it doesn't exist
        console.log('Initial encrypted database created.');
    } else {
        console.log('Encrypted database file already exists.');
    }

    // Ensure log file exists and has permissions
    try {
        await fs.access(LOG_FILE); // Check if file exists
    } catch (error) {
        if (error.code === 'ENOENT') {
            await fs.writeFile(LOG_FILE, ''); // Create empty log file
        }
    }
    await fs.chmod(LOG_FILE, 0o600); // Set strict permissions (owner read/write)

    console.log('Initialization complete.');
}

// --- Server Session Management ---

const activeSessions = new Map(); // Map to store active user sessions (socket.id -> {username, role})

// Get user session data
function getSessionUser(socket) {
    return activeSessions.get(socket.id);
}

// Middleware to check if user is authenticated
function requireAuth(socket, callback) {
    const user = getSessionUser(socket);
    if (!user) {
        socket.write('ERROR: Not logged in. Please LOGIN.\n');
        return false;
    }
    callback(user);
    return true;
}

// Middleware to check if user is admin
function requireAdmin(socket, callback) {
    return requireAuth(socket, (user) => {
        if (user.role !== 'admin') {
            socket.write('ERROR: Access denied. Admin privileges required.\n');
            return false;
        }
        callback(user);
        return true;
    });
}

// --- Server Command Handlers ---

const commandHandlers = {
    async LOGIN(socket, args) {
        const [username, password] = args;
        const clientInfo = `from ${socket.remoteAddress}:${socket.remotePort}`;

        if (!username || !password) {
            socket.write('ERROR: Usage: LOGIN <username> <password>\n');
            await logAccess('N/A', 'FAILURE', `LOGIN - Invalid arguments ${clientInfo}`);
            return;
        }

        if (getSessionUser(socket)) {
            socket.write('ERROR: Already logged in.\n');
            return;
        }

        // Implement rate limiting for login attempts per socket
        let loginAttempts = socket.loginAttempts || 0;
        if (loginAttempts >= LOGIN_ATTEMPTS_LIMIT) {
            socket.write('ERROR: Too many failed login attempts. Connection closed.\n');
            await logAccess(username, 'FAILURE', `LOGIN - Too many attempts ${clientInfo}`);
            socket.end(); // Terminate connection after too many attempts
            return;
        }

        const users = await loadUsers();
        const user = users.find(u => u.username === username);

        if (!user || !(await verifyPassword(password, user.salt, user.hash))) {
            socket.write('ERROR: Invalid credentials.\n');
            socket.loginAttempts = loginAttempts + 1;
            await logAccess(username, 'FAILURE', `LOGIN - Invalid credentials ${clientInfo}`);
            return;
        }
        
        // Authentication successful
        activeSessions.set(socket.id, { username: user.username, role: user.role });
        socket.write(`SUCCESS: Welcome, ${username}! (Role: ${user.role})\n`);
        await logAccess(username, 'SUCCESS', `LOGIN ${clientInfo}`);
        socket.loginAttempts = 0; // Reset attempts on success
    },

    async LOGOUT(socket) {
        requireAuth(socket, async (user) => {
            activeSessions.delete(socket.id);
            socket.write('SUCCESS: Logged out.\n');
            await logAccess(user.username, 'SUCCESS', `LOGOUT from ${socket.remoteAddress}:${socket.remotePort}`);
        });
    },

    async VIEW_DB(socket) {
        requireAuth(socket, async (user) => {
            const content = await getDecryptedDatabaseContent();
            socket.write(`SUCCESS: Database Content:\n${content}\nEND_DB_CONTENT\n`);
            await logAccess(user.username, 'SUCCESS', 'VIEW_DB');
        });
    },

    async EDIT_DB(socket, args) {
        requireAdmin(socket, async (user) => {
            const newContent = args.join(' ');
            if (!newContent) {
                socket.write('ERROR: Usage: EDIT_DB <new_content>\n');
                return;
            }
            await setDecryptedDatabaseContent(newContent);
            socket.write('SUCCESS: Database content updated.\n');
            await logAccess(user.username, 'SUCCESS', 'EDIT_DB');
        });
    },

    async CHANGE_PASSWORD(socket, args) {
        requireAuth(socket, async (user) => {
            const [currentPassword, newPassword] = args;
            if (!currentPassword || !newPassword) {
                socket.write('ERROR: Usage: CHANGE_PASSWORD <current_password> <new_password>\n');
                return;
            }

            const users = await loadUsers();
            const userIndex = users.findIndex(u => u.username === user.username);
            const storedUser = users[userIndex];

            if (!await verifyPassword(currentPassword, storedUser.salt, storedUser.hash)) {
                socket.write('ERROR: Current password incorrect.\n');
                await logAccess(user.username, 'FAILURE', 'CHANGE_PASSWORD - Incorrect current password');
                return;
            }

            const newHash = await hashPassword(newPassword);
            users[userIndex].salt = newHash.salt;
            users[userIndex].hash = newHash.hash;
            await saveUsers(users);

            socket.write('SUCCESS: Password changed successfully.\n');
            await logAccess(user.username, 'SUCCESS', 'CHANGE_PASSWORD');
        });
    },

    async ADD_USER(socket, args) {
        requireAdmin(socket, async (adminUser) => {
            const [newUsername, newPassword, newRole] = args;
            if (!newUsername || !newPassword || !newRole) {
                socket.write('ERROR: Usage: ADD_USER <username> <password> <role (admin/user)>\n');
                return;
            }
            if (newRole !== 'admin' && newRole !== 'user') {
                socket.write('ERROR: Role must be "admin" or "user".\n');
                return;
            }

            const users = await loadUsers();
            if (users.some(u => u.username === newUsername)) {
                socket.write('ERROR: User already exists.\n');
                return;
            }

            const { salt, hash } = await hashPassword(newPassword);
            users.push({ username: newUsername, salt, hash, role: newRole });
            await saveUsers(users);
            socket.write(`SUCCESS: User ${newUsername} with role ${newRole} added.\n`);
            await logAccess(adminUser.username, 'SUCCESS', `ADD_USER: ${newUsername} (${newRole})`);
        });
    },

    async DELETE_USER(socket, args) {
        requireAdmin(socket, async (adminUser) => {
            const [usernameToDelete] = args;
            if (!usernameToDelete) {
                socket.write('ERROR: Usage: DELETE_USER <username>\n');
                return;
            }
            if (usernameToDelete === adminUser.username) {
                socket.write('ERROR: You cannot delete yourself.\n');
                return;
            }

            let users = await loadUsers();
            const initialLength = users.length;
            users = users.filter(u => u.username !== usernameToDelete);

            if (users.length < initialLength) {
                await saveUsers(users);
                socket.write(`SUCCESS: User ${usernameToDelete} deleted.\n`);
                await logAccess(adminUser.username, 'SUCCESS', `DELETE_USER: ${usernameToDelete}`);
            } else {
                socket.write('ERROR: User not found.\n');
                await logAccess(adminUser.username, 'FAILURE', `DELETE_USER: ${usernameToDelete} (Not found)`);
            }
        });
    },
};

// --- TCP Server Setup ---

const server = net.createServer((socket) => {
    // Assign a unique ID to the socket for session management
    socket.id = crypto.randomBytes(16).toString('hex');
    console.log(`Client connected from ${socket.remoteAddress}:${socket.remotePort} (ID: ${socket.id})`);
    logAccess('N/A', 'INFO', `Client connected from ${socket.remoteAddress}:${socket.remotePort}`);
    socket.write('Welcome to the Secure DB Server!\n');
    socket.write('Commands: LOGIN <user> <pass>, VIEW_DB, EDIT_DB <content>, CHANGE_PASSWORD <current> <new>, ADD_USER <user> <pass> <role>, DELETE_USER <user>, LOGOUT\n');

    // Handle incoming data (commands)
    socket.on('data', async (data) => {
        const commandLine = data.toString().trim();
        console.log(`Received from ${socket.id}: ${commandLine}`);

        const parts = commandLine.split(' ');
        const command = parts[0].toUpperCase(); // Extract command (e.g., "LOGIN")
        const args = parts.slice(1); // Extract arguments

        if (commandHandlers[command]) {
            try {
                await commandHandlers[command](socket, args); // Execute the command handler
            } catch (error) {
                console.error(`Error handling command ${command} from ${socket.id}:`, error);
                socket.write('ERROR: Server error processing your command.\n');
                await logAccess(getSessionUser(socket)?.username || 'N/A', 'ERROR', `Command error: ${commandLine} - ${error.message}`);
            }
        } else {
            socket.write('ERROR: Unknown command.\n');
            await logAccess(getSessionUser(socket)?.username || 'N/A', 'FAILURE', `Unknown command: ${commandLine}`);
        }
    });

    // Handle client disconnection
    socket.on('end', () => {
        const user = getSessionUser(socket);
        if (user) {
            activeSessions.delete(socket.id); // Remove session on disconnect
            console.log(`Client ${socket.id} (${user.username}) disconnected.`);
            logAccess(user.username, 'INFO', `Disconnected from ${socket.remoteAddress}:${socket.remotePort}`);
        } else {
            console.log(`Client ${socket.id} disconnected.`);
            logAccess('N/A', 'INFO', `Disconnected from ${socket.remoteAddress}:${socket.remotePort}`);
        }
    });

    // Handle socket errors
    socket.on('error', (err) => {
        console.error(`Socket error from ${socket.id}:`, err.message);
        logAccess(getSessionUser(socket)?.username || 'N/A', 'ERROR', `Socket error: ${err.message}`);
    });
});

// Start the server after database initialization
initializeDB().then(() => {
    server.listen(SERVER_PORT, () => {
        console.log(`Server listening on port ${SERVER_PORT}`);
        console.log('--- READY FOR CLIENT CONNECTIONS ---');
        console.log('Remember to set a strong DB_MASTER_KEY in your .env file!');
        console.log('WARNING: This example does NOT use TLS/SSL for network encryption. DO NOT USE FOR SENSITIVE DATA IN PRODUCTION.');
    });
}).catch(err => {
    console.error('Failed to initialize database and start server:', err);
    process.exit(1); // Exit if initialization fails
});