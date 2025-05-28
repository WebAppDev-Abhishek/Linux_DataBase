#!/bin/bash

# This script simulates a basic "server database" with login, hashed passwords,
# encrypted database content, and rudimentary role-based access control.
#
# WARNING: This script is for educational purposes ONLY. It is NOT secure
#          enough for sensitive data or production environments.
#          - Passwords are SHA256 hashed but NOT salted.
#          - Encryption uses the user's password as the passphrase, which is
#            a simplification. A dedicated KDF with a unique salt per user
#            is required for real security.
#          - A temporary plain-text database file exists while logged in.
#          - No protection against data tampering (integrity check).
#          - Not designed for concurrent multi-user access.

# --- Configuration ---
DB_DIR="secure_db_data"
USERS_FILE="$DB_DIR/users.txt"
DATABASE_PLAINTEXT_TEMP="$DB_DIR/database.dblf" # Temporary decrypted file
DATABASE_ENCRYPTED_PERSISTENT="$DB_DIR/database.enc" # Permanent encrypted file
LOG_FILE="$DB_DIR/access.log"

# Encryption algorithm and options
ENCRYPTION_ALGO="aes-256-cbc"
OPENSSL_OPTIONS="-pbkdf2" # Use PBKDF2 for key derivation from passphrase

# --- Global Variables (set after successful login) ---
CURRENT_USER=""
CURRENT_USER_ROLE=""
CURRENT_LOGIN_PASSWORD="" # Stored temporarily for encryption/decryption

# --- Functions ---

# Function to hash a password using SHA256 (no salting for simplicity)
hash_password() {
    echo -n "$1" | sha256sum | awk '{print $1}'
}

# Function to encrypt the database file
encrypt_data() {
    local source_file="$1"
    local dest_file="$2"
    local password="$3"

    if [ ! -f "$source_file" ]; then
        echo "Error: Source file '$source_file' not found for encryption." | tee -a "$LOG_FILE"
        return 1
    fi

    echo "Encrypting '$source_file' to '$dest_file'..." | tee -a "$LOG_FILE"
    if ! openssl enc -"$ENCRYPTION_ALGO" -salt "$OPENSSL_OPTIONS" -pass pass:"$password" -in "$source_file" -out "$dest_file"; then
        echo "Error: Encryption failed for '$source_file'." | tee -a "$LOG_FILE"
        return 1
    fi
    # Set strict permissions on the encrypted file
    chmod 600 "$dest_file"
    echo "Encryption successful." | tee -a "$LOG_FILE"
    return 0
}

# Function to decrypt the database file
decrypt_data() {
    local source_file="$1"
    local dest_file="$2"
    local password="$3"

    if [ ! -f "$source_file" ]; then
        echo "Error: Encrypted file '$source_file' not found for decryption." | tee -a "$LOG_FILE"
        return 1
    fi

    echo "Attempting to decrypt '$source_file' to '$dest_file'..." | tee -a "$LOG_FILE"
    # openssl will return 0 even on wrong password if -d is used, but output will be garbage.
    # We check for successful decryption by looking at the exit code and file content.
    if ! openssl enc -d -"$ENCRYPTION_ALGO" -salt "$OPENSSL_OPTIONS" -pass pass:"$password" -in "$source_file" -out "$dest_file" 2>/dev/null; then
        echo "Error: Decryption failed for '$source_file'. Incorrect password or corrupted file." | tee -a "$LOG_FILE"
        rm -f "$dest_file" # Clean up potentially corrupted output
        return 1
    fi

    # Basic check to see if the decrypted file is empty, which might indicate wrong password
    if [ ! -s "$dest_file" ]; then
        echo "Error: Decrypted file '$dest_file' is empty. Possible incorrect password or corrupted data." | tee -a "$LOG_FILE"
        rm -f "$dest_file"
        return 1
    fi

    # Set strict permissions on the temporary decrypted file
    chmod 600 "$dest_file"
    echo "Decryption successful." | tee -a "$LOG_FILE"
    return 0
}

# Function to initialize the database directory and files
initialize_db() {
    echo "Initializing database directory and files..."
    mkdir -p "$DB_DIR"
    chmod 700 "$DB_DIR" # Set strict permissions on the directory

    if [ ! -f "$USERS_FILE" ]; then
        echo "Creating users file: $USERS_FILE"
        # Format: username:hashed_password:role
        # Hash default passwords before storing
        echo "admin:$(hash_password "adminpass"):admin" > "$USERS_FILE"
        echo "user:$(hash_password "userpass"):user" >> "$USERS_FILE"
        echo "Default users created: admin (adminpass), user (userpass)"
        echo "Passwords are SHA256 hashed."
        chmod 600 "$USERS_FILE" # Set strict permissions
    fi

    if [ ! -f "$DATABASE_ENCRYPTED_PERSISTENT" ]; then
        echo "Creating initial encrypted database file: $DATABASE_ENCRYPTED_PERSISTENT"
        # Create a temporary plain-text file first
        echo "This is the initial content of your simple database." > "$DATABASE_PLAINTEXT_TEMP"
        echo "Only 'admin' users can edit this content." >> "$DATABASE_PLAINTEXT_TEMP"
        # Encrypt it with a default password (e.g., admin's password)
        if ! encrypt_data "$DATABASE_PLAINTEXT_TEMP" "$DATABASE_ENCRYPTED_PERSISTENT" "adminpass"; then
            echo "Failed to create initial encrypted database. Exiting."
            rm -f "$DATABASE_PLAINTEXT_TEMP"
            exit 1
        fi
        rm -f "$DATABASE_PLAINTEXT_TEMP" # Remove the temporary plain-text file
        echo "Initial encrypted database created."
    fi

    if [ ! -f "$LOG_FILE" ]; then
        echo "Creating log file: $LOG_FILE"
        touch "$LOG_FILE"
        chmod 600 "$LOG_FILE" # Set strict permissions
    fi

    echo "Initialization complete."
}

# Function to log access attempts
log_access() {
    local username="$1"
    local status="$2" # e.g., "SUCCESS", "FAILURE"
    local message="$3" # e.g., "Login", "Logout", "Edit"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - User: $username - Status: $status - Action: $message" >> "$LOG_FILE"
}

# Function for user login
login() {
    local authenticated=false
    local attempts=0
    local max_attempts=3

    while [ "$authenticated" = false ] && [ "$attempts" -lt "$max_attempts" ]; do
        read -rp "Enter username: " input_username
        read -rsp "Enter password: " input_password
        echo # New line after password input

        local hashed_input_password=$(hash_password "$input_password")
        local user_entry=$(grep "^$input_username:" "$USERS_FILE")

        if [ -n "$user_entry" ]; then
            local stored_hashed_password=$(echo "$user_entry" | cut -d ':' -f 2)
            local stored_role=$(echo "$user_entry" | cut -d ':' -f 3)

            if [ "$hashed_input_password" = "$stored_hashed_password" ]; then
                # Attempt to decrypt the database with the provided password
                if decrypt_data "$DATABASE_ENCRYPTED_PERSISTENT" "$DATABASE_PLAINTEXT_TEMP" "$input_password"; then
                    authenticated=true
                    CURRENT_USER="$input_username"
                    CURRENT_USER_ROLE="$stored_role"
                    CURRENT_LOGIN_PASSWORD="$input_password" # Store password temporarily for encryption/decryption
                    echo "Login successful for user: $CURRENT_USER (Role: $CURRENT_USER_ROLE)"
                    log_access "$CURRENT_USER" "SUCCESS" "Login"
                else
                    echo "Authentication failed: Could not decrypt database. Incorrect password or corrupted data."
                    log_access "$input_username" "FAILURE" "Login - Decryption Failed"
                fi
            else
                echo "Invalid username or password."
                log_access "$input_username" "FAILURE" "Login - Incorrect Password"
            fi
        else
            echo "Invalid username or password."
            log_access "$input_username" "FAILURE" "Login - User Not Found"
        fi

        if [ "$authenticated" = false ]; then
            attempts=$((attempts + 1))
            echo "Attempts left: $((max_attempts - attempts))"
            sleep 1 # Small delay to deter brute-force attempts
        fi
    done

    if [ "$authenticated" = true ]; then
        return 0 # Success
    else
        echo "Too many failed login attempts. Exiting."
        return 1 # Failure
    fi
}

# Function to handle logout
logout() {
    echo "Logging out. Goodbye, $CURRENT_USER!"
    log_access "$CURRENT_USER" "SUCCESS" "Logout"

    # Encrypt the temporary plain-text database back to the persistent encrypted file
    if [ -f "$DATABASE_PLAINTEXT_TEMP" ]; then
        if encrypt_data "$DATABASE_PLAINTEXT_TEMP" "$DATABASE_ENCRYPTED_PERSISTENT" "$CURRENT_LOGIN_PASSWORD"; then
            rm -f "$DATABASE_PLAINTEXT_TEMP" # Remove the temporary decrypted file
        else
            echo "WARNING: Failed to re-encrypt database on logout. Data might be lost or exposed if not handled manually." | tee -a "$LOG_FILE"
        fi
    fi

    # Clear global variables
    CURRENT_USER=""
    CURRENT_USER_ROLE=""
    CURRENT_LOGIN_PASSWORD=""
}

# Function to display the database content
view_database() {
    echo -e "\n--- Database Content for $CURRENT_USER (Role: $CURRENT_USER_ROLE) ---"
    if [ -f "$DATABASE_PLAINTEXT_TEMP" ]; then
        cat "$DATABASE_PLAINTEXT_TEMP"
    else
        echo "Database file not found or not decrypted."
    fi
    echo "-----------------------------------"
    log_access "$CURRENT_USER" "SUCCESS" "View Database"
}

# Function to edit the database content (Admin only)
edit_database() {
    if [ "$CURRENT_USER_ROLE" != "admin" ]; then
        echo "Access denied: Only 'admin' users can edit the database."
        log_access "$CURRENT_USER" "FAILURE" "Edit Database - Permission Denied"
        return 1
    fi

    echo -e "\n--- Editing Database Content for $CURRENT_USER ---"
    echo "Opening $DATABASE_PLAINTEXT_TEMP in your default editor (e.g., nano, vi)."
    echo "Save and exit the editor to apply changes."
    # Use 'vi' as a common default, but 'nano' is more user-friendly
    "${EDITOR:-vi}" "$DATABASE_PLAINTEXT_TEMP"
    echo "Database content updated."
    log_access "$CURRENT_USER" "SUCCESS" "Edit Database"
}

# Function to change user password
change_password() {
    echo -e "\n--- Change Password for $CURRENT_USER ---"
    read -rsp "Enter current password: " current_password_input
    echo

    local hashed_current_password_input=$(hash_password "$current_password_input")
    local user_entry=$(grep "^$CURRENT_USER:" "$USERS_FILE")
    local stored_hashed_password=$(echo "$user_entry" | cut -d ':' -f 2)

    if [ "$hashed_current_password_input" = "$stored_hashed_password" ]; then
        read -rsp "Enter new password: " new_password1
        echo
        read -rsp "Confirm new password: " new_password2
        echo

        if [ "$new_password1" = "$new_password2" ]; then
            if [ -z "$new_password1" ]; then
                echo "New password cannot be empty. Password not changed."
                return 1
            fi

            local hashed_new_password=$(hash_password "$new_password1")
            local old_password_for_encryption="$CURRENT_LOGIN_PASSWORD" # Use the password used for current login
            local new_password_for_encryption="$new_password1"

            # 1. Decrypt the database with the old password (if not already decrypted)
            # This step is redundant if already logged in, but good for robustness.
            if [ ! -f "$DATABASE_PLAINTEXT_TEMP" ]; then
                if ! decrypt_data "$DATABASE_ENCRYPTED_PERSISTENT" "$DATABASE_PLAINTEXT_TEMP" "$old_password_for_encryption"; then
                    echo "Error: Failed to decrypt database with current password for re-encryption. Password not changed."
                    return 1
                fi
            fi

            # 2. Re-encrypt the database with the new password
            if ! encrypt_data "$DATABASE_PLAINTEXT_TEMP" "$DATABASE_ENCRYPTED_PERSISTENT" "$new_password_for_encryption"; then
                echo "Error: Failed to re-encrypt database with new password. Password not changed."
                return 1
            fi

            # 3. Update the hashed password in users.txt
            sed -i "/^$CURRENT_USER:/s/:$stored_hashed_password:/:$hashed_new_password:/" "$USERS_FILE"
            echo "Password for $CURRENT_USER successfully changed."
            log_access "$CURRENT_USER" "SUCCESS" "Change Password"

            # 4. Update the temporarily stored login password
            CURRENT_LOGIN_PASSWORD="$new_password1"

            # 5. Clean up temporary decrypted file
            rm -f "$DATABASE_PLAINTEXT_TEMP"

        else
            echo "New passwords do not match. Password not changed."
            log_access "$CURRENT_USER" "FAILURE" "Change Password - Mismatch"
        fi
    else
        echo "Incorrect current password. Password not changed."
        log_access "$CURRENT_USER" "FAILURE" "Change Password - Incorrect Current"
    fi
}

# Function to add a new user (Admin only)
add_user() {
    if [ "$CURRENT_USER_ROLE" != "admin" ]; then
        echo "Access denied: Only 'admin' users can add new users."
        log_access "$CURRENT_USER" "FAILURE" "Add User - Permission Denied"
        return 1
    fi

    echo -e "\n--- Add New User ---"
    read -rp "Enter new username: " new_username
    if grep -q "^$new_username:" "$USERS_FILE"; then
        echo "Error: User '$new_username' already exists."
        log_access "$CURRENT_USER" "FAILURE" "Add User - User Exists"
        return 1
    fi

    read -rsp "Enter password for $new_username: " new_password1
    echo
    read -rsp "Confirm password for $new_username: " new_password2
    echo

    if [ "$new_password1" = "$new_password2" ]; then
        if [ -z "$new_password1" ]; then
            echo "Password cannot be empty. User not added."
            return 1
        fi
        local hashed_new_password=$(hash_password "$new_password1")
        read -rp "Enter role for $new_username (admin/user, default: user): " new_role
        new_role=${new_role:-user} # Default to 'user' if empty

        echo "$new_username:$hashed_new_password:$new_role" >> "$USERS_FILE"
        echo "User '$new_username' with role '$new_role' added successfully."
        log_access "$CURRENT_USER" "SUCCESS" "Add User: $new_username (Role: $new_role)"
    else
        echo "Passwords do not match. User not added."
        log_access "$CURRENT_USER" "FAILURE" "Add User - Password Mismatch"
    fi
}

# Function to delete a user (Admin only)
delete_user() {
    if [ "$CURRENT_USER_ROLE" != "admin" ]; then
        echo "Access denied: Only 'admin' users can delete users."
        log_access "$CURRENT_USER" "FAILURE" "Delete User - Permission Denied"
        return 1
    fi

    echo -e "\n--- Delete User ---"
    read -rp "Enter username to delete: " user_to_delete

    if [ "$user_to_delete" = "$CURRENT_USER" ]; then
        echo "Error: You cannot delete yourself."
        log_access "$CURRENT_USER" "FAILURE" "Delete User - Self-Deletion Attempt"
        return 1
    fi

    if grep -q "^$user_to_delete:" "$USERS_FILE"; then
        read -rp "Are you sure you want to delete user '$user_to_delete'? (yes/no): " confirmation
        if [ "$confirmation" = "yes" ]; then
            sed -i "/^$user_to_delete:/d" "$USERS_FILE"
            echo "User '$user_to_delete' deleted successfully."
            log_access "$CURRENT_USER" "SUCCESS" "Delete User: $user_to_delete"
        else
            echo "User deletion cancelled."
            log_access "$CURRENT_USER" "INFO" "Delete User - Cancelled"
        fi
    else
        echo "Error: User '$user_to_delete' not found."
        log_access "$CURRENT_USER" "FAILURE" "Delete User - User Not Found"
    fi
}

# --- Main Script Logic ---

# Ensure the database directory and files exist with correct permissions
initialize_db

# Trap for unexpected exits to ensure cleanup
trap 'logout; exit' INT TERM EXIT # Ensures cleanup on Ctrl+C or script exit

# Attempt to log in
if login; then
    while true; do
        echo -e "\n--- Menu for $CURRENT_USER (Role: $CURRENT_USER_ROLE) ---"
        echo "1. View Database Content"
        echo "2. Edit Database Content (Admin Only)"
        echo "3. Change Password"
        if [ "$CURRENT_USER_ROLE" = "admin" ]; then
            echo "4. Add New User (Admin Only)"
            echo "5. Delete User (Admin Only)"
            echo "6. Logout"
        else
            echo "4. Logout"
        fi

        read -rp "Choose an option: " choice

        case "$choice" in
            1)
                view_database
                ;;
            2)
                edit_database
                ;;
            3)
                change_password
                ;;
            4)
                if [ "$CURRENT_USER_ROLE" = "admin" ]; then
                    add_user
                else
                    logout
                    break
                fi
                ;;
            5)
                if [ "$CURRENT_USER_ROLE" = "admin" ]; then
                    delete_user
                else
                    echo "Invalid option. Please try again."
                fi
                ;;
            6)
                if [ "$CURRENT_USER_ROLE" = "admin" ]; then
                    logout
                    break
                else
                    echo "Invalid option. Please try again."
                fi
                ;;
            *)
                echo "Invalid option. Please try again."
                ;;
        esac
    done
else
    echo "Authentication failed. Script terminated."
fi