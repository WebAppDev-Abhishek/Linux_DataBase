Secure Node.js TCP Database Server
This project demonstrates a foundational client-server database application implemented using Node.js.
It provides a basic framework for managing data and user accounts over a network connection,
focusing on core security concepts.

Key Features:

Node.js TCP Server: A custom server handles incoming client connections and processes commands.
User Authentication: Supports login with username and password.

Strong Password Hashing: Passwords are securely stored using PBKDF2/Scrypt with unique salts,
significantly enhancing protection against brute-force attacks.

Database Encryption: The database content is encrypted at rest using AES-256-CBC with
a server-side master key, ensuring data confidentiality on disk.

Role-Based Access Control: Differentiates between admin and user roles, restricting sensitive
operations (e.g., editing the database, user management) to administrators.

Basic Operations: Includes commands for viewing and editing database content, changing user
passwords, and managing user accounts.

Access Logging: Records connection events, login attempts, and user actions for auditing.
Critical Security Considerations
(DO NOT USE IN PRODUCTION):

No Network Encryption (TLS/SSL): Data transmitted between client and server is in plain text.
This is a major vulnerability for public networks.

Not Production Ready: Lacks robust error handling, advanced concurrency management, and comprehensive
security features required for sensitive data.

Educational Purpose: Intended solely as a demonstration of server-side logic, authentication,
and basic encryption principles.
