CREATE DATABASE IF NOT EXISTS chamsi_db;

-- 2. Use the database
USE chamsi_db;

-- 3. Drop tables for a clean rebuild
-- Order matters for foreign keys: drop messages first.
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS users;

-- 4. Create the USERS table (Authentication)
-- This table uses EMAIL for login and the character set is defined directly in the table definition.
CREATE TABLE users (
    user_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE COMMENT 'Primary login identifier.', 
    password_hash CHAR(60) NOT NULL COMMENT 'Stores the bcrypt password hash.',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Create the MESSAGES table (Chat History)
CREATE TABLE messages (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL, 
    role ENUM('user', 'ai') NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Define Foreign Key constraint
    CONSTRAINT fk_message_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Create Indexes (Using explicit syntax to avoid Error 1064)

-- Index on email for fast lookups during login
CREATE UNIQUE INDEX idx_email ON users (email);

-- Index on user_id for fast retrieval of chat history
CREATE INDEX idx_user_id ON messages (user_id);