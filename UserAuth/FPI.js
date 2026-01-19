const express = require('express');
const mysql = require('mysql2/promise'); // Using promise-based client for async/await
const bcrypt = require('bcryptjs'); // Library for hashing and comparing passwords
const nodemailer = require('nodemailer'); // Library for sending emails

const app = express();
const port = 3000;

// Middleware to parse JSON bodies
app.use(express.json());

// --- Database Connection Setup ---
// WARNING: Replace these placeholders with your actual MySQL credentials
const dbConfig = {
    host: 'Fuevo',
    user: 'root',
    password: 'Godsplan2',
    database: 'Fuevo.session.sql', // Make sure this database exists
};

let dbConnection;

/**
 * Initializes the database connection.
 */
async function initializeDB() {
    try {
        dbConnection = await mysql.createConnection(dbConfig);
        console.log('Successfully connected to MySQL database.');
    } catch (error) {
        console.error('Failed to connect to MySQL:', error.message);
        // Exit the process if we can't connect to the database
        process.exit(1);
    }
}

// --- Email Service Configuration (Nodemailer) ---
// IMPORTANT: Replace with your actual SMTP details (e.g., Gmail, SendGrid, etc.)
// If using Gmail, you must generate an App Password in your Google account settings.
const transporter = nodemailer.createTransport({
    service: 'gmail', // Example: Use 'gmail' or configure a custom SMTP host
    auth: {
        user: '2403291@students.kcau.ac.ke', // Your sending email address
        pass: 'Godsplan2.'  // Your email password or app key (REQUIRED)
    }
});

/**
 * Sends a notification email to the user upon successful login.
 * @param {string} userEmail The recipient's email address.
 * @param {string} username The recipient's username.
 */
async function sendLoginNotificationEmail(userEmail, username) {
    try {
        const info = await transporter.sendMail({
            from: '"Auth Server Notification" <your_email@gmail.com>', // Sender address
            to: userEmail, // List of receivers
            subject: "Successful Login Notification", // Subject line
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
                    <h2 style="color: #4CAF50;">Successful Login Detected</h2>
                    <p>Dear <strong>${username}</strong>,</p>
                    <p>This is an automated notification to confirm that your account 
                    (Email: <strong>${userEmail}</strong>) was successfully logged into just now.</p>
                    <p><strong>Login Time (Server Time):</strong> ${new Date().toLocaleString()}</p>
                    <p style="margin-top: 20px; color: #cc0000;">If this was not you, please take immediate action to secure your account or contact support.</p>
                </div>
            `, // html body
        });
        console.log("Login notification email sent to %s: %s", userEmail, info.messageId);
    } catch (error) {
        console.error("Failed to send login notification email to %s:", userEmail, error);
        // This is a non-critical failure, the user's login should still succeed.
    }
}


// --- API Endpoints ---

// 1. User Registration
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    // Basic input validation
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Missing username, email, or password.' });
    }

    try {
        // Step 1: Securely hash the password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        // Step 2: Insert the new user into the 'users' table
        const sql = 'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)';
        const [result] = await dbConnection.execute(sql, [username, email, passwordHash]);

        console.log(`User registered: ${username} (ID: ${result.insertId})`);
        res.status(201).json({ message: 'User registered successfully!', userId: result.insertId });

    } catch (error) {
        // Handle unique constraint violation (username or email already exists)
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Username or email already in use.' });
        }
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error during registration.' });
    }
});

// 2. User Login Authentication
app.post('/login', async (req, res) => {
    // We allow logging in with either username or email (the identifier)
    const { identifier, password } = req.body; 

    if (!identifier || !password) {
        return res.status(400).json({ message: 'Missing login identifier or password.' });
    }

    try {
        // Step 1: Fetch the user record. We now need the email for the notification.
        const sql = 'SELECT user_id, username, email, password_hash FROM users WHERE username = ? OR email = ?';
        const [rows] = await dbConnection.execute(sql, [identifier, identifier]);

        const user = rows[0];

        // Step 2: Check if the user exists
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Step 3: Compare the provided password with the stored hash
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            // Authentication successful!

            // Step 4: Send login notification email
            sendLoginNotificationEmail(user.email, user.username);
            
            // In a real application, you would generate a JWT here and send it back.
            res.status(200).json({ 
                message: 'Login successful!', 
                userId: user.user_id,
                username: user.username,
                token: 'YOUR_JWT_TOKEN_HERE' 
            });
        } else {
            // Password mismatch
            res.status(401).json({ message: 'Invalid credentials.' });
        }

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error during login.' });
    }
});


// Start the server after the database connection is established
async function startServer() {
    await initializeDB();
    app.listen(port, () => {
        console.log(`Authentication server running on http://localhost:${port}`);
        console.log('Ready to handle /register and /login requests.');
    });
}

startServer();
