const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const db = require('./db'); // MySQL connection
const { hashPassword, comparePassword } = require('./utils/password.js');// password utils
const isLoggedIn = require('./utils/auth.js'); // auth middleware

const app = express();

// Set view engine
app.set('view engine', 'ejs');

// Serve static files
app.use(express.static('public'));

// Parse URL-encoded bodies (form data)
app.use(bodyParser.urlencoded({ extended: true }));

// Setup session middleware
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false, // prevents deprecated warning
    cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

// Start server
app.listen(3000, () => {
    console.log("Server is running on port 3000");
});

// ===== ROUTES =====

// Root route -> render home page
app.get('/', (req, res) => {
    res.render('login'); 
});

// Signup page
app.get('/signup', (req, res) => {
    res.render('signup.ejs');
});

// Handle signup form submission
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const hashed = await hashPassword(password);

        db.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [username, email, hashed],
            (err) => {
                if (err) {
                    console.error("DB Insert Error:", err);
                    return res.status(500).send("Database error");
                }

                // Redirect to login after successful signup
                res.redirect('/login');
            }
        );
    } catch (err) {
        console.error("Hashing error:", err);
        res.status(500).send("Error hashing password");
    }
});


// Login page
app.get('/login', (req, res) => {
    res.render('login.ejs');
});

// Handle login form submission
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
        if (err) {
            console.error(err);
            return res.send("Database error!");
        }
        if (result.length === 0) {
            console.log("User not found:", email);
            return res.send("User not found!");
        }

        const hashedPassword = result[0].password;

        comparePassword(password, hashedPassword)
            .then(match => {
                if (!match) {
                    console.log("Incorrect password:", email);
                    return res.send("Incorrect password");
                }

                req.session.user = result[0].name;
                res.redirect('/dashboard'); // ✅ Response sent
            })
            .catch(err => {
                console.error("Password compare error:", err);
                res.send("Server error during login"); // ✅ Response sent
            });
    });
});

// Dashboard route (protected)
app.get('/dashboard', isLoggedIn, (req, res) => {
    res.render('dashboard', { user: req.session.user });
});


// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});
