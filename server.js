const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);

// Trust proxy configuration
app.set('trust proxy', 1);

// Add JSON parsing middleware
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Apply rate limiting to all requests
app.use(limiter);

// CORS configuration
const corsOptions = {
  origin: [
    'https://blockfly.netlify.app',
    'https://blockfly.rn601878.repl.co',
    'http://localhost:5500', // Allow local dev
    'http://127.0.0.1:5500', // Allow local dev
    'http://localhost:3000', // Allow local dev (if running frontend on 3000)
    'http://127.0.0.1:3000',  // Allow local dev (if running frontend on 3000)
    '*' // Allow all origins for development
  ],
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.use(express.static('public')); // Serve your Babylon game from /public

const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
    credentials: true
  },
  transports: ['websocket', 'polling']
});

// Store connected users and messages
const connectedUsers = new Map();

// Leaderboard persistence
const LEADERBOARD_FILE = path.join(__dirname, 'leaderboard.json');
let leaderboard = []; // [{ username, score }]

// Load leaderboard from file
if (fs.existsSync(LEADERBOARD_FILE)) {
    try {
        leaderboard = JSON.parse(fs.readFileSync(LEADERBOARD_FILE, 'utf8'));
        console.log('Loaded leaderboard:', leaderboard);
    } catch (e) {
        console.error('Error loading leaderboard:', e);
        leaderboard = [];
    }
}

// Save leaderboard to file
function saveLeaderboard() {
    try {
        fs.writeFileSync(LEADERBOARD_FILE, JSON.stringify(leaderboard, null, 2));
        console.log('Saved leaderboard');
    } catch (error) {
        console.error('Error saving leaderboard:', error);
    }
}

// User storage file path
const USERS_FILE = path.join(__dirname, 'users.json');

// Chat persistence
const CHAT_FILE = path.join(__dirname, 'chat.json');
let messages = [];
// Load chat history
if (fs.existsSync(CHAT_FILE)) {
    try {
        messages = JSON.parse(fs.readFileSync(CHAT_FILE, 'utf8'));
    } catch (e) {
        messages = [];
    }
}
function saveChat() {
    fs.writeFileSync(CHAT_FILE, JSON.stringify(messages.slice(-100), null, 2));
}

// Initialize users file if it doesn't exist
if (!fs.existsSync(USERS_FILE)) {
    console.log('Creating new users.json file');
    fs.writeFileSync(USERS_FILE, JSON.stringify({}, null, 2));
}

// Load users from file or create empty users object
let users = {};
try {
    users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    console.log('Loaded users:', Object.keys(users));
} catch (error) {
    console.error('Error loading users:', error);
    users = {};
}

// Save users to file
function saveUsers() {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        console.log('Saved users:', Object.keys(users));
    } catch (error) {
        console.error('Error saving users:', error);
    }
}

// Register endpoint (with password hashing and JWT)
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    if (users[username]) {
        return res.status(400).json({ error: 'Username already exists' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        users[username] = { 
            password: hashedPassword,
            badges: [], // Initialize empty badges array
            role: username === 'admin' ? 'admin' : 'user', // Set role based on username
            bannedFromChat: false, // Initialize ban fields
            bannedFromSite: false
        };
        saveUsers();
        // Issue JWT token
        const token = jwt.sign({ username }, process.env.JWT_SECRET || 'supersecretkey', { expiresIn: '7d' });
        res.json({ message: 'Registration successful', token, username });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login endpoint (with JWT)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users[username];
    if (!user) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    if (user.bannedFromSite) {
        return res.status(403).json({ error: 'You are banned from the site.' });
    }
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    // Issue JWT token
    const token = jwt.sign({ username }, process.env.JWT_SECRET || 'supersecretkey', { expiresIn: '7d' });
    res.json({ message: 'Login successful', token, username });
});

// Auth middleware
function authMiddleware(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid token' });
    }
    try {
        const payload = jwt.verify(auth.slice(7), process.env.JWT_SECRET || 'supersecretkey');
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// Get current user info
app.get('/api/me', authMiddleware, (req, res) => {
    res.json({ username: req.user.username });
});

// Admin-only endpoint to list all users
app.get('/api/users', authMiddleware, (req, res) => {
    const user = users[req.user.username];
    if (!user || user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    // Return a list of usernames (not passwords)
    res.json({ users: Object.keys(users) });
});

// Admin endpoint to give badge to user
app.post('/api/give-badge', authMiddleware, async (req, res) => {
    const user = users[req.user.username];
    if (!user || user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const { targetUsername } = req.body;
    if (!targetUsername || !users[targetUsername]) {
        return res.status(400).json({ error: 'Invalid username' });
    }

    // Add trophy badge if it doesn't exist
    if (!users[targetUsername].badges.includes('trophy')) {
        users[targetUsername].badges.push('trophy');
        saveUsers();
        res.json({ message: 'Badge given successfully', badges: users[targetUsername].badges });
    } else {
        res.status(400).json({ error: 'User already has this badge' });
    }
});

// Add badge endpoint
app.post('/api/add-badge', authMiddleware, async (req, res) => {
    const { username, badge } = req.body;
    if (!username || !badge) {
        return res.status(400).json({ error: 'Username and badge are required' });
    }

    // Only admin can add badges
    const requestingUser = users[req.user.username];
    if (!requestingUser || requestingUser.role !== 'admin') {
        return res.status(403).json({ error: 'Only admin can add badges' });
    }

    // Check if user exists
    if (!users[username]) {
        return res.status(404).json({ error: 'User not found' });
    }

    // Initialize badges array if it doesn't exist
    if (!users[username].badges) {
        users[username].badges = [];
    }

    // Add badge if it doesn't exist
    if (!users[username].badges.includes(badge)) {
        users[username].badges.push(badge);
        saveUsers();
        res.json({ message: 'Badge added successfully', badges: users[username].badges });
    } else {
        res.status(400).json({ error: 'User already has this badge' });
    }
});

// Admin endpoint to ban from chat
app.post('/api/ban-from-chat', authMiddleware, (req, res) => {
    const admin = users[req.user.username];
    if (!admin || admin.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const { targetUsername, ban } = req.body;
    if (!targetUsername || !users[targetUsername]) {
        return res.status(400).json({ error: 'Invalid username' });
    }
    users[targetUsername].bannedFromChat = !!ban;
    saveUsers();
    res.json({ message: `User ${ban ? 'banned' : 'unbanned'} from chat successfully.` });
});

// Admin endpoint to ban from site
app.post('/api/ban-from-site', authMiddleware, (req, res) => {
    const admin = users[req.user.username];
    if (!admin || admin.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const { targetUsername, ban } = req.body;
    if (!targetUsername || !users[targetUsername]) {
        return res.status(400).json({ error: 'Invalid username' });
    }
    users[targetUsername].bannedFromSite = !!ban;
    saveUsers();
    // Emit force_logout to all sockets for this user if banning
    if (ban) {
        for (const [socketId, userObj] of connectedUsers.entries()) {
            if (userObj.username === targetUsername) {
                const sock = io.sockets.sockets.get(socketId);
                if (sock) sock.emit('force_logout');
            }
        }
    }
    res.json({ message: `User ${ban ? 'banned' : 'unbanned'} from site successfully.` });
});

// Admin-only endpoint to get all users' ban status
app.get('/api/user-info', authMiddleware, (req, res) => {
    const user = users[req.user.username];
    if (!user || user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    // Return a list of users with ban status and badges
    const userInfo = Object.entries(users).map(([username, u]) => ({
        username,
        bannedFromChat: !!u.bannedFromChat,
        bannedFromSite: !!u.bannedFromSite,
        badges: u.badges || []
    }));
    res.json({ users: userInfo });
});

// Admin-only endpoint to revoke a badge from a user
app.post('/api/revoke-badge', authMiddleware, (req, res) => {
    const admin = users[req.user.username];
    if (!admin || admin.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const { username, badge } = req.body;
    if (!username || !badge || !users[username]) {
        return res.status(400).json({ error: 'Invalid username or badge' });
    }
    users[username].badges = (users[username].badges || []).filter(b => b !== badge);
    saveUsers();
    res.json({ message: 'Badge revoked successfully', badges: users[username].badges });
});

// Admin endpoint to get game statistics
app.get('/api/admin/stats', authMiddleware, (req, res) => {
    const user = users[req.user.username];
    if (!user || user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    // Calculate statistics
    const totalUsers = Object.keys(users).length;
    const activeUsers = Object.values(users).filter(u => u.lastActive > Date.now() - 24 * 60 * 60 * 1000).length;
    const bannedUsers = Object.values(users).filter(u => u.bannedFromSite).length;
    const totalBadges = Object.values(users).reduce((acc, u) => acc + (u.badges?.length || 0), 0);
    const averageScore = Object.values(users).reduce((acc, u) => acc + (u.highScore || 0), 0) / totalUsers;

    res.json({
        totalUsers,
        activeUsers,
        bannedUsers,
        totalBadges,
        averageScore: Math.round(averageScore)
    });
});

// Admin endpoint to reset a user's high score
app.post('/api/admin/reset-score', authMiddleware, (req, res) => {
    const user = users[req.user.username];
    if (!user || user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const { targetUsername } = req.body;
    if (!targetUsername || !users[targetUsername]) {
        return res.status(400).json({ error: 'Invalid username' });
    }

    users[targetUsername].highScore = 0;
    saveUsers();
    res.json({ message: 'High score reset successfully' });
});

// Admin endpoint to give special badge
app.post('/api/admin/give-special-badge', authMiddleware, (req, res) => {
    const user = users[req.user.username];
    if (!user || user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const { targetUsername, badgeType } = req.body;
    const validBadges = ['trophy.png', 'star.png', 'diamond.png', 'crown.png'];

    if (!targetUsername || !users[targetUsername]) {
        return res.status(400).json({ error: 'Invalid username' });
    }
    if (!validBadges.includes(badgeType)) {
        return res.status(400).json({ error: 'Invalid badge type' });
    }

    if (!users[targetUsername].badges.includes(badgeType)) {
        users[targetUsername].badges.push(badgeType);
        saveUsers();
        res.json({ message: 'Special badge given successfully', badges: users[targetUsername].badges });
    } else {
        res.status(400).json({ error: 'User already has this badge' });
    }
});

// Helper function to validate messages
const validateMessage = (message) => {
  if (!message || typeof message !== 'string') return false;
  if (message.length > 500) return false; // Max message length
  return true;
};

io.on('connection', (socket) => {
  console.log('A user connected');

  // Send initial data to the new connection
  socket.emit('initial_data', {
    messages: messages.map(msg => ({
      ...msg,
      badges: users[msg.username]?.badges || []
    })),
    users: Array.from(connectedUsers.values())
  });

  // Handle user joining
  socket.on('user_join', (username) => {
    console.log('User join event:', username); // Debug log
    if (!username || typeof username !== 'string' || username.length > 20) {
      socket.emit('error', 'Invalid username');
      return;
    }
    // Check if user is banned from chat
    if (users[username] && users[username].bannedFromChat) {
      socket.emit('error', 'You are banned from chat.');
      return;
    }
    connectedUsers.set(socket.id, {
      id: socket.id,
      username: username,
      joinTime: Date.now()
    });
    // Send updated user list to all clients
    io.emit('user_list', Array.from(connectedUsers.values()));
    // Send system message about user joining
    io.emit('system_message', `${username} has joined the chat`);
    console.log('User joined:', username, 'Total users:', connectedUsers.size);
  });

  // Handle chat messages
  socket.on('chat message', (msg) => {
    console.log('Received chat message:', msg); // Debug log
    const user = connectedUsers.get(socket.id);
    if (!user) {
      socket.emit('error', 'You must join the chat first');
      return;
    }
    // Check if user is banned from chat
    if (users[user.username] && users[user.username].bannedFromChat) {
      socket.emit('error', 'You are banned from chat.');
      return;
    }
    if (!validateMessage(msg)) {
      socket.emit('error', 'Invalid message');
      return;
    }
    const message = {
      id: Date.now(),
      userId: user.id,
      username: user.username,
      content: msg,
      timestamp: Date.now(),
      badges: users[user.username]?.badges || [],
      role: users[user.username]?.role || 'user'
    };
    messages.push(message);
    if (messages.length > 100) messages.shift(); // Keep last 100 messages
    saveChat();
    // Broadcast the message to all clients
    io.emit('chat message', message);
    console.log('Broadcasted message:', message);
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    const user = connectedUsers.get(socket.id);
    if (user) {
      connectedUsers.delete(socket.id);
      io.emit('system_message', `${user.username} has left the chat`);
      io.emit('user_list', Array.from(connectedUsers.values()));
      console.log('User disconnected:', user.username, 'Total users:', connectedUsers.size);
    }
  });

  // Handle score submission
  socket.on('submit_score', (score) => {
    score = Number(score); // Ensure score is a number
    const user = connectedUsers.get(socket.id);
    console.log('Score submission details:', {
        username: user?.username,
        newScore: score,
        currentLeaderboard: leaderboard,
        userExists: user ? 'yes' : 'no'
    });

    if (!user) {
        console.log('No user found for socket.id:', socket.id);
        return;
    }

    // Add or update user's score
    const existing = leaderboard.find(entry => entry.username === user.username);
    console.log('Existing entry found:', existing);

    if (existing) {
        console.log('Previous score:', existing.score, 'New score:', score);
        if (score > existing.score) {
            console.log('Updating score from', existing.score, 'to', score);
            existing.score = score;
        } else {
            console.log('New score not higher than existing score');
        }
    } else {
        console.log('Adding new entry for user:', user.username, 'with score:', score);
        leaderboard.push({ username: user.username, score });
    }

    // Sort leaderboard
    leaderboard.sort((a, b) => b.score - a.score);
    console.log('Sorted leaderboard:', leaderboard);

    // Save leaderboard to file
    saveLeaderboard();

    // Broadcast updated leaderboard (top 10)
    console.log('Broadcasting leaderboard:', leaderboard.slice(0, 10));
    io.emit('leaderboard', leaderboard.slice(0, 10));
    socket.emit('submit_score', score);
  });

  // Send leaderboard to new connections
  socket.emit('leaderboard', leaderboard.slice(0, 10));

  // Listen for leaderboard updates
  socket.on('leaderboard', (data) => {
    // data is an array of { username, score }
    // Update your leaderboard UI here
    console.log('Leaderboard:', data);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});