const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const helmet = require("helmet");
const sanitizeHtml = require("sanitize-html");
const rateLimit = require("express-rate-limit");

const PORT = process.env.PORT || 8080;
const app = express();

// Use Helmet for secure HTTP headers
app.use(helmet());

// Configure CORS
app.use(cors({
    origin: "*",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"]
}));

// Rate limiter for express endpoints (e.g., /rooms endpoint)
const roomsLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100,
    message: "Too many requests, please try again later."
});
app.use('/rooms', roomsLimiter);

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// In-memory storage
let messages = []; // Global chat messages (each with a room property)
let rooms = {};    // Format: { roomName: { password: string, public: boolean, users: { socketId: username } } }
let voiceRooms = {}; // Format: { roomName: { [socket.id]: username } }

// Reserved usernames to prevent fake names
const reservedUsernames = ["Server", "Admin", "Moderator"];

// Prepopulate public rooms if they don't exist
const prepopulatedRooms = ["General", "Token Discussion", "Off-Topic", "Announcements"];
prepopulatedRooms.forEach(roomName => {
  if (!rooms[roomName]) {
    rooms[roomName] = {
      password: "",
      public: true,
      users: {}
    };
    console.log(`📂 Prepopulated public room: ${roomName}`);
  }
});

// Endpoint to return public rooms
app.get('/rooms', (req, res) => {
    let publicRooms = [];
    for (let room in rooms) {
        if (rooms[room].public) {
            publicRooms.push({
                room,
                users: Object.keys(rooms[room].users).length
            });
        }
    }
    res.json(publicRooms);
});

// In-memory IP ban list
const bannedIPs = new Set();

// Rate limiter for socket "sendMessage" events per socket
const messageRateLimiters = {}; // { socketId: { count: number, lastReset: timestamp } }
const MESSAGE_LIMIT = 5; // max messages
const MESSAGE_WINDOW = 10 * 1000; // per 10 seconds

// Removed JWT middleware - now directly handling connections

io.on("connection", (socket) => {
    // Check IP ban
    const userIP = socket.handshake.address;
    if (bannedIPs.has(userIP)) {
        socket.disconnect();
        console.log(`❌ Connection from banned IP: ${userIP}`);
        return;
    }
    console.log(`🔗 New Connection: ${socket.id} from IP: ${userIP}`);

    // Create a new room
    socket.on("createRoom", (data) => {
        // Data: { room: string, password: string, username: string }
        if (!data || !data.room || !data.username) {
            socket.emit("errorMessage", "Invalid room creation data.");
            return;
        }
        const roomName = data.room;
        const password = data.password || "";
        const username = data.username.trim();

        // Block reserved usernames
        if (reservedUsernames.includes(username)) {
            socket.emit("errorMessage", "Username is reserved.");
            return;
        }
        
        if (rooms[roomName]) {
            socket.emit("errorMessage", "Room already exists.");
            return;
        }
        
        // Create room. No password means public.
        rooms[roomName] = { 
            password: password, 
            public: (password === ""), 
            users: {} 
        };
        socket.join(roomName);
        rooms[roomName].users[socket.id] = username;
        socket.emit("roomCreated", { room: roomName, username });
        console.log(`📂 Room created: ${roomName} by ${username}`);
    });
    
    // Join an existing room
    socket.on("joinRoom", (data) => {
        // Data: { room: string, password: string, username: string }
        if (!data || !data.room || !data.username) {
            socket.emit("errorMessage", "Invalid join room data.");
            return;
        }
        const roomName = data.room;
        const password = data.password || "";
        const username = data.username.trim();

        // Block reserved usernames
        if (reservedUsernames.includes(username)) {
            socket.emit("errorMessage", "Username is reserved.");
            return;
        }
        
        if (!rooms[roomName]) {
            socket.emit("errorMessage", "Room does not exist.");
            return;
        }
        
        // Validate password if needed
        if (rooms[roomName].password && rooms[roomName].password !== password) {
            socket.emit("errorMessage", "Incorrect password.");
            return;
        }
        
        socket.join(roomName);
        rooms[roomName].users[socket.id] = username;
        socket.emit("roomJoined", { room: roomName, username });
        
        // Send chat history for this room
        const roomMessages = messages.filter(m => m.room === roomName);
        socket.emit("chatHistory", roomMessages);
        
        // Notify others in the room about the new user
        socket.to(roomName).emit("receiveMessage", { room: roomName, user: "Server", text: `${username} joined the room.` });
        console.log(`📥 ${username} joined room: ${roomName}`);
    });
    
    // Handle sending messages with rate limiting and sanitization
    socket.on("sendMessage", (data) => {
        // Data: { room: string, user: string, text: string }
        if (!data || !data.room || !data.user || !data.text) {
            socket.emit("errorMessage", "Invalid message data.");
            return;
        }
        
        // Apply rate limiting per socket
        const now = Date.now();
        if (!messageRateLimiters[socket.id]) {
            messageRateLimiters[socket.id] = { count: 0, lastReset: now };
        }
        const limiter = messageRateLimiters[socket.id];
        if (now - limiter.lastReset > MESSAGE_WINDOW) {
            limiter.count = 0;
            limiter.lastReset = now;
        }
        if (limiter.count >= MESSAGE_LIMIT) {
            socket.emit("errorMessage", "Rate limit exceeded. Please wait before sending more messages.");
            return;
        }
        limiter.count++;
        
        // Sanitize message to prevent XSS attacks
        const sanitizedText = sanitizeHtml(data.text, {
            allowedTags: [],
            allowedAttributes: {}
        });
        data.text = sanitizedText;
        
        // Store message and enforce a maximum of 500 messages per room
        messages.push(data);
        const roomMessages = messages.filter(m => m.room === data.room);
        if (roomMessages.length > 500) {
            const excessCount = roomMessages.length - 500;
            let removed = 0;
            messages = messages.filter(m => {
                if (m.room === data.room && removed < excessCount) {
                    removed++;
                    return false;
                }
                return true;
            });
        }
        
        io.to(data.room).emit("receiveMessage", data);
        console.log(`💬 Message in ${data.room}: ${data.user}: ${data.text}`);
    });
    
    // Voice Chat events using WebRTC signaling
    socket.on("joinVoice", (data) => {
        // Data: { room: string, username: string }
        if (!data || !data.room || !data.username) {
            socket.emit("errorMessage", "Invalid voice join data.");
            return;
        }
        const roomName = data.room;
        const username = data.username.trim();
        
        // Block reserved usernames
        if (reservedUsernames.includes(username)) {
            socket.emit("errorMessage", "Username is reserved.");
            return;
        }
        
        if (!voiceRooms[roomName]) {
            voiceRooms[roomName] = {};
        }
        voiceRooms[roomName][socket.id] = username;
        // Use a separate room for voice connections
        socket.join(roomName + "_voice");
        socket.emit("voiceConnected");
        socket.to(roomName + "_voice").emit("voiceNewPeer", { peerId: socket.id, username });
        console.log(`🎙️ ${username} joined voice room: ${roomName}`);
    });
    
    socket.on("voiceOffer", (data) => {
        // Data: { offer, to, room: string, username: string }
        if (data && data.to) {
            io.to(data.to).emit("voiceOffer", { from: socket.id, offer: data.offer, username: data.username, room: data.room });
        }
    });
    
    socket.on("voiceAnswer", (data) => {
        // Data: { answer, to, room: string }
        if (data && data.to) {
            io.to(data.to).emit("voiceAnswer", { from: socket.id, answer: data.answer, room: data.room });
        }
    });
    
    socket.on("voiceCandidate", (data) => {
        // Data: { candidate, to, room: string }
        if (data && data.to) {
            io.to(data.to).emit("voiceCandidate", { from: socket.id, candidate: data.candidate, room: data.room });
        }
    });
    
    socket.on("leaveVoice", (data) => {
        // Data: { room: string, username: string }
        if (!data || !data.room || !data.username) {
            socket.emit("errorMessage", "Invalid voice leave data.");
            return;
        }
        const roomName = data.room;
        if (voiceRooms[roomName]) {
            delete voiceRooms[roomName][socket.id];
            socket.leave(roomName + "_voice");
            socket.to(roomName + "_voice").emit("receiveMessage", { room: roomName, user: "Server", text: `${data.username} left the voice chat.` });
            console.log(`🎙️ ${data.username} left voice room: ${roomName}`);
        }
    });
    
    // Clean up on disconnect
    socket.on("disconnect", () => {
        console.log(`❌ User Disconnected: ${socket.id}`);
        // Remove rate limiter data
        delete messageRateLimiters[socket.id];
        // Remove user from text rooms
        for (let room in rooms) {
            if (rooms[room].users[socket.id]) {
                const username = rooms[room].users[socket.id];
                delete rooms[room].users[socket.id];
                socket.to(room).emit("receiveMessage", { room, user: "Server", text: `${username} left the room.` });
                // Optionally delete room if empty and not prepopulated
                if (Object.keys(rooms[room].users).length === 0 && !prepopulatedRooms.includes(room)) {
                    delete rooms[room];
                    console.log(`🗑️ Room deleted: ${room}`);
                }
            }
        }
        // Remove user from voice rooms
        for (let room in voiceRooms) {
            if (voiceRooms[room][socket.id]) {
                delete voiceRooms[room][socket.id];
                socket.to(room + "_voice").emit("receiveMessage", { room, user: "Server", text: `A user left the voice chat.` });
                if (Object.keys(voiceRooms[room]).length === 0) {
                    delete voiceRooms[room];
                }
            }
        }
    });
});

server.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
