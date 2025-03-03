// Add these dependencies to your package.json
// npm install rate-limiter-flexible sanitize-html ipaddr.js

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { RateLimiterMemory } = require("rate-limiter-flexible");
const sanitizeHtml = require("sanitize-html");
const ipaddr = require("ipaddr.js");

const PORT = process.env.PORT || 8080;
const app = express();

app.use(
    cors({
        origin: "*",
        methods: ["GET", "POST"],
        allowedHeaders: ["Content-Type", "Admin-Token"],
    })
);

// Add body parser for admin API routes
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"],
    },
});

// In-memory storage for messages and rooms
let messages = []; // Global chat messages (each with a room property)
let rooms = {}; // Format: { roomName: { password: string, public: boolean, users: { socketId: username } } }
let voiceRooms = {}; // Format: { roomName: { [socket.id]: username } }

// === AUTOMOD SYSTEM ===
// In-memory ban storage
let bannedIPs = new Set();
let userWarnings = {}; // Track warnings before banning: { socketId: count }
let userMessageTimestamps = {}; // For tracking message frequency: { socketId: [timestamps] }
let ipSocketMap = {}; // Map IP addresses to socket IDs: { ip: [socketIds] }
let recentMessagesByUser = {}; // Track recent messages by user for spam detection

// Configure rate limiters
const messageLimiter = new RateLimiterMemory({
    points: 5, // 5 messages
    duration: 5, // per 5 seconds
    blockDuration: 10, // Block for 10 seconds if exceeded
});

const roomJoinLimiter = new RateLimiterMemory({
    points: 5, // 5 room joins
    duration: 30, // per 30 seconds
    blockDuration: 60, // Block for 1 minute if exceeded
});

// Automod configuration
const automodConfig = {
    maxMessageLength: 1000, // Characters
    minMessageInterval: 300, // Milliseconds
    maxDuplicateMessages: 3, // Number of repeats allowed
    maxWarningsBeforeBan: 5,
    messageHistorySize: 10, // Number of messages to keep for spam detection
    patternRules: [
        // Solana address pattern (base58 encoding, typically 40+ chars)
        { 
            pattern: /[1-9A-HJ-NP-Za-km-z]{40,}/g, 
            action: "warn", 
            reason: "possible contract address" 
        },
        // Too many consecutive characters (message flooding)
        { 
            pattern: /(.)\1{20,}/g, 
            action: "warn", 
            reason: "character flooding detected" 
        },
        // Basic XSS patterns
        { 
            pattern: /<script[\s\S]*?>[\s\S]*?<\/script>/gi, 
            action: "block", 
            reason: "potentially harmful content detected" 
        },
        { 
            pattern: /javascript:/gi, 
            action: "block", 
            reason: "potentially harmful content detected" 
        },
        { 
            pattern: /on\w+\s*=/gi, 
            action: "block", 
            reason: "potentially harmful content detected" 
        },
        // Link spam (allow some links but warn on excessive)
        { 
            pattern: /(https?:\/\/[^\s]+)/g, 
            action: "checkCount", 
            threshold: 3,
            reason: "too many links" 
        },
    ]
};

// Function to extract client IP address
function getClientIP(socket) {
    let ip = socket.handshake.headers["x-forwarded-for"] || 
             socket.handshake.address || 
             socket.conn.remoteAddress;
    
    // Handle IPv6 format if necessary
    if (ip.includes("::ffff:")) {
        ip = ip.split("::ffff:")[1];
    }
    
    return ip;
}

// Function to check if a message contains patterns that should be moderated
function checkMessageContent(message) {
    const result = {
        allowed: true,
        action: "allow",
        reason: "",
    };

    if (!message || typeof message !== "string") {
        return result;
    }

    // Check message length
    if (message.length > automodConfig.maxMessageLength) {
        result.allowed = false;
        result.action = "block";
        result.reason = "Message exceeds maximum length";
        return result;
    }

    // Check against pattern rules
    for (const rule of automodConfig.patternRules) {
        const matches = message.match(rule.pattern);
        
        if (matches && matches.length > 0) {
            if (rule.action === "block") {
                result.allowed = false;
                result.action = "block";
                result.reason = rule.reason;
                return result;
            } else if (rule.action === "warn") {
                result.action = "warn";
                result.reason = rule.reason;
            } else if (rule.action === "checkCount" && matches.length >= rule.threshold) {
                result.action = "warn";
                result.reason = rule.reason;
            }
        }
    }

    return result;
}

// Function to check for spam (duplicate messages, frequency)
function checkForSpam(socketId, username, text, room) {
    const result = {
        allowed: true,
        action: "allow",
        reason: "",
    };

    const now = Date.now();
    
    // Initialize user message history if not exists
    if (!userMessageTimestamps[socketId]) {
        userMessageTimestamps[socketId] = [];
    }
    
    if (!recentMessagesByUser[username]) {
        recentMessagesByUser[username] = [];
    }
    
    // Check message frequency
    if (userMessageTimestamps[socketId].length > 0) {
        const lastMessageTime = userMessageTimestamps[socketId][userMessageTimestamps[socketId].length - 1];
        if (now - lastMessageTime < automodConfig.minMessageInterval) {
            result.allowed = false;
            result.action = "block";
            result.reason = "Sending messages too quickly";
            return result;
        }
    }
    
    // Add current timestamp
    userMessageTimestamps[socketId].push(now);
    
    // Keep only the most recent timestamps
    if (userMessageTimestamps[socketId].length > automodConfig.messageHistorySize) {
        userMessageTimestamps[socketId] = userMessageTimestamps[socketId].slice(-automodConfig.messageHistorySize);
    }
    
    // Check for repeated messages by this user
    const userRecentMessages = recentMessagesByUser[username];
    const duplicateCount = userRecentMessages.filter(msg => 
        msg.text === text && msg.room === room
    ).length;
    
    if (duplicateCount >= automodConfig.maxDuplicateMessages - 1) {
        result.allowed = false;
        result.action = "warn";
        result.reason = "Duplicate message spam detected";
    }
    
    // Add current message to history
    userRecentMessages.push({ text, room, timestamp: now });
    
    // Keep only recent messages
    if (userRecentMessages.length > automodConfig.messageHistorySize) {
        recentMessagesByUser[username] = userRecentMessages.slice(-automodConfig.messageHistorySize);
    }
    
    return result;
}

// Function to sanitize message content (prevent XSS)
function sanitizeMessage(text) {
    return sanitizeHtml(text, {
        allowedTags: [], // No HTML tags allowed
        allowedAttributes: {}, // No attributes allowed
        disallowedTagsMode: 'recursiveEscape'
    });
}

// Function to issue a warning to a user
function warnUser(socket, reason) {
    if (!userWarnings[socket.id]) {
        userWarnings[socket.id] = 0;
    }
    
    userWarnings[socket.id]++;
    
    socket.emit("modWarning", {
        reason,
        warningCount: userWarnings[socket.id],
        maxWarnings: automodConfig.maxWarningsBeforeBan
    });
    
    console.log(`⚠️ Warning issued to ${socket.id}: ${reason} (${userWarnings[socket.id]}/${automodConfig.maxWarningsBeforeBan})`);
    
    // If user reached max warnings, ban them
    if (userWarnings[socket.id] >= automodConfig.maxWarningsBeforeBan) {
        banUser(socket);
    }
}

// Function to ban a user
function banUser(socket) {
    const ip = getClientIP(socket);
    
    bannedIPs.add(ip);
    
    // Find all sockets from this IP
    if (ipSocketMap[ip]) {
        ipSocketMap[ip].forEach(socketId => {
            const targetSocket = io.sockets.sockets.get(socketId);
            if (targetSocket) {
                targetSocket.emit("banned", { 
                    reason: "You have been banned for violating the chat rules" 
                });
                targetSocket.disconnect(true);
            }
        });
    }
    
    console.log(`🚫 Banned IP: ${ip}`);
}

// Clear old data periodically to prevent memory leaks
setInterval(() => {
    const now = Date.now();
    const timeoutThreshold = 3600000; // 1 hour
    
    // Clean up message timestamps
    for (const socketId in userMessageTimestamps) {
        userMessageTimestamps[socketId] = userMessageTimestamps[socketId].filter(
            timestamp => now - timestamp < timeoutThreshold
        );
        if (userMessageTimestamps[socketId].length === 0) {
            delete userMessageTimestamps[socketId];
        }
    }
    
    // Clean up user message history
    for (const username in recentMessagesByUser) {
        recentMessagesByUser[username] = recentMessagesByUser[username].filter(
            msg => now - msg.timestamp < timeoutThreshold
        );
        if (recentMessagesByUser[username].length === 0) {
            delete recentMessagesByUser[username];
        }
    }
}, 3600000); // Run every hour

const prepopulatedRooms = ["General", "Token Discussion", "Off-Topic", "Announcements"];
prepopulatedRooms.forEach((roomName) => {
    if (!rooms[roomName]) {
        rooms[roomName] = {
            password: "",
            public: true,
            users: {},
        };
        console.log(`📂 Prepopulated public room: ${roomName}`);
    }
});

// === REST API ROUTES ===

app.get("/rooms", (req, res) => {
    let publicRooms = [];
    for (let room in rooms) {
        if (rooms[room].public) {
            publicRooms.push({
                room,
                users: Object.keys(rooms[room].users).length,
            });
        }
    }
    res.json(publicRooms);
});

// Admin routes for moderation
app.get("/admin/banned", (req, res) => {
    // In production, you should add proper auth middleware here
    const adminToken = req.headers['admin-token'];
    if (adminToken !== process.env.ADMIN_TOKEN) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    
    res.json({
        bannedIPs: Array.from(bannedIPs),
        count: bannedIPs.size
    });
});

app.post("/admin/ban", (req, res) => {
    // In production, you should add proper auth middleware here
    const adminToken = req.headers['admin-token'];
    if (adminToken !== process.env.ADMIN_TOKEN) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    
    const { ip } = req.body;
    if (!ip) {
        return res.status(400).json({ error: "IP address required" });
    }
    
    bannedIPs.add(ip);
    
    // Disconnect all sockets from this IP
    if (ipSocketMap[ip]) {
        ipSocketMap[ip].forEach(socketId => {
            const targetSocket = io.sockets.sockets.get(socketId);
            if (targetSocket) {
                targetSocket.emit("banned", { 
                    reason: "You have been banned by an administrator" 
                });
                targetSocket.disconnect(true);
            }
        });
    }
    
    res.json({ success: true, message: `IP ${ip} banned successfully` });
});

app.post("/admin/unban", (req, res) => {
    // In production, you should add proper auth middleware here
    const adminToken = req.headers['admin-token'];
    if (adminToken !== process.env.ADMIN_TOKEN) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    
    const { ip } = req.body;
    if (!ip) {
        return res.status(400).json({ error: "IP address required" });
    }
    
    if (bannedIPs.has(ip)) {
        bannedIPs.delete(ip);
        res.json({ success: true, message: `IP ${ip} unbanned successfully` });
    } else {
        res.status(404).json({ error: "IP not found in ban list" });
    }
});

// === SOCKET.IO CONNECTION HANDLING ===

io.on("connection", (socket) => {
    const ip = getClientIP(socket);
    
    // Check if IP is banned
    if (bannedIPs.has(ip)) {
        socket.emit("banned", { reason: "Your IP address has been banned from this chat" });
        socket.disconnect(true);
        return;
    }
    
    // Track IP to socket mapping for ban management
    if (!ipSocketMap[ip]) {
        ipSocketMap[ip] = [];
    }
    ipSocketMap[ip].push(socket.id);
    
    console.log(`🔗 New Connection: ${socket.id} from IP: ${ip}`);

    socket.on("createRoom", async (data) => {
        // Apply rate limiting for room creation
        try {
            await roomJoinLimiter.consume(socket.id);
        } catch (rejRes) {
            socket.emit("errorMessage", "You're creating rooms too quickly. Please try again later.");
            return;
        }
        
        const { room: roomName, password = "", username } = data;
        
        // Sanitize room name and username
        const sanitizedRoomName = sanitizeMessage(roomName).trim();
        const sanitizedUsername = sanitizeMessage(username).trim();
        
        if (!sanitizedRoomName || !sanitizedUsername) {
            socket.emit("errorMessage", "Invalid room name or username");
            return;
        }
        
        if (rooms[sanitizedRoomName]) {
            socket.emit("errorMessage", "Room already exists.");
            return;
        }
        
        rooms[sanitizedRoomName] = {
            password,
            public: password === "",
            users: {},
        };
        
        socket.join(sanitizedRoomName);
        rooms[sanitizedRoomName].users[socket.id] = sanitizedUsername;
        socket.emit("roomCreated", { room: sanitizedRoomName, username: sanitizedUsername });
        console.log(`📂 Room created: ${sanitizedRoomName} by ${sanitizedUsername}`);
    });

    socket.on("joinRoom", async (data) => {
        // Apply rate limiting for room joining
        try {
            await roomJoinLimiter.consume(socket.id);
        } catch (rejRes) {
            socket.emit("errorMessage", "You're joining rooms too quickly. Please try again later.");
            return;
        }
        
        const { room: roomName, password = "", username } = data;
        
        // Sanitize inputs
        const sanitizedRoomName = sanitizeMessage(roomName).trim();
        const sanitizedUsername = sanitizeMessage(username).trim();
        
        if (!sanitizedRoomName || !sanitizedUsername) {
            socket.emit("errorMessage", "Invalid room name or username");
            return;
        }

        if (!rooms[sanitizedRoomName]) {
            socket.emit("errorMessage", "Room does not exist.");
            return;
        }

        if (rooms[sanitizedRoomName].password && rooms[sanitizedRoomName].password !== password) {
            socket.emit("errorMessage", "Incorrect password.");
            return;
        }

        socket.join(sanitizedRoomName);
        rooms[sanitizedRoomName].users[socket.id] = sanitizedUsername;
        socket.emit("roomJoined", { room: sanitizedRoomName, username: sanitizedUsername });

        const roomMessages = messages.filter((m) => m.room === sanitizedRoomName);
        socket.emit("chatHistory", roomMessages);

        socket.to(sanitizedRoomName).emit("receiveMessage", { 
            room: sanitizedRoomName, 
            user: "Server", 
            text: `${sanitizedUsername} joined the room.` 
        });
        
        console.log(`📥 ${sanitizedUsername} joined room: ${sanitizedRoomName}`);
    });

    socket.on("sendMessage", async (data) => {
        // Apply rate limiting for messages
        try {
            await messageLimiter.consume(socket.id);
        } catch (rejRes) {
            socket.emit("errorMessage", "You're sending messages too quickly. Please slow down.");
            return;
        }
        
        // Make a copy of the data to avoid modifying the original
        const sanitizedData = { 
            room: sanitizeMessage(data.room),
            user: sanitizeMessage(data.user),
            text: sanitizeMessage(data.text)
        };
        
        // Skip empty messages
        if (!sanitizedData.text.trim()) {
            return;
        }
        
        // Check message content for blocked patterns
        const contentCheck = checkMessageContent(sanitizedData.text);
        if (!contentCheck.allowed) {
            if (contentCheck.action === "block") {
                socket.emit("errorMessage", `Message blocked: ${contentCheck.reason}`);
                return;
            } else if (contentCheck.action === "warn") {
                warnUser(socket, contentCheck.reason);
                // Continue with warning issued
            }
        }
        
        // Check for spam behavior
        const spamCheck = checkForSpam(
            socket.id, 
            sanitizedData.user,
            sanitizedData.text,
            sanitizedData.room
        );
        
        if (!spamCheck.allowed) {
            if (spamCheck.action === "block") {
                socket.emit("errorMessage", `Message blocked: ${spamCheck.reason}`);
                return;
            } else if (spamCheck.action === "warn") {
                warnUser(socket, spamCheck.reason);
                // Continue with warning issued
            }
        }
        
        // If all checks passed, broadcast the message
        messages.push(sanitizedData);
        
        // Limit message history to prevent memory issues
        if (messages.length > 1000) {
            messages = messages.slice(-1000);
        }
        
        io.to(sanitizedData.room).emit("receiveMessage", sanitizedData);
        console.log(`💬 Message in ${sanitizedData.room}: ${sanitizedData.user}: ${sanitizedData.text}`);
    });

    // Voice Chat events using WebRTC signaling
    socket.on("joinVoice", (data) => {
        const { room: roomName, username } = data;
        const sanitizedRoomName = sanitizeMessage(roomName);
        const sanitizedUsername = sanitizeMessage(username);
        
        if (!voiceRooms[sanitizedRoomName]) {
            voiceRooms[sanitizedRoomName] = {};
        }
        voiceRooms[sanitizedRoomName][socket.id] = sanitizedUsername;
        socket.join(`${sanitizedRoomName}_voice`);
        socket.emit("voiceConnected");
        socket.to(`${sanitizedRoomName}_voice`).emit("voiceNewPeer", { 
            peerId: socket.id, 
            username: sanitizedUsername 
        });
        console.log(`🎙️ [joinVoice] ${sanitizedUsername} (${socket.id}) joined voice room: ${sanitizedRoomName}`);
    });

    socket.on("voiceOffer", (data) => {
        io.to(data.to).emit("voiceOffer", { 
            from: socket.id, 
            offer: data.offer, 
            username: sanitizeMessage(data.username), 
            room: sanitizeMessage(data.room) 
        });
    });

    socket.on("voiceAnswer", (data) => {
        io.to(data.to).emit("voiceAnswer", { 
            from: socket.id, 
            answer: data.answer, 
            room: sanitizeMessage(data.room) 
        });
    });

    socket.on("voiceCandidate", (data) => {
        io.to(data.to).emit("voiceCandidate", { 
            from: socket.id, 
            candidate: data.candidate, 
            room: sanitizeMessage(data.room) 
        });
    });

    socket.on("leaveVoice", (data) => {
        const { room: roomName } = data;
        const sanitizedRoomName = sanitizeMessage(roomName);
        
        if (voiceRooms[sanitizedRoomName] && voiceRooms[sanitizedRoomName][socket.id]) {
            const username = voiceRooms[sanitizedRoomName][socket.id];
            delete voiceRooms[sanitizedRoomName][socket.id];
            socket.leave(`${sanitizedRoomName}_voice`);
            socket.to(`${sanitizedRoomName}_voice`).emit("voicePeerDisconnected", { 
                peerId: socket.id, 
                username 
            });
        }
    });

    // Admin commands for moderation
    socket.on("adminCommand", (data) => {
        // Should have proper authentication in production
        if (data.adminToken !== process.env.ADMIN_TOKEN) {
            socket.emit("errorMessage", "Unauthorized admin command");
            return;
        }
        
        switch (data.command) {
            case "ban":
                if (data.targetSocketId) {
                    const targetSocket = io.sockets.sockets.get(data.targetSocketId);
                    if (targetSocket) {
                        banUser(targetSocket);
                        socket.emit("adminCommandResult", { 
                            success: true, 
                            message: "User banned" 
                        });
                    } else {
                        socket.emit("adminCommandResult", { 
                            success: false, 
                            message: "User not found" 
                        });
                    }
                } else if (data.ip) {
                    bannedIPs.add(data.ip);
                    socket.emit("adminCommandResult", { 
                        success: true, 
                        message: `IP ${data.ip} banned` 
                    });
                } else {
                    socket.emit("adminCommandResult", { 
                        success: false, 
                        message: "No target specified" 
                    });
                }
                break;
                
            case "unban":
                if (data.ip && bannedIPs.has(data.ip)) {
                    bannedIPs.delete(data.ip);
                    socket.emit("adminCommandResult", { 
                        success: true, 
                        message: `IP ${data.ip} unbanned` 
                    });
                } else {
                    socket.emit("adminCommandResult", { 
                        success: false, 
                        message: "IP not found in ban list" 
                    });
                }
                break;
                
            case "listBans":
                socket.emit("adminCommandResult", { 
                    success: true, 
                    bans: Array.from(bannedIPs) 
                });
                break;
                
            default:
                socket.emit("adminCommandResult", { 
                    success: false, 
                    message: "Unknown command" 
                });
        }
    });

    socket.on("disconnect", () => {
        const ip = getClientIP(socket);
        
        // Remove socket from IP tracking
        if (ipSocketMap[ip]) {
            ipSocketMap[ip] = ipSocketMap[ip].filter(id => id !== socket.id);
            if (ipSocketMap[ip].length === 0) {
                delete ipSocketMap[ip];
            }
        }
        
        // Clean up user data
        delete userWarnings[socket.id];
        delete userMessageTimestamps[socket.id];
        
        console.log(`❌ User Disconnected: ${socket.id}`);
        
        // Handle room cleanup
        for (let room in rooms) {
            if (rooms[room].users[socket.id]) {
                const username = rooms[room].users[socket.id];
                delete rooms[room].users[socket.id];
                socket.to(room).emit("receiveMessage", { 
                    room, 
                    user: "Server", 
                    text: `${username} left the room.` 
                });
                
                // Remove empty non-prepopulated rooms
                if (Object.keys(rooms[room].users).length === 0 && !prepopulatedRooms.includes(room)) {
                    delete rooms[room];
                }
            }
        }
        
        // Handle voice room cleanup
        for (let room in voiceRooms) {
            if (voiceRooms[room][socket.id]) {
                delete voiceRooms[room][socket.id];
                socket.to(`${room}_voice`).emit("voicePeerDisconnected", { peerId: socket.id });
                
                // Remove empty voice rooms
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
