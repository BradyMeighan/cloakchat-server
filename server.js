const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");

const PORT = process.env.PORT || 8080;
const app = express();

// Fix CORS issues
app.use(cors({
    origin: "*",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"]
}));

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// In-memory storage for messages and rooms
let messages = []; // Global chat messages (each with a room property)
let rooms = {};    // Format: { roomName: { password: string, public: boolean, users: { socketId: username } } }
let voiceRooms = {}; // Format: { roomName: { [socket.id]: username } }

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

io.on("connection", (socket) => {
    console.log(`🔗 New Connection: ${socket.id}`);

    // Create a new room
    socket.on("createRoom", (data) => {
        // Data: { room: string, password: string, username: string }
        const roomName = data.room;
        const password = data.password || "";
        const username = data.username;
        
        if (rooms[roomName]) {
            socket.emit("errorMessage", "Room already exists.");
            return;
        }
        
        // Create room. If no password is provided, mark it as public.
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
        const roomName = data.room;
        const password = data.password || "";
        const username = data.username;
        
        if (!rooms[roomName]) {
            socket.emit("errorMessage", "Room does not exist.");
            return;
        }
        
        // Check password if required
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
    
    // Handle sending messages
    socket.on("sendMessage", (data) => {
        // Data: { room: string, user: string, text: string }
        messages.push(data);
        io.to(data.room).emit("receiveMessage", data);
        console.log(`💬 Message in ${data.room}: ${data.user}: ${data.text}`);
    });
    
    // Voice Chat events using WebRTC signaling
    socket.on("joinVoice", (data) => {
        // Data: { room: string, username: string }
        const roomName = data.room;
        const username = data.username;
        if (!voiceRooms[roomName]) {
            voiceRooms[roomName] = {};
        }
        voiceRooms[roomName][socket.id] = username;
        // Use a separate room name for voice connections
        socket.join(roomName + "_voice");
        socket.emit("voiceConnected");
        // Notify other voice peers of the new connection
        socket.to(roomName + "_voice").emit("voiceNewPeer", { peerId: socket.id, username });
        console.log(`🎙️ ${username} joined voice room: ${roomName}`);
    });
    
    socket.on("voiceOffer", (data) => {
        // Data: { offer, to, room: string, username: string }
        io.to(data.to).emit("voiceOffer", { from: socket.id, offer: data.offer, username: data.username, room: data.room });
    });
    
    socket.on("voiceAnswer", (data) => {
        // Data: { answer, to, room: string }
        io.to(data.to).emit("voiceAnswer", { from: socket.id, answer: data.answer, room: data.room });
    });
    
    socket.on("voiceCandidate", (data) => {
        // Data: { candidate, to, room: string }
        io.to(data.to).emit("voiceCandidate", { from: socket.id, candidate: data.candidate, room: data.room });
    });
    
    socket.on("leaveVoice", (data) => {
        // Data: { room: string, username: string }
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
        // Remove user from text rooms
        for (let room in rooms) {
            if (rooms[room].users[socket.id]) {
                const username = rooms[room].users[socket.id];
                delete rooms[room].users[socket.id];
                socket.to(room).emit("receiveMessage", { room, user: "Server", text: `${username} left the room.` });
                // Optionally delete room if empty
                if (Object.keys(rooms[room].users).length === 0) {
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
