const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");

const PORT = process.env.PORT || 8080;
const app = express();

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

    // --- Text Chat Events (unchanged) ---
    // ... your text chat events here ...

    // --- Reworked Voice Chat Events ---
    socket.on("joinVoice", (data) => {
        const roomName = data.room;
        const username = data.username;
        if (!voiceRooms[roomName]) {
            voiceRooms[roomName] = {};
        }
        voiceRooms[roomName][socket.id] = username;
        socket.join(roomName + "_voice");
        socket.emit("voiceConnected");
        // Notify other peers about the new participant
        socket.to(roomName + "_voice").emit("voiceNewPeer", { peerId: socket.id, username });
        console.log(`🎙️ [joinVoice] ${username} (${socket.id}) joined voice room: ${roomName}`);
    });

    socket.on("voiceOffer", (data) => {
        console.log(`🎙️ [voiceOffer] From ${socket.id} to ${data.to} in room ${data.room}`);
        io.to(data.to).emit("voiceOffer", { from: socket.id, offer: data.offer, username: data.username, room: data.room });
    });

    socket.on("voiceAnswer", (data) => {
        console.log(`🎙️ [voiceAnswer] From ${socket.id} to ${data.to} in room ${data.room}`);
        io.to(data.to).emit("voiceAnswer", { from: socket.id, answer: data.answer, room: data.room });
    });

    socket.on("voiceCandidate", (data) => {
        console.log(`🎙️ [voiceCandidate] From ${socket.id} to ${data.to} in room ${data.room}`);
        io.to(data.to).emit("voiceCandidate", { from: socket.id, candidate: data.candidate, room: data.room });
    });

    socket.on("leaveVoice", (data) => {
        const roomName = data.room;
        if (voiceRooms[roomName] && voiceRooms[roomName][socket.id]) {
            console.log(`🎙️ [leaveVoice] ${data.username} (${socket.id}) leaving voice room: ${roomName}`);
            delete voiceRooms[roomName][socket.id];
            socket.leave(roomName + "_voice");
            // Notify remaining peers to remove this connection
            socket.to(roomName + "_voice").emit("voicePeerDisconnected", { peerId: socket.id, username: data.username });
        }
    });

    socket.on("disconnect", () => {
        console.log(`❌ User Disconnected: ${socket.id}`);
        // Handle text chat disconnection
        for (let room in rooms) {
            if (rooms[room].users[socket.id]) {
                const username = rooms[room].users[socket.id];
                delete rooms[room].users[socket.id];
                socket.to(room).emit("receiveMessage", { room, user: "Server", text: `${username} left the room.` });
                if (Object.keys(rooms[room].users).length === 0 && !prepopulatedRooms.includes(room)) {
                    delete rooms[room];
                    console.log(`🗑️ Room deleted: ${room}`);
                }
            }
        }
        // Handle voice chat disconnection
        for (let room in voiceRooms) {
            if (voiceRooms[room][socket.id]) {
                const username = voiceRooms[room][socket.id];
                console.log(`❌ [disconnect] Removing ${socket.id} from voice room: ${room}`);
                delete voiceRooms[room][socket.id];
                socket.to(room + "_voice").emit("voicePeerDisconnected", { peerId: socket.id, username });
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
