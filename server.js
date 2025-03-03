const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");

const app = express();

// Fix CORS issues by allowing all origins
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

let messages = []; // Store chat history

io.on("connection", (socket) => {
    console.log(`🔗 New Connection: ${socket.id}`);

    // Send chat history
    socket.emit("chatHistory", messages);

    // Handle new messages
    socket.on("sendMessage", (data) => {
        messages.push(data);
        io.emit("receiveMessage", data); // Broadcast to all clients
        console.log(`💬 New Message from ${data.user}: ${data.text}`);
    });

    socket.on("disconnect", () => {
        console.log(`❌ User Disconnected: ${socket.id}`);
    });
});

// Use Railway's assigned PORT
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
