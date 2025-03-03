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

let messages = [];

io.on("connection", (socket) => {
    console.log(`🔗 New Connection: ${socket.id}`);

    // Send chat history
    socket.emit("chatHistory", messages);

    // Handle messages
    socket.on("sendMessage", (data) => {
        messages.push(data);
        io.emit("receiveMessage", data);
        console.log(`💬 Message: ${data.user}: ${data.text}`);
    });

    socket.on("disconnect", () => {
        console.log(`❌ User Disconnected: ${socket.id}`);
    });
});

// Use Railway's assigned PORT
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
