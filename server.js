const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");

const app = express();
app.use(cors());

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

let messages = [];

io.on("connection", (socket) => {
    console.log(`User connected: ${socket.id}`);

    socket.emit("chatHistory", messages);

    socket.on("sendMessage", (data) => {
        messages.push(data);
        io.emit("receiveMessage", data);
    });

    socket.on("disconnect", () => {
        console.log(`User disconnected: ${socket.id}`);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Chat server running on port ${PORT}`);
});
