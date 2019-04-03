const express = require("express");
//Global middleware
const configureMiddleware = require("./middleware.js");

const server = express();

configureMiddleware(server);

server.use("/api/auth", require("../auth/authRouter"));
server.use("/api/users", require("../users/usersRouter"));

server.get("/", (req, res) => {
  res.send("got it");
});

module.exports = server;
