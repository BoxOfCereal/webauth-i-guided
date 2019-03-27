const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const session = require("express-session");

const db = require("./database/dbConfig.js");
const Users = require("./users/users-model.js");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get("/", (req, res) => {
  res.send("It's alive!");
});

server.post("/api/register", (req, res) => {
  let user = req.body;
  //1 hash pass
  const hash = bcrypt.hashSync(user.password, 10);
  //2 replace pw with hash
  user.password = hash;
  console.log(`user`, user);

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      //password,hash
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function auth(req, res, next) {
  console.log(req.headers);
  const { username, password } = req.headers;
  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        console.log(user);
        if (user && bcrypt.compareSync(password, user.password)) next();
        else res.status(403).json({ message: "forbidden" });
      })
      .catch(err => next(err));
  } else {
    res.status(400).json({ message: "Missing Credentials" });
  }
}

server.get("/api/users", auth, (req, res) => {
  //we should only send back if credentials valid

  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
