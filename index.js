require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken"); //web token

const db = require("./database/dbConfig.js");
const Users = require("./users/users-model.js");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

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

const secret = process.env.JWT_SECRET || "secret";

//produce token
const genToken = user => {
  const payload = {
    subject: user.id,
    username: user.username,
    roles: ["TA", "PM"] //in reality from db
  };

  const options = {
    expiresIn: "1d"
  };

  return jwt.sign(payload, secret, options);
};

//read decode verify
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (token) {
    jwt.verify(token, secret, (err, decodedToken) => {
      if (err) {
        //record tampering
        res.status(401).json({ message: "nice try" });
      } else {
        //give api access to decoded token
        req.decodedJwt = decodedToken;
        next();
      }
    });
  } else {
    res.status(401).json({ message: "no entry" });
  }
}

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      //password,hash
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = genToken(user);
        res.status(200).json({
          message: `Welcome ${user.username}!`,
          token
        });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function checkRoles(role) {
  return function(req, res, next) {
    if (req.decodedJwt.roles.includes(role)) {
      next();
    } else {
      res.status(403).json({ message: "Invalid Role" });
    }
  };
}

server.get("/api/users", auth, checkRoles("TA"), (req, res) => {
  //we should only send back if credentials valid

  Users.find()
    .then(users => {
      //give back token payload
      res.json({ users, decodedToken: req.decodedJwt });
    })
    .catch(err => res.send(err));
});

server.get("/", (req, res) => {
  res.send("got it");
});

server.get("/greet", auth, (req, res) => {});

// Access the session as req.session
server.get("/views", auth, function(req, res, next) {});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
