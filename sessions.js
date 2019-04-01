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

//configure express-session middleware
server.use(
  session({
    name: "notsession", // default is connect.sid
    secret: "nobody tosses a dwarf!",
    cookie: {
      maxAge: 1 * 24 * 60 * 60 * 1000,
      //https://medium.freecodecamp.org/how-to-get-https-working-on-your-local-development-environment-in-5-minutes-7af615770eec
      secure: false // only set cookies over https. Server will not send back a cookie over http.
    }, // 1 day in milliseconds
    httpOnly: true, // don't let JS code access cookies. Browser extensions run JS code on your browser!
    resave: false,
    saveUninitialized: false
  })
);

// server.get("/", (req, res) => {
//   res.send("It's alive!");
// });

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

function protected(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ message: "you shall not pass!!" });
  }
}

server.get("/", (req, res) => {
  req.session.name = "Frodo";
  req.session.userId = "9000";
  res.send("got it");
});

server.get("/greet", protected, (req, res) => {
  console.log(req.session);
  const name = req.session.name;
  res.send(`hello ${req.session.name}`);
});

// Access the session as req.session
server.get("/views", protected, function(req, res, next) {
  console.log(req.session);
  if (req.session.views) {
    req.session.views++;
    res.setHeader("Content-Type", "text/html");
    res.write("<p>views: " + req.session.views + "</p>");
    res.write("<p>expires in: " + req.session.cookie.maxAge / 1000 + "s</p>");
    res.end();
  } else {
    req.session.views = 1;
    res.end("welcome to the session demo. refresh!");
  }
});

//destroy sessions
server.get("/logout", (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.send("error logging out");
      } else {
        res.send("good bye");
      }
    });
  }
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
