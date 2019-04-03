const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const Users = require("../users/users-model.js");
const { genToken } = require("./tokenService");

//produce token

router.post("/register", (req, res) => {
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

router.post("/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      //password,hash
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = genToken(user);
        console.log(token);
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

module.exports = router;
