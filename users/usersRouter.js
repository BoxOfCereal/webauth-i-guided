const express = require("express");
const router = express.Router();
const Users = require("../users/users-model.js");
//middlware
const restricted = require("../auth/restrictedMiddleware");
const checkRoles = require("../auth/checkRoleMiddleware");

router.get("/", restricted, checkRoles("TA"), (req, res) => {
  //we should only send back if credentials valid

  Users.find()
    .then(users => {
      //give back token payload
      res.json({ users, decodedToken: req.decodedJwt });
    })
    .catch(err => res.send(err));
});

router.get("/greet", restricted, (req, res) => {});

// Access the session as req.session
router.get("/views", restricted, function(req, res, next) {});
module.exports = router;
