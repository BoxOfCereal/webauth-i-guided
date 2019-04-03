//read decode verify
const jwt = require("jsonwebtoken");

const { secret } = require("../config/secrets");

module.exports = (req, res, next) => {
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
};
