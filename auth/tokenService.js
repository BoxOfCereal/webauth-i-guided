const jwt = require("jsonwebtoken");
const { secret } = require("../config/secrets");

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

module.exports = {
  genToken
};
