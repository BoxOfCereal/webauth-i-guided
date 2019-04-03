module.exports = role => {
  return function(req, res, next) {
    if (req.decodedJwt.roles.includes(role)) {
      next();
    } else {
      res.status(403).json({ message: "Invalid Role" });
    }
  };
};
