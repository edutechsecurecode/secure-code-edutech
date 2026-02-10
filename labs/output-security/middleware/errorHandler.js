module.exports = (err, req, res, next) => {
  // VULNERABLE: sending stack to client
  res.status(500).send(`<pre>${err.stack}</pre>`);
};
