const ms = require("ms");

function since(start) {
  return ms(Date.now() - start, { long: true });
}

module.exports = { since };
