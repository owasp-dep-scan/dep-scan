const ms = require("ms");

function short(time) {
  return ms(time);
}

module.exports = { short };
