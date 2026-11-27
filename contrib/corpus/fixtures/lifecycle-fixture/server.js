// The fixture's own code: express is the shipped dependency the code uses
// (line 4 is the require). chalk stays unused and eslint stays dev-only.
const http = require("http");
const express = require("express");

const app = express();
app.get("/", (req, res) => {
  res.send("lifecycle fixture");
});

const port = process.env.PORT || 3000;
http.createServer(app).listen(port, () => {
  console.log("listening on", port);
});
