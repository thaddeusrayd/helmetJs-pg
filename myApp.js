const express = require("express");
const app = express();
const helmet = require("helmet");

app.use(helmet.hidePoweredBy());
// middleware to remove X-Powered-By header to prevent bad actors from seeing that app uses Express
app.use(helmet.frameguard({ action: "deny" }));
// middleware to combat clickjacking and iframing with malicious context;
//// sets X-Frame-Options header to deny, sameorigin, or allow-from

module.exports = app;
const api = require("./server.js");
app.use(express.static("public"));
app.disable("strict-transport-security");
app.use("/_api", api);
app.get("/", function (request, response) {
  response.sendFile(__dirname + "/views/index.html");
});
let port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Your app is listening on port ${port}`);
});
