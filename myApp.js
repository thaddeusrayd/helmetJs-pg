const express = require("express");
const app = express();
const helmet = require("helmet");

app.use(helmet.hidePoweredBy());
// middleware to remove X-Powered-By header to prevent bad actors from seeing that app uses Express
app.use(helmet.frameguard({ action: "deny" }));
// middleware to combat clickjacking and iframing with malicious context;
//// sets X-Frame-Options header to deny, sameorigin, or allow-from
app.use(helmet.xssFilter());
// middleware to serve as basic protection against XSS;
//// browser detects potential malicious script injections and neutralizes it
app.use(helmet.noSniff());
// middleware that prevents content/MIME sniffing overrides of a response's Content-Type header;
//// sets X-Content-Type-Options to nosniff and prevents browser from bypassing Content-Type
app.use(helmet.ieNoOpen());
// not often used, as Internet Explorer is deprecated, but some versions of IE download and open untrusted HTML by default;
//// .ieNoOpen() sets X-Download-Options header to noopen
const ninetyDaysInSeconds = 90 * 24 * 60 * 60;
app.use(helmet.hsts({ maxAge: ninetyDaysInSeconds, force: true }));
// force site to adhere to HSTS and avoid HTTP; can only be used if domain has SSL/TLS certificate
//// protects against protocol downgrade and cookie hijacking
app.use(helmet.dnsPrefetchControl());
// prevents browsers from prefetching DNS records for page links; downgrades performance for security;
//// protects against DNS overuse, privacy concerns (bad actor could see which DNS records are fetched and infer
//// which site you're on), or page statistics alteration
app.use(helmet.noCache());
// disables caching on client browser; lose performance benefits
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "trusted-cdn.com"],
    },
  })
);
// implements a security policy that only allows scripts to be run from the site itself;
//// a CSP defines a whitelist of allowed content sources; provides granular control;
//// protects against XSS, tracking, framing, or any other injection-based attack; unsupported by older browsers

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
