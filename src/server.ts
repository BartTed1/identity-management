import app from "./app.js";
import https from "https";
import fs from "fs";

const port = process.env.PORT || 8000;

const privateKey = fs.readFileSync("./sslcert/server.key", "utf8");
const certificate = fs.readFileSync("./sslcert/server.cert", "utf8");

const httpsServer = https.createServer({key:privateKey, cert:certificate},app).listen(port, () => {
	console.log(`Express running → PORT ${port}`);
});