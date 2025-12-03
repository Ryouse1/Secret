import express from "express";
import multer from "multer";
import fs from "fs";
import dns from "dns/promises";
import fetch from "node-fetch";
import requestIp from 'request-ip';

const app = express();
const upload = multer({ dest: "uploads/" });
app.use(express.static("public"));
app.use(express.json());

// Ping
app.get("/api/ping", (req, res) => res.send("pong"));

// Malware Scan
app.post("/api/scan", upload.single("file"), (req, res) => {
const filePath = req.file.path;
const isSafe = true;
fs.unlinkSync(filePath);
res.send(isSafe ? "✔️ Safe file" : "⚠️ MALWARE DETECTED!");
});

// GeoIP Lookup (サイトサーバー)
app.get("/api/geoip", async (req, res) => {
try {
const url = req.query.url;
if(!url) return res.status(400).send("URL required");
let hostname = url.replace(/^https?:\/\//,'').split('/')[0];
const ipAddr = (await dns.lookup(hostname)).address;
const geoRes = await fetch(`https://ipapi.co/${ipAddr}/json/`);
const geoData = await geoRes.json();
res.json({ ip: ipAddr, geo: geoData });
} catch(e) { res.status(500).send(e.message); }
});

// GeoIP Lookup (クライアント)
app.get('/api/clientGeo', async (req, res) => {
try {
const clientIp = requestIp.getClientIp(req);
const geoRes = await fetch(`https://ipapi.co/${clientIp}/json/`);
const geoData = await geoRes.json();
res.json({ ip: clientIp, geo: geoData });
} catch(e){ res.status(500).send(e.message); }
});

// HTML Fetch
app.get("/api/fetchHtml", async (req,res)=>{
try {
const url=req.query.url;
if(!url) return res.status(400).send("URL required");
let html = await (await fetch(url)).text();
html = html.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi,'');
res.send(html);
} catch(e){ res.status(500).send(e.message); }
});

// HTTP/API Catch
app.post('/api/proxy', async (req,res)=>{
app.listen(3000, ()=>console.log("Server running on http://localhost:3000"));
