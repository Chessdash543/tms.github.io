const express = require("express");
const bodyParser = require("body-parser");
const basicAuth = require("basic-auth");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3000;

// Configurar JSON e pasta pública
app.use(bodyParser.json());
app.use(express.static("public"));

// Usuário e senha do admin
const adminUser = "admin";
const adminPass = "minhaSenha123";

// Middleware de autenticação
function auth(req, res, next) {
    const user = basicAuth(req);
    if (!user || user.name !== adminUser || user.pass !== adminPass) {
        res.set("WWW-Authenticate", 'Basic realm="Admin Area"');
        return res.status(401).send("Autenticação necessária.");
    }
    next();
}

// Rotas
app.get("/admin.html", auth, (req, res) => {
    res.sendFile(path.join(__dirname, "public/admin.html"));
});

// API para ler JSON
app.get("/api/packs", (req, res) => {
    const packs = JSON.parse(fs.readFileSync("./data/packs.json"));
    res.json(packs);
});

// API para adicionar pack
app.post("/api/packs", auth, (req, res) => {
    const packs = JSON.parse(fs.readFileSync("/public/packs.json"));
    packs.push(req.body);
    fs.writeFileSync("./data/packs.json", JSON.stringify(packs, null, 2));
    res.json({ success: true });
});

app.listen(PORT, () => console.log(`Servidor rodando em http://localhost:${PORT}`));
