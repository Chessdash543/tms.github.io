const express = require("express");
const bodyParser = require("body-parser");
const basicAuth = require("basic-auth");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Configurar JSON e pasta pública
app.use(bodyParser.json());
app.use(express.static("public"));

// Usuário e senha do admin
const adminUser = "CHESSDASH543";
const adminPass = "8D9WJ49FKAS0WIE01K-QWJEFOI3J";

// Caminho do arquivo JSON
const packsFilePath = path.join(__dirname, "data", "data.json");

// Middleware de autenticação
function auth(req, res, next) {
    const user = basicAuth(req);
    if (!user || user.name !== adminUser || user.pass !== adminPass) {
        res.set("WWW-Authenticate", 'Basic realm="Admin Area"');
        return res.status(401).send("Autenticação necessária.");
    }
    next();
}

// Rota para admin.html
app.get("/admin.html", auth, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// API para ler todos os packs
app.get("/api/packs", (req, res) => {
    try {
        const packs = JSON.parse(fs.readFileSync(packsFilePath));
        res.json(packs);
    } catch (err) {
        res.status(500).json({ error: "Não foi possível ler o JSON" });
    }
});

// API para adicionar um novo pack
app.post("/api/packs", auth, (req, res) => {
    try {
        const packs = JSON.parse(fs.readFileSync(packsFilePath));
        packs.push(req.body);
        fs.writeFileSync(packsFilePath, JSON.stringify(packs, null, 2));
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: "Não foi possível adicionar o pack" });
    }
});

// Inicializar servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});
