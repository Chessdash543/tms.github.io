// server.js - Versão para Servidor Contínuo (Render, Railway, etc.)

const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const archiver = require("archiver");
const bcrypt = require('bcryptjs');
const multer = require("multer");
const AdmZip = require('adm-zip');

const app = express();
// CRÍTICO: Re-introduzindo o PORT e app.listen() para rodar 24/7.
const PORT = process.env.PORT || 3000; 

// Nota: Em ambientes de contêiner (Render/Railway), o __dirname é seguro
// para referenciar arquivos que fazem parte do build do seu projeto.
const dataDir = path.join(__dirname, "data");
// Os paths foram reajustados para serem relativos à raiz do servidor
const packsFilePath = path.join(dataDir, "data.json");
const uploadsDir = path.join(__dirname, 'public', 'uploads'); 
const backupDir = path.join(dataDir, '.backup'); 

// --- Configuração Temporária para RESTORE ---
// Usando /tmp/ para garantir que o disco não encha, mas lembre-se:
// Arquivos em /tmp/ são perdidos após o restart/reboot.
const RESTORE_TEMP_DIR = path.join('/tmp', '.restore-upload'); 
if (!fs.existsSync(RESTORE_TEMP_DIR)) fs.mkdirSync(RESTORE_TEMP_DIR, { recursive: true });

const restoreStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, RESTORE_TEMP_DIR),
    filename: (req, file, cb) => cb(null, `restore-temp-${Date.now()}.zip`)
});

const tempUpload = multer({
    storage: restoreStorage,
    limits: { fileSize: 10737418240 } 
});

const passwordPath = path.join(dataDir, "password.json");

// Secret para JWT (gera automaticamente se não existir)
const JWT_SECRET = process.env.JWT_SECRET || "d594ee2ecd88d7ac7fe72d189614209f8fcb36b3f70c24224b4f46ee59c6abb937d546f9dd8f27f7e73b31f5a218eb2b";

// Configura pasta pública e JSON
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static("public"));

let uploadPasswordHash = "$2b$10$gBVPx3RzcG0kKEw.Zf8edu57vR7W.2X2Wt6pEph8p3Ui1/i9xIBSO";

const copyDirRecursive = (src, dest) => {
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    fs.readdirSync(src).forEach(file => {
        const srcFile = path.join(src, file);
        const destFile = path.join(dest, file);
        if (fs.statSync(srcFile).isDirectory()) {
            copyDirRecursive(srcFile, destFile);
        } else {
            fs.copyFileSync(srcFile, destFile);
        }
    });
};

// --- Bloco de Inicialização de Senha (Mantido, mas requer arquivos no repo) ---
try {
    // ... (Lógica de leitura de password.json mantida)
    if (fs.existsSync(passwordPath)) {
        const pwdData = JSON.parse(fs.readFileSync(passwordPath));
        if (process.env.UPLOAD_PASSWORD_HASH) {
            uploadPasswordHash = process.env.UPLOAD_PASSWORD_HASH;
        } else if (pwdData.uploadPasswordHash) {
            uploadPasswordHash = pwdData.uploadPasswordHash;
        } else if (process.env.UPLOAD_PASSWORD) {
            uploadPasswordHash = bcrypt.hashSync(process.env.UPLOAD_PASSWORD, 10);
        } else if (typeof pwdData.uploadPassword === 'string' && pwdData.uploadPassword.length > 0) {
            const hashed = bcrypt.hashSync(pwdData.uploadPassword, 10);
            uploadPasswordHash = hashed;
            try {
                // Tenta persistir o hash (Pode funcionar se o servidor tiver volume persistente)
                pwdData.uploadPasswordHash = hashed;
                delete pwdData.uploadPassword;
                fs.writeFileSync(passwordPath, JSON.stringify(pwdData, null, 2));
                console.warn('Senha plaintext em password.json foi hasheada.');
            } catch (werr) {
                console.warn('Falha ao persistir senha hasheada:', werr.message || werr);
            }
        } else {
            console.warn("Aviso: nenhum password configurado.");
        }
    } else {
        if (process.env.UPLOAD_PASSWORD_HASH) {
            uploadPasswordHash = process.env.UPLOAD_PASSWORD_HASH;
        } else if (process.env.UPLOAD_PASSWORD) {
            uploadPasswordHash = bcrypt.hashSync(process.env.UPLOAD_PASSWORD, 10);
        } else {
            console.warn("Aviso: password.json não encontrado e nenhuma variável de senha definida.");
        }
    }
} catch (err) {
    console.warn("Aviso ao ler password.json:", err.message || err);
}

if (!process.env.JWT_SECRET) {
    console.warn("Aviso: JWT_SECRET não definido. Usando valor padrão.");
}

// Middlewares de Autenticação (Mantidos)
const authenticate = (req, res, next) => {
    const password = req.headers['x-upload-password'] || req.body?.password;
    if (!uploadPasswordHash) return res.status(500).json({ error: 'Senha do servidor não configurada' });
    if (!password || !bcrypt.compareSync(password, uploadPasswordHash)) {
        return res.status(401).json({ error: "Senha incorreta" });
    }
    next();
};

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1] || req.body?.token;
    
    if (!token) {
        return res.status(401).json({ error: "Token não fornecido" });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Token inválido ou expirado" });
    }
};

// Verifica diretório de uploads (Pode falhar se não houver volume persistente)
if (!fs.existsSync(uploadsDir)) {
    try {
        fs.mkdirSync(uploadsDir, { recursive: true });
    } catch (e) {
        console.error("Não foi possível criar uploadsDir. Arquivos podem não ser persistentes.", e);
    }
}

// Configuração do Multer para uploads PERMANENTES (Atenção: só funciona em VM ou contêiner com Volume)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const packId = req.body.packId;
        if (!packId) return cb(new Error('packId não fornecido'));

        // Mantido no uploadsDir, mas SÓ FUNCIONA com disco persistente
        const dir = path.join(uploadsDir, packId); 
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 500 * 1024 * 1024 } // 500MB
});

// ==========================================================
// ROTAS (Mantidas com operações de disco local)
// ==========================================================

app.get("/admin.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.post("/api/login", (req, res) => {
    const { password } = req.body;
    if (!password) { return res.status(400).json({ error: "Senha é obrigatória" }); }
    if (!uploadPasswordHash || !bcrypt.compareSync(password, uploadPasswordHash)) {
        return res.status(401).json({ error: "Senha incorreta" });
    }
    const token = jwt.sign({ admin: true, loginTime: new Date() }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token, expiresIn: '24h' });
});

app.get("/api/packs", (req, res) => {
    try {
        const packs = JSON.parse(fs.readFileSync(packsFilePath));
        res.json(packs);
    } catch (err) {
        res.status(500).json({ error: "Não foi possível ler o JSON" });
    }
});

app.post("/api/download/:id", (req, res) => {
    try {
        let packs = JSON.parse(fs.readFileSync(packsFilePath));
        const pack = packs.find(p => p.id === req.params.id);
        if (!pack) { return res.status(404).json({ error: "Pack não encontrado" }); }
        if (!pack.downloads) pack.downloads = 0;
        pack.downloads += 1;
        fs.writeFileSync(packsFilePath, JSON.stringify(packs, null, 2));
        res.json({ success: true, downloads: pack.downloads });
    } catch (err) {
        res.status(500).json({ error: "Erro ao atualizar downloads" });
    }
});

app.post("/api/packs", verifyToken, (req, res) => {
    try {
        const { id, name, creator, download } = req.body;
        if (!id || !name || !creator || !download) {
            return res.status(400).json({ error: "Campos obrigatórios: id, name, creator, download" });
        }
        let packs = JSON.parse(fs.readFileSync(packsFilePath));
        if (packs.find(p => p.id === id)) {
            return res.status(409).json({ error: "Pack com esse ID já existe" });
        }
        const newPack = { ...req.body, downloads: 0 };
        packs.push(newPack);
        fs.writeFileSync(packsFilePath, JSON.stringify(packs, null, 2));
        res.status(201).json({ success: true, pack: newPack });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro ao adicionar pack" });
    }
});

app.put('/api/packs/:id', verifyToken, (req, res) => {
    try {
        const packId = req.params.id;
        const updates = req.body;
        let packs = JSON.parse(fs.readFileSync(packsFilePath));
        const idx = packs.findIndex(p => p.id === packId);
        if (idx === -1) return res.status(404).json({ error: 'Pack não encontrado' });

        const allowed = ['name', 'creator', 'description', 'version', 'resolution', 'download', 'icon', 'screenshot'];
        allowed.forEach(field => {
            if (updates[field] !== undefined) packs[idx][field] = updates[field];
        });

        fs.writeFileSync(packsFilePath, JSON.stringify(packs, null, 2));
        res.json({ success: true, pack: packs[idx] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao atualizar pack' });
    }
});

app.delete('/api/packs/:id', verifyToken, (req, res) => {
    try {
        const packId = req.params.id;
        let packs = JSON.parse(fs.readFileSync(packsFilePath));
        const idx = packs.findIndex(p => p.id === packId);
        if (idx === -1) return res.status(404).json({ error: 'Pack não encontrado' });

        const removed = packs.splice(idx, 1)[0];
        fs.writeFileSync(packsFilePath, JSON.stringify(packs, null, 2));

        const packDir = path.join(uploadsDir, packId);
        try {
            if (fs.existsSync(packDir)) {
                fs.rmSync(packDir, { recursive: true, force: true });
            }
        } catch (rmErr) {
            console.warn('Não foi possível remover pasta de uploads:', rmErr.message || rmErr);
        }

        res.json({ success: true, removed });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao remover pack' });
    }
});

app.post('/api/upload', verifyToken, (req, res) => {
    upload.fields([
        { name: 'zipFile', maxCount: 1 },
        { name: 'icon', maxCount: 1 },
        { name: 'screenshot', maxCount: 1 }
    ])(req, res, (err) => {
        if (err instanceof multer.MulterError) {
            return res.status(400).json({ error: 'Erro no upload: ' + err.message });
        } else if (err) {
            console.error('Upload error (Multer):', err);
            return res.status(500).json({ error: 'Erro ao fazer upload: ' + (err.message || 'Erro desconhecido') });
        }

        try {
            const packId = req.body.packId;
            if (!packId) return res.status(400).json({ error: 'packId é obrigatório' });

            const uploads = {};
            if (req.files?.zipFile?.[0]) uploads.zip = `/uploads/${packId}/${req.files.zipFile[0].filename}`;
            if (req.files?.icon?.[0]) uploads.icon = `/uploads/${packId}/${req.files.icon[0].filename}`;
            if (req.files?.screenshot?.[0]) uploads.screenshot = `/uploads/${packId}/${req.files.screenshot[0].filename}`;

            // Nota: Este caminho (uploads.zip) é válido apenas se 'uploadsDir' for persistente!
            res.json({ success: true, uploads });
        } catch (internalErr) {
            console.error('Upload error (Internal Logic):', internalErr);
            res.status(500).json({ error: 'Erro interno ao processar upload: ' + internalErr.message });
        }
    });
});

app.get('/api/backup', verifyToken, (req, res) => {
    try {
        const dataFile = packsFilePath;

        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename=backup-${Date.now()}.zip`);

        const archive = archiver('zip', { zlib: { level: 9 } });
        archive.on('error', (err) => {
            console.error('Archive error:', err);
            if (!res.headersSent) {
                res.status(500).json({ error: 'Erro ao criar arquivo ZIP' });
            } else {
                res.end();
            }
        });

        archive.on('end', () => {
            console.log('Archive data stream ended. Total bytes:', archive.pointer());
        });

        archive.pipe(res);

        if (fs.existsSync(dataFile)) {
            archive.file(dataFile, { name: 'data.json' });
        }

        if (fs.existsSync(uploadsDir)) {
            archive.directory(uploadsDir, 'uploads');
        }

        archive.finalize();
    } catch (err) {
        console.error('Backup error:', err);
        res.status(500).json({ error: 'Erro ao fazer backup' });
    }
});

app.post('/api/backup/restore', verifyToken, (req, res) => {
    tempUpload.single('backup')(req, res, async (err) => {
        if (err) {
            console.error('Erro Multer no Restore:', err);
            return res.status(400).json({ error: 'Erro no upload: ' + (err.message || 'Nenhum arquivo enviado') });
        }
        if (!req.file) {
             return res.status(400).json({ error: 'Nenhum arquivo .zip de backup selecionado.' });
        }
        
        // CRÍTICO: No Render/Railway, o disco local pode ser perdido a qualquer momento,
        // mas em uma VM, esta lógica de restore funcionaria.
        const zipFilePath = req.file.path; 
        const RESTORE_EXTRACT_DIR = path.join('/tmp', '.restore-temp-extract'); // Usando /tmp

        try {
            if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

            const timestamp = Date.now();
            if (fs.existsSync(packsFilePath)) {
                fs.copyFileSync(packsFilePath, path.join(backupDir, `data-${timestamp}.json`));
            }

            const zip = new AdmZip(zipFilePath);
            if (fs.existsSync(RESTORE_EXTRACT_DIR)) {
                fs.rmSync(RESTORE_EXTRACT_DIR, { recursive: true, force: true });
            }
            fs.mkdirSync(RESTORE_EXTRACT_DIR, { recursive: true });

            zip.extractAllTo(RESTORE_EXTRACT_DIR, true);

            const tempDataFile = path.join(RESTORE_EXTRACT_DIR, 'data.json');
            if (fs.existsSync(tempDataFile)) {
                const dataContent = fs.readFileSync(tempDataFile, 'utf8');
                JSON.parse(dataContent);
                fs.writeFileSync(packsFilePath, dataContent);
            }

            const tempUploadsDir = path.join(RESTORE_EXTRACT_DIR, 'uploads');
            if (fs.existsSync(uploadsDir)) {
                fs.rmSync(uploadsDir, { recursive: true, force: true });
            }
            
            if (fs.existsSync(tempUploadsDir)) {
                copyDirRecursive(tempUploadsDir, uploadsDir);
            }
            
            res.json({ 
                success: true, 
                message: 'Backup restaurado com sucesso. Recarregando...' 
            });
            
        } catch (parseErr) {
            console.error('Restore error:', parseErr);
            res.status(400).json({ error: 'Erro ao processar o backup. Arquivo inválido ou corrompido: ' + parseErr.message });
        } finally {
            try {
                const fsPromises = require('fs').promises;
                if (fs.existsSync(zipFilePath)) {
                    await fsPromises.unlink(zipFilePath);
                    console.log(`[CLEANUP] Arquivo ZIP temporário removido: ${zipFilePath}`);
                }
                if (fs.existsSync(RESTORE_EXTRACT_DIR)) {
                    await fsPromises.rm(RESTORE_EXTRACT_DIR, { recursive: true, force: true });
                    console.log(`[CLEANUP] Diretório de extração removido: ${RESTORE_EXTRACT_DIR}`);
                }
            } catch (cleanupErr) {
                console.warn('Falha na limpeza de arquivos temporários.', cleanupErr.message || cleanupErr);
            }
        }
    });
});

app.get("/api/packs/:id", (req, res) => {
    try {
        const packId = req.params.id;
        const packs = JSON.parse(fs.readFileSync(packsFilePath));
        const pack = packs.find(p => p.id === packId);
        if (!pack) { return res.status(404).json({ error: "Pack não encontrado" }); }
        res.json(pack);
    } catch (err) {
        console.error('Error fetching single pack:', err);
        res.status(500).json({ error: "Erro ao buscar detalhes do pack" });
    }
});


// Middlewares de Erro e 404 (Mantidos)
app.use((req, res, next) => {
    if (req.path.startsWith('/api')) {
        return res.status(404).json({ error: 'Endpoint API não encontrado' });
    }
    next();
});

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err && (err.stack || err)); 
    if (req.path && req.path.startsWith('/api')) {
        return res.status(500).json({ error: 'Erro interno no servidor' });
    }
    res.status(500).send('Erro interno no servidor');
});

// CRÍTICO: ESTA LINHA INICIA O SERVIDOR E O MANTÉM ATIVO 24/7.
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});
// module.exports = app; // Removido, pois só é necessário para Serverless (Vercel)