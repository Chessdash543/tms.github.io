const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const archiver = require("archiver");
const bcrypt = require('bcryptjs');
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const AdmZip = require('adm-zip');

const app = express();
const PORT = process.env.PORT || 3000;

const packsFilePath = path.join(__dirname, "data", "data.json");
// Onde estão todos os ícones/screenshots/zips dos packs
const uploadsDir = path.join(__dirname, 'public', 'uploads'); 
// Diretório para backups de segurança do JSON
const backupDir = path.join(__dirname, 'data', '.backup'); 

// --- Configuração Temporária para RESTORE (USA DISCO) ---
const RESTORE_TEMP_DIR = path.join(__dirname, '.restore-upload');
if (!fs.existsSync(RESTORE_TEMP_DIR)) fs.mkdirSync(RESTORE_TEMP_DIR, { recursive: true });

const restoreStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, RESTORE_TEMP_DIR),
    filename: (req, file, cb) => cb(null, `restore-temp-${Date.now()}.zip`)
});

// Configurar upload temporário para o backup (usando DISCO, limite de 500MB)
const tempUpload = multer({
    storage: restoreStorage,
    limits: { fileSize: 500 * 1024 * 1024 } 
});

const passwordPath = path.join(__dirname, "data", "password.json");

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

try {
    if (fs.existsSync(passwordPath)) {
        const pwdData = JSON.parse(fs.readFileSync(passwordPath));
        // Prefer explicit hash from env or file
        if (process.env.UPLOAD_PASSWORD_HASH) {
            uploadPasswordHash = process.env.UPLOAD_PASSWORD_HASH;
        } else if (pwdData.uploadPasswordHash) {
            uploadPasswordHash = pwdData.uploadPasswordHash;
        } else if (process.env.UPLOAD_PASSWORD) {
            // hash env plaintext (do not persist)
            uploadPasswordHash = bcrypt.hashSync(process.env.UPLOAD_PASSWORD, 10);
        } else if (typeof pwdData.uploadPassword === 'string' && pwdData.uploadPassword.length > 0) {
            // legacy plaintext in file — hash it and persist the hash
            const hashed = bcrypt.hashSync(pwdData.uploadPassword, 10);
            uploadPasswordHash = hashed;
            // persist hashed value and remove plaintext (best-effort)
            try {
                pwdData.uploadPasswordHash = hashed;
                delete pwdData.uploadPassword;
                fs.writeFileSync(passwordPath, JSON.stringify(pwdData, null, 2));
                console.warn('Plaintext password in password.json was hashed and replaced with uploadPasswordHash.');
            } catch (werr) {
                console.warn('Failed to persist hashed password to password.json:', werr.message || werr);
            }
        } else {
            console.warn("Aviso: nenhum password configurado em password.json ou variáveis de ambiente. Use UPLOAD_PASSWORD ou UPLOAD_PASSWORD_HASH.");
        }
    } else {
        // No password file
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
    console.warn("Aviso: JWT_SECRET não definido. Usando valor padrão. Defina a variável de ambiente JWT_SECRET em produção.");
}

// Middleware de autenticação
const authenticate = (req, res, next) => {
    const password = req.headers['x-upload-password'] || req.body?.password;
    if (!uploadPasswordHash) return res.status(500).json({ error: 'Senha do servidor não configurada' });
    if (!password || !bcrypt.compareSync(password, uploadPasswordHash)) {
        return res.status(401).json({ error: "Senha incorreta" });
    }
    next();
};

// Middleware de verificação de token JWT
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

if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const packId = req.body.packId;
        if (!packId) return cb(new Error('packId não fornecido'));

        const dir = path.join(__dirname, 'public', 'uploads', packId);
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

// Rota admin
app.get("/admin.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// Login - gera token JWT
app.post("/api/login", (req, res) => {
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ error: "Senha é obrigatória" });
    }

    if (!uploadPasswordHash || !bcrypt.compareSync(password, uploadPasswordHash)) {
        return res.status(401).json({ error: "Senha incorreta" });
    }

    // Gera token válido por 24 horas
    const token = jwt.sign(
        { admin: true, loginTime: new Date() },
        JWT_SECRET,
        { expiresIn: '24h' }
    );

    res.json({ success: true, token, expiresIn: '24h' });
});

// Ler todos os packs
app.get("/api/packs", (req, res) => {
    try {
        const packs = JSON.parse(fs.readFileSync(packsFilePath));
        res.json(packs);
    } catch (err) {
        res.status(500).json({ error: "Não foi possível ler o JSON" });
    }
});

// Incrementar contagem de downloads
app.post("/api/download/:id", (req, res) => {
    try {
        let packs = JSON.parse(fs.readFileSync(packsFilePath));
        const pack = packs.find(p => p.id === req.params.id);
        
        if (!pack) {
            return res.status(404).json({ error: "Pack não encontrado" });
        }
        
        // Incrementa contador
        if (!pack.downloads) pack.downloads = 0;
        pack.downloads += 1;
        
        // Salva arquivo atualizado
        fs.writeFileSync(packsFilePath, JSON.stringify(packs, null, 2));
        
        res.json({ success: true, downloads: pack.downloads });
    } catch (err) {
        res.status(500).json({ error: "Erro ao atualizar downloads" });
    }
});

// Adicionar novo pack
app.post("/api/packs", verifyToken, (req, res) => {
    try {
        const { id, name, creator, description, version, resolution, download, icon, screenshot } = req.body;
        
        // Validação básica
        if (!id || !name || !creator || !download) {
            return res.status(400).json({ error: "Campos obrigatórios: id, name, creator, download" });
        }
        
        let packs = JSON.parse(fs.readFileSync(packsFilePath));
        
        // Verifica se pack já existe
        if (packs.find(p => p.id === id)) {
            return res.status(409).json({ error: "Pack com esse ID já existe" });
        }
        
        // Cria novo pack
        const newPack = {
            id,
            name,
            creator,
            resolution: resolution || ["medium"],
            download,
            description: description || "",
            version: version || "v1.0.0",
            icon: icon || "/img/default-icon.png",
            screenshot: screenshot || "/img/default-screenshot.png",
            downloads: 0
        };
        
        packs.push(newPack);
        fs.writeFileSync(packsFilePath, JSON.stringify(packs, null, 2));
        
        res.status(201).json({ success: true, pack: newPack });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro ao adicionar pack" });
    }
});

// Atualizar pack existente
app.put('/api/packs/:id', verifyToken, (req, res) => {
    try {
        const packId = req.params.id;
        const updates = req.body;

        let packs = JSON.parse(fs.readFileSync(packsFilePath));
        const idx = packs.findIndex(p => p.id === packId);
        if (idx === -1) return res.status(404).json({ error: 'Pack não encontrado' });

        // Atualiza apenas campos permitidos
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

// Remover pack
app.delete('/api/packs/:id', verifyToken, (req, res) => {
    try {
        const packId = req.params.id;
        let packs = JSON.parse(fs.readFileSync(packsFilePath));
        const idx = packs.findIndex(p => p.id === packId);
        if (idx === -1) return res.status(404).json({ error: 'Pack não encontrado' });

        const removed = packs.splice(idx, 1)[0];
        fs.writeFileSync(packsFilePath, JSON.stringify(packs, null, 2));

        // tenta remover pasta de uploads (se existir)
        const packDir = path.join(__dirname, 'public', 'uploads', packId);
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

// Upload de arquivos (ZIP, ícone, screenshot)
app.post('/api/upload', verifyToken, (req, res) => {
    // 1. Envolver o middleware do multer para capturar erros específicos dele
    upload.fields([
        { name: 'zipFile', maxCount: 1 },
        { name: 'icon', maxCount: 1 },
        { name: 'screenshot', maxCount: 1 }
    ])(req, res, (err) => {
        if (err instanceof multer.MulterError) {
            // Erros do multer (ex: tamanho de arquivo excedido, número de arquivos)
            return res.status(400).json({ error: 'Erro no upload: ' + err.message });
        } else if (err) {
            // Outros erros (ex: packId não fornecido na função de destino)
            console.error('Upload error (Multer):', err);
            return res.status(500).json({ error: 'Erro ao fazer upload: ' + (err.message || 'Erro desconhecido') });
        }

        // 2. Sua lógica de sucesso original, que agora está dentro do callback
        try {
            const packId = req.body.packId;
            if (!packId) return res.status(400).json({ error: 'packId é obrigatório' });

            const uploads = {};
            if (req.files?.zipFile?.[0]) uploads.zip = `/uploads/${packId}/${req.files.zipFile[0].filename}`;
            if (req.files?.icon?.[0]) uploads.icon = `/uploads/${packId}/${req.files.icon[0].filename}`;
            if (req.files?.screenshot?.[0]) uploads.screenshot = `/uploads/${packId}/${req.files.screenshot[0].filename}`;

            res.json({ success: true, uploads });
        } catch (internalErr) {
            console.error('Upload error (Internal Logic):', internalErr);
            res.status(500).json({ error: 'Erro interno ao processar upload: ' + internalErr.message });
        }
    });
});

// GET /api/backup - download backup compactado (data.json + uploads)
app.get('/api/backup', verifyToken, (req, res) => {
    try {
        const uploadsDir = path.join(__dirname, 'public', 'uploads');
        const dataFile = packsFilePath;

        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename=backup-${Date.now()}.zip`);

        const archive = archiver('zip', { zlib: { level: 9 } });
        archive.on('error', (err) => {
            console.error('Archive error:', err);
            res.end();
        });

        archive.on('end', () => {
            console.log('Archive data stream ended. Total bytes:', archive.pointer());
        });


        archive.pipe(res);

        // Adiciona data.json
        if (fs.existsSync(dataFile)) {
            archive.file(dataFile, { name: 'data.json' });
        }

        // Adiciona pasta uploads inteira
        if (fs.existsSync(uploadsDir)) {
            archive.directory(uploadsDir, 'uploads');
        }

        archive.finalize();
    } catch (err) {
        console.error('Backup error:', err);
        res.status(500).json({ error: 'Erro ao fazer backup' });
    }
});

// POST /api/backup/restore - restaurar backup de arquivo .zip
app.post('/api/backup/restore', verifyToken, (req, res) => {
    // 1. Usar o middleware tempUpload para salvar o ZIP no disco
    tempUpload.single('backup')(req, res, async (err) => {
        if (err) {
            console.error('Erro Multer no Restore:', err);
            return res.status(400).json({ error: 'Erro no upload: ' + (err.message || 'Nenhum arquivo enviado') });
        }
        if (!req.file) {
             return res.status(400).json({ error: 'Nenhum arquivo .zip de backup selecionado.' });
        }
        
        const zipFilePath = req.file.path; // O caminho do arquivo salvo no disco
        const RESTORE_EXTRACT_DIR = path.join(__dirname, '.restore-temp-extract');

        try {
            // 2. Backup do estado atual antes de restaurar
            if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

            const timestamp = Date.now();
            if (fs.existsSync(packsFilePath)) {
                fs.copyFileSync(packsFilePath, path.join(backupDir, `data-${timestamp}.json`));
            }

            // 3. Extrair o arquivo ZIP
            const zip = new AdmZip(zipFilePath);

            // Criar e limpar diretório de extração temporário
            if (fs.existsSync(RESTORE_EXTRACT_DIR)) {
                fs.rmSync(RESTORE_EXTRACT_DIR, { recursive: true, force: true });
            }
            fs.mkdirSync(RESTORE_EXTRACT_DIR, { recursive: true });

            // Extrai tudo para o temp
            zip.extractAllTo(RESTORE_EXTRACT_DIR, true);

            // 4. Restaura data.json
            const tempDataFile = path.join(RESTORE_EXTRACT_DIR, 'data.json');
            if (fs.existsSync(tempDataFile)) {
                const dataContent = fs.readFileSync(tempDataFile, 'utf8');
                JSON.parse(dataContent); // Valida se o JSON é válido
                fs.writeFileSync(packsFilePath, dataContent);
            }

            // 5. Restaura uploads (Substitui a pasta inteira)
            const tempUploadsDir = path.join(RESTORE_EXTRACT_DIR, 'uploads');

            // 5a. Remove pasta uploads atual
            if (fs.existsSync(uploadsDir)) {
                fs.rmSync(uploadsDir, { recursive: true, force: true });
            }
            
            // 5b. Copia a pasta uploads do backup para a pasta pública
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
            // 6. Limpeza FINAL: Remove todos os arquivos temporários do disco
            try {
                // Remove o arquivo ZIP temporário que foi salvo
                if (fs.existsSync(zipFilePath)) {
                    fs.unlinkSync(zipFilePath);
                }
                // Remove a pasta de extração temporária
                if (fs.existsSync(RESTORE_EXTRACT_DIR)) {
                    fs.rmSync(RESTORE_EXTRACT_DIR, { recursive: true, force: true });
                }
            } catch (cleanupErr) {
                console.warn('Falha ao remover arquivos temporários:', cleanupErr.message || cleanupErr);
                // NOTA: Não retorne um erro 500 aqui, pois a restauração já foi concluída com sucesso.
            }
        }
    });
});

// Retorna JSON para rotas /api não encontradas (evita HTML)
app.use((req, res, next) => {
    if (req.path.startsWith('/api')) {
        return res.status(404).json({ error: 'Endpoint API não encontrado' });
    }
    next();
});

// Handler global de erros — retorna JSON para rotas /api
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err && (err.stack || err));
    if (req.path && req.path.startsWith && req.path.startsWith('/api')) {
        return res.status(500).json({ error: 'Erro interno no servidor' });
    }
    res.status(500).send('Erro interno no servidor');
});

app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});
