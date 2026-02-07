const express = require('express');
const https = require('https');
const dns = require('dns');
try {
  dns.setServers(['8.8.8.8', '8.8.4.4']);
} catch (e) {
  console.log("Impossible de forcer le DNS");
}
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static('uploads'));

app.use((req, res, next) => {
  const sanitize = (obj) => {
    for (const key in obj) {
      if (typeof obj[key] === 'string') {
        obj[key] = obj[key].replace(/[<>]/g, ""); 
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        sanitize(obj[key]);
      }
      if (key.includes('$')) {
        delete obj[key];
      }
    }
  };
  if (req.body) sanitize(req.body);
  if (req.query) sanitize(req.query);
  if (req.params) sanitize(req.params);
  next();
});

// Fonctions de validation Magic Numbers
const checkMagicNumbers = (filePath) => {
  return new Promise((resolve, reject) => {
    const stream = fs.createReadStream(filePath, { start: 0, end: 3 });
    let buffer = Buffer.alloc(0);
    
    stream.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
    });
    
    stream.on('end', () => {
      stream.close();
      const hex = buffer.toString('hex').toUpperCase();
      
      // Signatures
      // JPEG: FFD8FF
      // PNG: 89504E47
      // PDF: 25504446
      
      let isValid = false;
      if (hex.startsWith('FFD8FF')) isValid = true; 
      else if (hex.startsWith('89504E')) isValid = true;
      else if (hex.startsWith('255044')) isValid = true;
      
      resolve(isValid);
    });
    
    stream.on('error', (err) => reject(err));
  });
};

const storage = multer.diskStorage({ 
  destination: (req, file, cb) => {
    if (!fs.existsSync('uploads')) {
      fs.mkdirSync('uploads');
    }
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, 
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Seulement les fichiers images (JPG, PNG) et PDF sont autorisés'));
    }
  }
});

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/palestine_future')
  .then(async () => {
    console.log('✅ MongoDB connecté');
    await seedAdmin();
  })
  .catch(err => console.error('❌ MongoDB erreur:', err));

async function seedAdmin() {
  try {
    const adminEmail = 'cse@esi.dz';
    const adminExists = await User.findOne({ email: adminEmail });
    
    if (!adminExists) {
      const salt = await bcrypt.genSalt(12);
      const hashedPassword = await bcrypt.hash('Hackin', salt);
      
      const admin = new User({
        nom: 'CSE Admin',
        email: adminEmail,
        password: hashedPassword,
        metier: 'Administrateur',
        role: 'admin',
        verified: true
      });
      
      await admin.save();
      console.log('🛡️ Compte Admin créé: cse@esi.dz / Hackin');
    }
  } catch (err) {
    console.error('Erreur seeding admin:', err);
  }
}

const userSchema = new mongoose.Schema({
  nom: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  nationalite: String,
  telephone: String,
  metier: { type: String, required: true },
  experience: Number,
  institution: String,
  disponibilite: String,
  langues: [String],
  portfolio: String,
  motivation: String,
  localisation: String,
  verified: { type: Boolean, default: false },
  role: { type: String, default: 'volunteer', enum: ['volunteer', 'admin'] },
  photoId: String,
  skills: [String],
  securityQuestion: { type: String }, 
  securityAnswer: { type: String },   
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

const projectSchema = new mongoose.Schema({
  titre: String,
  description: String,
  quartier: String,
  metiersBesoin: [String],
  status: { type: String, default: 'ouvert' },
  prosAssigned: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const Project = mongoose.model('Project', projectSchema);

const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ success: false, msg: 'Token manquant' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'votre_secret_jwt_dev');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ success: false, msg: 'Token invalide' });
  }
};

app.use(express.static(path.join(__dirname, '../frontend')));

// Limiteur de débit pour l'hébergement (5 inscriptions par heure par IP)
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 heure
  max: 5, 
  message: { success: false, msg: "Trop de tentatives, veuillez réessayer plus tard." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/auth/signup', 
  signupLimiter,
  upload.single('photoId'),
  [
    body('nom').trim().notEmpty().withMessage('Le nom est requis').escape(),
    body('email').isEmail().normalizeEmail().withMessage('Email invalide'),
    body('nationalite').optional().trim().escape(),
    body('telephone').optional().trim().escape(),
    body('experience').optional().isNumeric(),
    body('institution').optional().trim().escape(),
    body('disponibilite').optional().trim().escape(),
    body('langues').optional().trim().escape(),
    body('portfolio').optional().trim().isURL().withMessage('Lien invalide'),
    body('motivation').optional().trim().escape(),
    body('localisation').optional().trim().escape(),
    body('skills').optional().trim().escape(),
    body('securityAnswer').optional().trim().escape(), // Protection réponse secrète
    body('password')
      .isLength({ min: 10 }).withMessage('Le mot de passe doit contenir au moins 10 caractères')
      .matches(/[A-Z]/).withMessage('Le mot de passe doit contenir une majuscule')
      .matches(/[0-9]/).withMessage('Le mot de passe doit contenir un chiffre')
      .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Le mot de passe doit contenir un caractère spécial'),
    body('metier').trim().notEmpty().withMessage('Le métier est requis').escape()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      
      const { recaptchaToken } = req.body;
    
      // Utilisation de la clé secrète de TEST. Remplacez par une clé secrète v2 valide pour la production.
      const secretKey = process.env.RECAPTCHA_SECRET_KEY || '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';
      
     
      if (recaptchaToken) {
        const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaToken}`;
        
        const isHuman = await new Promise((resolve) => {
          https.get(verifyUrl, (apiRes) => {
            let data = '';
            apiRes.on('data', chunk => data += chunk);
            apiRes.on('end', () => {
              try {
                const json = JSON.parse(data);
                resolve(json.success);
              } catch (e) { resolve(false); }
            });
          }).on('error', () => resolve(false));
        });

        if (!isHuman) {
           // En mode dev si la clé n'est pas configurée, ça va échouer. 
           // On renvoie une erreur explicite.
           return res.status(400).json({ success: false, msg: 'Validation reCAPTCHA échouée. Bot détecté ou clé invalide.' });
        }
      } else {
         // Si le token est absent, on peut choisir de bloquer ou non.
         return res.status(400).json({ success: false, msg: 'Veuillez valider le captcha.' });
      }
      // Fin validation reCAPTCHA

      // Validation stricte du fichier (Anti-Malware basique)
      if (req.file) {
        try {
          const isValidFile = await checkMagicNumbers(req.file.path);
          if (!isValidFile) {
            // Suppression immédiate du fichier suspect
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ success: false, msg: 'Fichier corrompu ou format non autorisé (Magic Bytes invalid).' });
          }
        } catch (fileErr) {
          console.error("Erreur lecture fichier:", fileErr);
          // Suppression par précaution
          if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
          return res.status(500).json({ success: false, msg: 'Erreur lors de l\'analyse du fichier.' });
        }
      }

      const { 
        nom, 
        email, 
        password, 
        metier, 
        nationalite, 
        telephone, 
        experience, 
        institution,
        disponibilite,
        langues,
        portfolio, 
        motivation, 
        localisation,
        skills,
        securityQuestion,
        securityAnswer
      } = req.body;

      const userExists = await User.findOne({ email });
      if (userExists) {
        return res.status(400).json({ 
          success: false, 
          msg: 'Un compte avec cet email existe déjà' 
        });
      }

      const salt = await bcrypt.genSalt(12);
      const hashedPassword = await bcrypt.hash(password, salt);
      
      let hashedAnswer = null;
      if (securityAnswer) {
          hashedAnswer = await bcrypt.hash(securityAnswer.toLowerCase().trim(), salt);
      }

      const skillsArray = skills ? skills.split(',').map(skill => skill.trim()) : [];
      const languesArray = langues ? langues.split(',').map(lang => lang.trim()) : [];

      const user = new User({
        nom,
        email,
        password: hashedPassword,
        metier,
        nationalite,
        telephone,
        experience: experience ? parseInt(experience) : 0,
        institution,
        disponibilite,
        langues: languesArray,
        portfolio,
        motivation,
        localisation,
        skills: skillsArray,
        photoId: req.file ? req.file.path : null,
        securityQuestion: securityQuestion || null,
        securityAnswer: hashedAnswer || null
      });

      await user.save();

      const token = jwt.sign(
        { id: user._id, email: user.email },
        process.env.JWT_SECRET || 'votre_secret_jwt_dev',
        { expiresIn: '2h' }
      );

      const userResponse = {
        id: user._id,
        nom: user.nom,
        email: user.email,
        metier: user.metier,
        nationalite: user.nationalite,
        verified: user.verified
      };

      res.status(201).json({
        success: true,
        msg: 'Inscription réussie',
        token,
        user: userResponse
      });

    } catch (err) {
      console.error('Erreur inscription:', err);
      res.status(500).json({ 
        success: false, 
        msg: 'Erreur serveur lors de l\'inscription' 
      });
    }
  }
);

app.post('/api/auth/get-security-question', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        
        if (!user || !user.securityQuestion) {
            return res.status(404).json({ success: false, msg: "Compte introuvable ou pas de question configurée." });
        }
        
        res.json({ success: true, question: user.securityQuestion });
    } catch (err) {
        res.status(500).json({ success: false, msg: "Erreur serveur" });
    }
});

app.post('/api/auth/reset-password', 
  [
    body('email').isEmail(),
    body('newPassword').isLength({ min: 10 }).withMessage('Mot de passe trop court')
  ],
  async (req, res) => {
    try {
        const { email, answer, newPassword } = req.body;
        const user = await User.findOne({ email });

        if (!user || !user.securityAnswer) {
             return res.status(400).json({ success: false, msg: "Opération impossible." });
        }

        const isMatch = await bcrypt.compare(answer.toLowerCase().trim(), user.securityAnswer);
        if (!isMatch) {
             return res.status(400).json({ success: false, msg: "Réponse incorrecte." });
        }

        const salt = await bcrypt.genSalt(12);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();

        res.json({ success: true, msg: "Mot de passe modifié avec succès." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, msg: "Erreur serveur" });
    }
});

app.post('/api/auth/login',
  [
    body('email').isEmail().normalizeEmail().withMessage('Email invalide'),
    body('password').notEmpty().withMessage('Mot de passe requis')
  ],
  async (req, res) => {
    await new Promise(resolve => setTimeout(resolve, 500));

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { email, password } = req.body;

      const user = await User.findOne({ email });
      
      const invalidMsg = 'Identifiants invalides';

      if (!user) {
        await bcrypt.compare("dummy_password", "$2a$12$GwF9j6.5eN103/5.5./5.5.5.5.5.5.5.5.5.5.5.5."); 
        return res.status(400).json({ success: false, msg: invalidMsg });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).json({ success: false, msg: invalidMsg });
      }

      const token = jwt.sign(
        { id: user._id, email: user.email, role: user.role }, 
        process.env.JWT_SECRET || 'votre_secret_jwt_dev',
        { expiresIn: '2h' } 
      );

      console.log(`[SEC] Login Success: ${email} @ ${new Date().toISOString()}`);

      const userResponse = {
        id: user._id,
        nom: user.nom,
        email: user.email,
        metier: user.metier,
        nationalite: user.nationalite,
        verified: user.verified,
        role: user.role
      };

      res.json({
        success: true,
        msg: 'Connexion réussie',
        token,
        user: userResponse
      });

    } catch (err) {
      console.error('Erreur connexion:', err);
      res.status(500).json({ 
        success: false, 
        msg: 'Erreur serveur lors de la connexion' 
      });
    }
  }
);

app.get('/api/users/by-profession/:metier', async (req, res) => {
  try {
    const { metier } = req.params;
    const users = await User.find({ 
      metier: new RegExp(metier, 'i'),
      verified: true 
    }).select('-password').limit(20);

    res.json({
      success: true,
      count: users.length,
      users
    });
  } catch (err) {
    console.error('Erreur récupération utilisateurs:', err);
    res.status(500).json({ 
      success: false, 
      msg: 'Erreur lors de la récupération des utilisateurs' 
    });
  }
});

app.get('/api/professions', async (req, res) => {
  try {
    const professions = await User.distinct('metier');
    res.json({
      success: true,
      professions: professions.filter(p => p).sort()
    });
  } catch (err) {
    console.error('Erreur récupération métiers:', err);
    res.status(500).json({ 
      success: false, 
      msg: 'Erreur lors de la récupération des métiers' 
    });
  }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        msg: 'Utilisateur non trouvé' 
      });
    }
    res.json({
      success: true,
      user
    });
  } catch (err) {
    console.error('Erreur récupération utilisateur:', err);
    res.status(500).json({ 
      success: false, 
      msg: 'Erreur lors de la récupération de l\'utilisateur' 
    });
  }
});

app.get('/api/projects', async (req, res) => {
  try {
    const projects = await Project.find()
      .populate('prosAssigned', 'nom metier')
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      count: projects.length,
      projects
    });
  } catch (err) {
    console.error('Erreur récupération projets:', err);
    res.status(500).json({ 
      success: false, 
      msg: 'Erreur lors de la récupération des projets' 
    });
  }
});

app.get('/api/admin/overview', auth, async (req, res) => {
  try {
    const users = await User.find({ role: { $ne: 'admin' } }).select('-password');
    const projectsData = await Project.find();

    const randomGazaCoords = () => ({
      lat: 31.25 + (Math.random() * 0.30),
      lng: 34.25 + (Math.random() * 0.25)
    });

    const missionsTitles = [
      "Réfection Hôpital Al-Shifa (Aile Nord)", "Approvisionnement Eau Potable - Zone B",
      "Déploiement Starlink d'urgence", "Classe Mobile - École UNRWA #4",
      "Support Psychologique - Camp Rafah", "Analyse Structurelle Bâtiment 7",
      "Installation Panneaux Solaires", "Tri Médical Urgence"
    ];

    const enrichedUsers = users.map(u => {
      const coords = randomGazaCoords();
      const isActive = Math.random() > 0.15; 
      
      return {
        _id: u._id,
        nom: u.nom,
        metier: u.metier,
        email: u.email,
        location: { ...coords },
        status: isActive ? 'Opérationnel' : 'Repos',
        mission: missionsTitles[Math.floor(Math.random() * missionsTitles.length)],
        progress: isActive ? Math.floor(Math.random() * 60) + 20 : 0, 
        lastPing: new Date().toISOString(),
        batteryLevel: Math.floor(Math.random() * 40) + 60 
      };
    });

    if (enrichedUsers.length < 10) {
      const ghostRoles = ['Médecin Urgentiste', 'Ingénieur BTP', 'Logisticien', 'Secouriste', 'Tech Lead'];
      const ghostNames = ['Amira K.', 'Tariq S.', 'Leila M.', 'Youssef B.', 'Farid H.', 'Nour D.'];
      
      for(let i=0; i < 15; i++) {
        const coords = randomGazaCoords();
        enrichedUsers.push({
          _id: `ghost-${i}`,
          nom: ghostNames[Math.floor(Math.random() * ghostNames.length)] + ` (Unité ${i+1})`,
          metier: ghostRoles[Math.floor(Math.random() * ghostRoles.length)],
          email: `unit-${i}@hackin.sys`,
          location: coords,
          status: 'Opérationnel',
          mission: missionsTitles[Math.floor(Math.random() * missionsTitles.length)],
          progress: Math.floor(Math.random() * 90) + 10,
          lastPing: new Date().toISOString(),
          batteryLevel: Math.floor(Math.random() * 50) + 50
        });
      }
    }

    res.json({
      success: true,
      kpi: {
        totalVolunteers: enrichedUsers.length,
        activeMissions: projectsData.length > 0 ? projectsData.length : 12,
        criticalAlerts: Math.floor(Math.random() * 3),
        resourcesDeployed: '84%',
      },
      users: enrichedUsers,
      zones: [ 
        { name: "Zone Rouge (Nord)", lat: 31.50, lng: 34.46, radius: 3000, type: 'danger' },
        { name: "Safe Zone (Centre)", lat: 31.35, lng: 34.30, radius: 5000, type: 'safe' }
      ]
    });

  } catch (err) {
    console.error("Dashboard Error:", err);
    res.status(500).json({ success: false, msg: 'Erreur Dashboard' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend', 'index.html'));
});

app.get('/ask', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend', 'Ask.html'));
});

app.get('/community', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend', 'community.html'));
});

app.get('/ask_admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend', 'ask_admin.html'));
});

app.get('/centre_formation', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend', 'centre_formation.html'));
});

app.get('/admin', (req, res) => {
  const adminPath = path.join(__dirname, '../frontend', 'admin.html');
  if (fs.existsSync(adminPath)) {
    res.sendFile(adminPath);
  } else {
    res.send('<h1 style="color:white; background:black; padding:20px;">🚧 Dashboard Admin en construction...</h1>');
  }
});

app.use(/\/api\/(.*)/, (req, res) => {
  res.status(404).json({ 
    success: false, 
    msg: 'Route API non trouvée' 
  });
});

app.get(/(.*)/, (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error('Erreur globale:', err);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ 
      success: false, 
      msg: `Erreur upload: ${err.message}` 
    });
  }
  
  res.status(500).json({ 
    success: false, 
    msg: 'Erreur serveur interne',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
  console.log(`📁 Dossier static: ${path.join(__dirname, '../frontend')}`);
});