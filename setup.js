#!/usr/bin/env node
/**
 * NIDS Setup Verification Script
 * Run: node setup.js
 * Checks all dependencies and configuration are correct
 */

const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const GREEN  = '\x1b[32m';
const RED    = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN   = '\x1b[36m';
const RESET  = '\x1b[0m';
const BOLD   = '\x1b[1m';

let errors = 0, warnings = 0;

function ok(msg)   { console.log(`  ${GREEN}✅${RESET} ${msg}`); }
function fail(msg) { console.log(`  ${RED}❌${RESET} ${msg}`); errors++; }
function warn(msg) { console.log(`  ${YELLOW}⚠️ ${RESET} ${msg}`); warnings++; }
function info(msg) { console.log(`  ${CYAN}ℹ️ ${RESET} ${msg}`); }

console.log(`\n${BOLD}=========================================${RESET}`);
console.log(`${BOLD}  NIDS.AI Setup Verification${RESET}`);
console.log(`${BOLD}=========================================${RESET}\n`);

// ── 1. Node.js version ────────────────────────────────────────────────────────
console.log(`${BOLD}[1] Node.js${RESET}`);
const nodeVer = parseInt(process.version.replace('v','').split('.')[0]);
if (nodeVer >= 16) ok(`Node.js ${process.version}`);
else fail(`Node.js ${process.version} — requires v16+`);

// ── 2. Python ─────────────────────────────────────────────────────────────────
console.log(`\n${BOLD}[2] Python${RESET}`);
['python3','python'].forEach(cmd => {
  try {
    const ver = execSync(`${cmd} --version 2>&1`).toString().trim();
    ok(`${cmd}: ${ver}`);
  } catch {
    warn(`${cmd} not found`);
  }
});

// ── 3. Python packages ────────────────────────────────────────────────────────
console.log(`\n${BOLD}[3] Python Packages${RESET}`);
const pyPkgs = ['numpy','pandas','sklearn','joblib'];
pyPkgs.forEach(pkg => {
  try {
    execSync(`python3 -c "import ${pkg}" 2>&1`);
    ok(pkg);
  } catch {
    try {
      execSync(`python -c "import ${pkg}" 2>&1`);
      ok(pkg + ' (via python)');
    } catch {
      fail(`${pkg} not installed — run: pip3 install -r requirements.txt`);
    }
  }
});

// TensorFlow optional
try {
  execSync('python3 -c "import tensorflow" 2>&1');
  ok('tensorflow');
} catch {
  warn('tensorflow not installed — CNN/LSTM models unavailable (KNN+RF will still work)');
  warn('Install: pip3 install tensorflow');
}

// ── 4. Node packages ──────────────────────────────────────────────────────────
console.log(`\n${BOLD}[4] Node Packages${RESET}`);
const nodePkgs = ['express','mongoose','passport','ejs','multer','bcryptjs','connect-flash'];
nodePkgs.forEach(pkg => {
  try {
    require.resolve(pkg);
    ok(pkg);
  } catch {
    fail(`${pkg} missing — run: npm install`);
  }
});

// ── 5. Required files ─────────────────────────────────────────────────────────
console.log(`\n${BOLD}[5] Project Files${RESET}`);
const required = [
  'app.js','package.json','requirements.txt',
  'config/passport.js','middleware/auth.js',
  'models/User.js','models/Prediction.js',
  'routes/index.js','routes/auth.js','routes/dashboard.js','routes/predict.js',
  'views/landing.ejs','views/login.ejs','views/signup.ejs',
  'views/dashboard.ejs','views/prediction.ejs','views/result.ejs',
  'views/history.ejs','views/error.ejs',
  'python/train_models.py','python/nids_parameter_prediction.py',
  'python/nids_random_row_prediction.py','python/nids_csv_prediction.py'
];
required.forEach(f => {
  if (fs.existsSync(path.join(__dirname, f))) ok(f);
  else fail(`Missing: ${f}`);
});

// ── 6. Directories ────────────────────────────────────────────────────────────
console.log(`\n${BOLD}[6] Directories${RESET}`);
['uploads','models','dataset'].forEach(d => {
  const p = path.join(__dirname, d);
  if (!fs.existsSync(p)) { fs.mkdirSync(p,{recursive:true}); ok(`${d}/ (created)`); }
  else ok(d + '/');
});

// ── 7. .env file ──────────────────────────────────────────────────────────────
console.log(`\n${BOLD}[7] Environment Config${RESET}`);
if (fs.existsSync('.env')) {
  require('dotenv').config();
  ok('.env file found');
  if (process.env.MONGODB_URI)      ok('MONGODB_URI set');
  else warn('MONGODB_URI not set — will default to mongodb://localhost:27017/nids_db');
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 16) ok('SESSION_SECRET set');
  else warn('SESSION_SECRET not set or too short — using fallback (not safe for production)');
  if (process.env.GOOGLE_CLIENT_ID && !process.env.GOOGLE_CLIENT_ID.includes('your_')) ok('GOOGLE_CLIENT_ID set');
  else warn('GOOGLE_CLIENT_ID not configured — Google login will not work');
} else {
  warn('.env file not found — copy .env.example to .env and fill in values');
}

// ── 8. Trained models ─────────────────────────────────────────────────────────
console.log(`\n${BOLD}[8] Trained Models${RESET}`);
const models = [
  'knn_binary_class.sav','knn_multi_class.sav',
  'random_forest_binary_class.sav','random_forest_multi_class.sav',
  'cnn_binary_class.h5','cnn_multi_class.h5',
  'lstm_binary_class.h5','lstm_multi_class.h5',
  'scaler.pkl','multi_label_encoder.pkl'
];
let modelsFound = 0;
models.forEach(m => {
  if (fs.existsSync(path.join(__dirname,'models',m))) { ok(m); modelsFound++; }
  else warn(`${m} not found (train with: python3 python/train_models.py)`);
});
if (modelsFound === 0) {
  info('No models trained yet — simulation mode will be used for predictions');
  info('To train: python3 python/train_models.py dataset/nsl-kdd.csv');
}

// ── 9. Dataset ────────────────────────────────────────────────────────────────
console.log(`\n${BOLD}[9] Dataset${RESET}`);
const dsPath = path.join(__dirname,'dataset','nsl-kdd.csv');
if (fs.existsSync(dsPath)) {
  const size = (fs.statSync(dsPath).size / 1024 / 1024).toFixed(1);
  ok(`nsl-kdd.csv found (${size} MB)`);
} else {
  warn('nsl-kdd.csv not found in dataset/');
  info('Download from: https://www.kaggle.com/datasets/hassan06/nslkdd');
  info('Simulation mode will still work without the dataset');
}

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n${BOLD}=========================================${RESET}`);
if (errors === 0 && warnings === 0) {
  console.log(`${GREEN}${BOLD}  ✅ Everything looks good! Run: npm start${RESET}`);
} else if (errors === 0) {
  console.log(`${YELLOW}${BOLD}  ⚠️  ${warnings} warning(s) — app will still run${RESET}`);
  console.log(`${GREEN}  Run: npm start${RESET}`);
} else {
  console.log(`${RED}${BOLD}  ❌ ${errors} error(s) must be fixed before running${RESET}`);
  if (warnings > 0) console.log(`${YELLOW}  Also ${warnings} warning(s)${RESET}`);
}
console.log(`${BOLD}=========================================${RESET}\n`);
