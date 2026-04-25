const express = require('express');
const router = express.Router();
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { ensureAuthenticated } = require('../middleware/auth');
const Prediction = require('../models/Prediction');

// ─── Multer CSV Upload ────────────────────────────────────────────────────────
const uploadsDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_'))
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'text/csv' || file.originalname.toLowerCase().endsWith('.csv'))
      return cb(null, true);
    cb(new Error('Only .csv files are allowed'));
  }
});

// ─── Python Runner ────────────────────────────────────────────────────────────
function runPython(scriptName, args) {
  return new Promise((resolve, reject) => {
    const scriptPath = path.resolve(__dirname, '..', 'python', scriptName);

    // Try python3 first, fall back to python
    const pythonBin = process.platform === 'win32' ? 'python' : 'python3';
    const child = spawn(pythonBin, [scriptPath, ...args], {
  cwd: path.join(__dirname, '..')
});

    let output = '';
    let errOutput = '';

    child.stdout.on('data', data => { output += data.toString(); });
    child.stderr.on('data', data => { errOutput += data.toString(); });

    child.on('error', (err) => {
      // Try fallback python if python3 fails
      if (err.code === 'ENOENT') {
        const fallback = spawn('python', [scriptPath, ...args]);
        let fbOut = '', fbErr = '';
        fallback.stdout.on('data', d => { fbOut += d.toString(); });
        fallback.stderr.on('data', d => { fbErr += d.toString(); });
        fallback.on('close', code => {
          if (code !== 0) return reject(new Error(fbErr || 'Python script failed'));
          try { resolve(JSON.parse(fbOut.trim())); }
          catch (e) { reject(new Error('Invalid JSON from Python: ' + fbOut.substring(0, 200))); }
        });
        fallback.on('error', () => reject(new Error('Python not found. Please install Python 3.')));
      } else {
        reject(err);
      }
    });

    child.on('close', code => {
      if (code !== 0) return reject(new Error(errOutput.trim() || 'Python script exited with code ' + code));
      try {
        const trimmed = output.trim();
        if (!trimmed) return reject(new Error('Python returned empty output'));
        resolve(JSON.parse(trimmed));
      } catch (e) {
        reject(new Error('Failed to parse Python output: ' + output.substring(0, 200)));
      }
    });

    // Timeout after 60 seconds
    setTimeout(() => {
      child.kill();
      reject(new Error('Prediction timed out (60s). Models may be too large for this machine.'));
    }, 60000);
  });
}

// ─── GET /predict ─────────────────────────────────────────────────────────────
router.get('/', ensureAuthenticated, (req, res) => {
  res.render('prediction', { user: req.user, error: null });
});

// ─── POST /predict/parameter ──────────────────────────────────────────────────
router.post('/parameter', ensureAuthenticated, async (req, res) => {
  try {
    const { model, classType, ...params } = req.body;

    if (!model || !classType) {
      return res.render('prediction', { user: req.user, error: 'Please select a model and classification type.' });
    }

    const inputStr = JSON.stringify(params);
    const result = await runPython('nids_parameter_prediction.py', [model, classType, inputStr]);

    if (result.error) throw new Error(result.error);

    const prediction = new Prediction({
      userId: req.user._id,
      predictionType: 'parameter',
      model,
      classType,
      inputParameters: params,
      binaryResult: result.binary_result,
      multiclassResult: result.multiclass_result,
      attackProbability: result.probability,
      attackCategory: result.attack_category
    });
    await prediction.save();

    res.render('result', {
      user: req.user,
      result,
      model,
      classType,
      predictionType: 'parameter',
      inputParams: params,
      predictionId: prediction._id,
      csvFileName: null
    });
  } catch (err) {
    console.error('Parameter prediction error:', err.message);
    res.render('prediction', { user: req.user, error: 'Prediction failed: ' + err.message });
  }
});

// ─── POST /predict/random ─────────────────────────────────────────────────────
router.post('/random', ensureAuthenticated, async (req, res) => {
  try {
    const { model, classType } = req.body;

    if (!model || !classType) {
      return res.render('prediction', { user: req.user, error: 'Please select a model and classification type.' });
    }

    const result = await runPython('nids_random_row_prediction.py', [model, classType]);

    if (result.error) throw new Error(result.error);

    const prediction = new Prediction({
      userId: req.user._id,
      predictionType: 'random',
      model,
      classType,
      inputParameters: result.input_row || {},
      binaryResult: result.binary_result,
      multiclassResult: result.multiclass_result,
      attackProbability: result.probability,
      attackCategory: result.attack_category
    });
    await prediction.save();

    res.render('result', {
      user: req.user,
      result,
      model,
      classType,
      predictionType: 'random',
      inputParams: result.input_row || {},
      predictionId: prediction._id,
      csvFileName: null
    });
  } catch (err) {
    console.error('Random prediction error:', err.message);
    res.render('prediction', { user: req.user, error: 'Random prediction failed: ' + err.message });
  }
});

// ─── POST /predict/csv ────────────────────────────────────────────────────────
router.post('/csv', ensureAuthenticated, (req, res) => {
  upload.single('csvFile')(req, res, async (uploadErr) => {
    if (uploadErr) {
      return res.render('prediction', { user: req.user, error: 'Upload error: ' + uploadErr.message });
    }

    try {
      if (!req.file) {
        return res.render('prediction', { user: req.user, error: 'Please select a CSV file to upload.' });
      }

      const { model, classType } = req.body;

      if (!model || !classType) {
        return res.render('prediction', { user: req.user, error: 'Please select a model and classification type.' });
      }

      const result = await runPython('nids_csv_prediction.py', [model, classType, req.file.path]);

      if (result.error) throw new Error(result.error);

      const prediction = new Prediction({
        userId: req.user._id,
        predictionType: 'csv',
        model,
        classType,
        isBatchPrediction: true,
        batchResults: result.predictions || [],
        csvFileName: req.file.originalname
      });
      await prediction.save();

      res.render('result', {
        user: req.user,
        result,
        model,
        classType,
        predictionType: 'csv',
        inputParams: {},
        predictionId: prediction._id,
        csvFileName: req.file.originalname
      });
    } catch (err) {
      console.error('CSV prediction error:', err.message);
      res.render('prediction', { user: req.user, error: 'CSV prediction failed: ' + err.message });
    }
  });
});

module.exports = router;
