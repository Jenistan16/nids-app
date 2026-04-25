# NIDS.AI — Network Intrusion Detection System

A complete full-stack web application for detecting network intrusions using Machine Learning and Deep Learning models trained on the NSL-KDD dataset.

---

## 🚀 Quick Start (3 steps)

### Step 1 — Install dependencies

```bash
# Node.js packages
npm install

# Python packages
pip3 install -r requirements.txt
```

### Step 2 — Configure environment

```bash
cp .env.example .env
```

Edit `.env` — at minimum set `SESSION_SECRET` to any long random string. MongoDB and Google OAuth are optional for initial testing.

### Step 3 — Run

```bash
npm start
# Visit: http://localhost:3000
```

> ✅ The app works immediately without training models — it uses intelligent simulation mode.
> Train real models when you're ready (see below).

---

## 📋 Full Setup Guide

### Prerequisites

| Tool       | Required Version |
|------------|-----------------|
| Node.js    | 16+             |
| Python     | 3.8+            |
| MongoDB    | 5+ (local or Atlas) |

### Verify your setup

```bash
node setup.js
```

This checks everything: Node.js, Python, packages, files, .env, models, dataset.

### Install Python packages

```bash
pip3 install -r requirements.txt
```

For GPU-accelerated training (optional):
```bash
pip3 install tensorflow-gpu
```

### MongoDB

**Option A — Local MongoDB:**
```bash
# macOS:  brew install mongodb-community && brew services start mongodb-community
# Ubuntu: sudo apt install mongodb && sudo systemctl start mongod
# Windows: Download from https://www.mongodb.com/try/download/community
```

**Option B — MongoDB Atlas (free cloud):**
1. Sign up at https://cloud.mongodb.com
2. Create a free cluster
3. Get your connection string
4. Set `MONGODB_URI=mongodb+srv://...` in `.env`

### Google OAuth (optional)

1. Go to https://console.cloud.google.com
2. Create project → APIs & Services → Credentials
3. Create OAuth 2.0 Client ID (Web application)
4. Add Authorized redirect URI: `http://localhost:3000/auth/google/callback`
5. Copy Client ID and Secret to `.env`

---

## 🧠 Training ML Models

### Get the dataset

Download NSL-KDD from Kaggle: https://www.kaggle.com/datasets/hassan06/nslkdd

Place the CSV file at: `dataset/nsl-kdd.csv`

The CSV should have no header row and 43 columns (41 features + label + difficulty).

### Train all models

```bash
python3 python/train_models.py dataset/nsl-kdd.csv
# Or: npm run train
```

**Expected training time:**
| Model             | CPU Time    |
|-------------------|-------------|
| KNN               | ~3–8 min    |
| Random Forest     | ~5–15 min   |
| CNN               | ~15–30 min  |
| LSTM              | ~20–40 min  |

**Expected accuracy on NSL-KDD test set:**
| Model             | Binary    | Multiclass |
|-------------------|-----------|------------|
| KNN (k=5)         | ~97%      | ~97%       |
| Random Forest     | ~99.5%    | ~99%       |
| CNN               | ~98%      | ~97.5%     |
| LSTM              | ~98.5%    | ~97.5%     |

---

## 📁 Project Structure

```
nids-app/
├── app.js                       Main Express server
├── setup.js                     Setup verification script
├── package.json
├── requirements.txt             Python dependencies
├── .env                         Environment variables (create from .env.example)
├── .env.example                 Template
├── Dockerfile
├── docker-compose.yml
│
├── config/
│   └── passport.js              Local + Google OAuth strategies
│
├── middleware/
│   └── auth.js                  Route protection
│
├── models/
│   ├── User.js                  MongoDB User schema
│   ├── Prediction.js            MongoDB Prediction schema
│   └── *.sav / *.h5 / *.pkl    (generated after training)
│
├── python/
│   ├── train_models.py          Train all 8 models
│   ├── nids_parameter_prediction.py   Single prediction
│   ├── nids_random_row_prediction.py  Random dataset row
│   └── nids_csv_prediction.py         Batch CSV prediction
│
├── routes/
│   ├── index.js
│   ├── auth.js                  Login / signup / Google OAuth / logout
│   ├── dashboard.js             Dashboard + history
│   └── predict.js               All 3 prediction types
│
├── views/
│   ├── landing.ejs              Landing page
│   ├── login.ejs                Login form
│   ├── signup.ejs               Register form
│   ├── dashboard.ejs            Main dashboard with charts
│   ├── prediction.ejs           3-tab prediction form
│   ├── result.ejs               Single + batch result display
│   ├── history.ejs              Paginated prediction history
│   └── error.ejs                404/500 error page
│
├── public/
│   └── css/main.css
│
├── uploads/                     CSV uploads (auto-created)
├── dataset/                     Place nsl-kdd.csv here
└── models/                      Trained model files (auto-created)
```

---

## 🔐 Authentication

- **Local login**: Email + bcrypt-hashed password
- **Google OAuth 2.0**: One-click Google sign-in (requires credentials in .env)
- **Session-based**: 24-hour sessions with secure HTTP-only cookies
- Both methods work independently — Google OAuth is optional

---

## 🎯 Attack Categories

| Category | Description                                    | Examples                         |
|----------|------------------------------------------------|----------------------------------|
| Normal   | Legitimate network traffic                     | —                                |
| DoS      | Overwhelm resources to deny service            | neptune, smurf, teardrop, back   |
| Probe    | Scan/survey network for vulnerabilities        | ipsweep, nmap, portsweep, satan  |
| R2L      | Unauthorised remote access to local machine    | guess_passwd, ftp_write, imap    |
| U2R      | Escalate from normal user to root              | buffer_overflow, rootkit, perl   |

---

## 🐳 Docker Deployment

```bash
# Build and start everything
docker-compose up -d

# View logs
docker-compose logs -f app

# Stop
docker-compose down
```

The docker-compose.yml starts the Node.js app + MongoDB automatically.

---

## 📊 Features

| Feature                | Status |
|------------------------|--------|
| Local login + signup   | ✅     |
| Google OAuth 2.0       | ✅ (requires .env config) |
| Parameter prediction   | ✅     |
| Random row prediction  | ✅     |
| CSV batch prediction   | ✅     |
| KNN model              | ✅     |
| Random Forest model    | ✅     |
| CNN model              | ✅     |
| LSTM model             | ✅     |
| Binary classification  | ✅     |
| Multiclass (5 classes) | ✅     |
| Prediction history     | ✅     |
| Dashboard charts       | ✅     |
| Simulation fallback    | ✅ (works without trained models) |
| Error pages (404/500)  | ✅     |
| Docker support         | ✅     |

---

## ⚙️ Environment Variables

| Variable              | Required | Description                                        |
|-----------------------|----------|----------------------------------------------------|
| `PORT`                | No       | Server port (default: 3000)                        |
| `NODE_ENV`            | No       | `development` or `production`                      |
| `MONGODB_URI`         | No*      | MongoDB connection string (*defaults to localhost) |
| `SESSION_SECRET`      | Yes      | Random secret string (32+ chars)                  |
| `GOOGLE_CLIENT_ID`    | No       | Google OAuth Client ID                             |
| `GOOGLE_CLIENT_SECRET`| No       | Google OAuth Client Secret                         |
| `GOOGLE_CALLBACK_URL` | No       | OAuth redirect URL                                 |

