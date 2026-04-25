#!/usr/bin/env python3
"""
NIDS Model Training Script
Trains KNN, Random Forest, CNN, LSTM on NSL-KDD dataset
Usage: python3 train_models.py [path/to/nsl-kdd.csv]
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
import warnings
warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

# ── NSL-KDD schema ────────────────────────────────────────────────────────────
COLUMNS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty_level'
]
CAT_COLS = ['protocol_type', 'service', 'flag']

ATTACK_MAP = {
    'normal':'Normal',
    'neptune':'DoS','back':'DoS','land':'DoS','pod':'DoS','smurf':'DoS',
    'teardrop':'DoS','mailbomb':'DoS','apache2':'DoS','processtable':'DoS','udpstorm':'DoS',
    'ipsweep':'Probe','nmap':'Probe','portsweep':'Probe','satan':'Probe','mscan':'Probe','saint':'Probe',
    'ftp_write':'R2L','guess_passwd':'R2L','imap':'R2L','multihop':'R2L','phf':'R2L',
    'spy':'R2L','warezclient':'R2L','warezmaster':'R2L','sendmail':'R2L','named':'R2L',
    'snmpgetattack':'R2L','snmpguess':'R2L','xlock':'R2L','xsnoop':'R2L','worm':'R2L',
    'buffer_overflow':'U2R','loadmodule':'U2R','perl':'U2R','rootkit':'U2R',
    'httptunnel':'U2R','ps':'U2R','sqlattack':'U2R','xterm':'U2R'
}

def load_dataset(filepath):
    print(f"\n📂 Loading dataset: {filepath}")
    df = pd.read_csv(filepath, header=None, names=COLUMNS)
    df = df.drop('difficulty_level', axis=1)
    df['label'] = df['label'].str.replace('.','',regex=False).str.strip().str.lower()

    # Binary label
    df['binary_label'] = (df['label'] != 'normal').astype(int)

    # Multiclass label
    df['multi_label'] = df['label'].map(ATTACK_MAP).fillna('Unknown')

    # Encode categoricals
    le_dict = {}
    for col in CAT_COLS:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        le_dict[col] = le

    feature_cols = [c for c in df.columns if c not in ['label','binary_label','multi_label']]
    X = df[feature_cols].values.astype(np.float32)
    y_bin = df['binary_label'].values

    le_multi = LabelEncoder()
    y_multi  = le_multi.fit_transform(df['multi_label'].values)

    # Scale
    scaler  = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Save artifacts
    joblib.dump(scaler,       os.path.join(MODELS_DIR, 'scaler.pkl'))
    joblib.dump(le_dict,      os.path.join(MODELS_DIR, 'label_encoders.pkl'))
    joblib.dump(le_multi,     os.path.join(MODELS_DIR, 'multi_label_encoder.pkl'))
    joblib.dump(feature_cols, os.path.join(MODELS_DIR, 'feature_cols.pkl'))

    print(f"   ✅ {len(df):,} samples | {len(feature_cols)} features")
    print(f"   Binary  → Normal: {int((y_bin==0).sum()):,}  Attack: {int((y_bin==1).sum()):,}")
    classes, counts = np.unique(le_multi.inverse_transform(y_multi), return_counts=True)
    for c,n in zip(classes, counts):
        print(f"   Multi   → {c}: {n:,}")
    print(f"   Classes saved to {MODELS_DIR}")

    return X_scaled, y_bin, y_multi, le_multi, feature_cols

def train_knn(X_tr, y_tr_bin, y_tr_multi):
    print("\n🔵 Training KNN ...")
    knn_b = KNeighborsClassifier(n_neighbors=5, n_jobs=-1)
    knn_b.fit(X_tr, y_tr_bin)
    joblib.dump(knn_b, os.path.join(MODELS_DIR, 'knn_binary_class.sav'))
    print("   ✅ knn_binary_class.sav")

    knn_m = KNeighborsClassifier(n_neighbors=5, n_jobs=-1)
    knn_m.fit(X_tr, y_tr_multi)
    joblib.dump(knn_m, os.path.join(MODELS_DIR, 'knn_multi_class.sav'))
    print("   ✅ knn_multi_class.sav")
    return knn_b, knn_m

def train_rf(X_tr, y_tr_bin, y_tr_multi):
    print("\n🌲 Training Random Forest ...")
    rf_b = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_b.fit(X_tr, y_tr_bin)
    joblib.dump(rf_b, os.path.join(MODELS_DIR, 'random_forest_binary_class.sav'))
    print("   ✅ random_forest_binary_class.sav")

    rf_m = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_m.fit(X_tr, y_tr_multi)
    joblib.dump(rf_m, os.path.join(MODELS_DIR, 'random_forest_multi_class.sav'))
    print("   ✅ random_forest_multi_class.sav")
    return rf_b, rf_m

def build_cnn(n_features, n_classes, binary=True):
    import tensorflow as tf
    from tensorflow.keras import layers, models
    inp = tf.keras.Input(shape=(n_features,))
    x   = layers.Reshape((n_features,1))(inp)
    x   = layers.Conv1D(64,3,activation='relu',padding='same')(x)
    x   = layers.Conv1D(128,3,activation='relu',padding='same')(x)
    x   = layers.MaxPooling1D(2)(x)
    x   = layers.Dropout(0.3)(x)
    x   = layers.Conv1D(64,3,activation='relu',padding='same')(x)
    x   = layers.GlobalAveragePooling1D()(x)
    x   = layers.Dense(128,activation='relu')(x)
    x   = layers.Dropout(0.3)(x)
    x   = layers.Dense(64,activation='relu')(x)
    if binary:
        out = layers.Dense(1,activation='sigmoid')(x)
        model = models.Model(inp, out)
        model.compile(optimizer='adam',loss='binary_crossentropy',metrics=['accuracy'])
    else:
        out = layers.Dense(n_classes,activation='softmax')(x)
        model = models.Model(inp, out)
        model.compile(optimizer='adam',loss='sparse_categorical_crossentropy',metrics=['accuracy'])
    return model

def build_lstm(n_features, n_classes, binary=True):
    import tensorflow as tf
    from tensorflow.keras import layers, models
    inp = tf.keras.Input(shape=(n_features,))
    x   = layers.Reshape((n_features,1))(inp)
    x   = layers.LSTM(128, return_sequences=True)(x)
    x   = layers.Dropout(0.3)(x)
    x   = layers.LSTM(64)(x)
    x   = layers.Dropout(0.3)(x)
    x   = layers.Dense(64,activation='relu')(x)
    if binary:
        out = layers.Dense(1,activation='sigmoid')(x)
        model = models.Model(inp,out)
        model.compile(optimizer='adam',loss='binary_crossentropy',metrics=['accuracy'])
    else:
        out = layers.Dense(n_classes,activation='softmax')(x)
        model = models.Model(inp,out)
        model.compile(optimizer='adam',loss='sparse_categorical_crossentropy',metrics=['accuracy'])
    return model

def train_deep(X_tr, X_te, y_tr_bin, y_te_bin, y_tr_multi, y_te_multi, n_classes):
    import tensorflow as tf
    n_features = X_tr.shape[1]
    es = tf.keras.callbacks.EarlyStopping(monitor='val_loss',patience=3,restore_best_weights=True,verbose=0)

    print("\n🧠 Training CNN Binary ...")
    m = build_cnn(n_features,2,binary=True)
    m.fit(X_tr,y_tr_bin,epochs=20,batch_size=512,validation_split=0.1,callbacks=[es],verbose=1)
    m.save(os.path.join(MODELS_DIR,'cnn_binary_class.h5'))
    print("   ✅ cnn_binary_class.h5")

    print("\n🧠 Training CNN Multiclass ...")
    m = build_cnn(n_features,n_classes,binary=False)
    m.fit(X_tr,y_tr_multi,epochs=20,batch_size=512,validation_split=0.1,callbacks=[es],verbose=1)
    m.save(os.path.join(MODELS_DIR,'cnn_multi_class.h5'))
    print("   ✅ cnn_multi_class.h5")

    print("\n⚡ Training LSTM Binary ...")
    m = build_lstm(n_features,2,binary=True)
    m.fit(X_tr,y_tr_bin,epochs=20,batch_size=512,validation_split=0.1,callbacks=[es],verbose=1)
    m.save(os.path.join(MODELS_DIR,'lstm_binary_class.h5'))
    print("   ✅ lstm_binary_class.h5")

    print("\n⚡ Training LSTM Multiclass ...")
    m = build_lstm(n_features,n_classes,binary=False)
    m.fit(X_tr,y_tr_multi,epochs=20,batch_size=512,validation_split=0.1,callbacks=[es],verbose=1)
    m.save(os.path.join(MODELS_DIR,'lstm_multi_class.h5'))
    print("   ✅ lstm_multi_class.h5")

def evaluate(models_tuple, X_te, y_te_bin, y_te_multi, le_multi):
    knn_b, knn_m, rf_b, rf_m = models_tuple
    print("\n" + "="*55)
    print("MODEL EVALUATION ON TEST SET")
    print("="*55)
    for name, model, y_true in [
        ("KNN Binary",           knn_b, y_te_bin),
        ("KNN Multiclass",       knn_m, y_te_multi),
        ("Random Forest Binary", rf_b,  y_te_bin),
        ("Random Forest Multi",  rf_m,  y_te_multi),
    ]:
        acc = accuracy_score(y_true, model.predict(X_te))
        print(f"  {name:30s}  Accuracy: {acc*100:.2f}%")
    print("="*55)

if __name__ == '__main__':
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(BASE_DIR,'dataset','nsl-kdd.csv')

    if not os.path.exists(dataset_path):
        print(f"❌ Dataset not found: {dataset_path}")
        print("   Download NSL-KDD from: https://www.kaggle.com/datasets/hassan06/nslkdd")
        print("   Place the CSV file at: dataset/nsl-kdd.csv")
        sys.exit(1)

    print("="*55)
    print("  NIDS MODEL TRAINING — NSL-KDD DATASET")
    print("="*55)

    X, y_bin, y_multi, le_multi, feat_cols = load_dataset(dataset_path)
    n_classes = len(np.unique(y_multi))

    X_tr, X_te, y_tr_bin, y_te_bin, y_tr_multi, y_te_multi = train_test_split(
        X, y_bin, y_multi, test_size=0.2, random_state=42, stratify=y_bin
    )
    print(f"\n   Train: {len(X_tr):,} | Test: {len(X_te):,}")

    knn_b, knn_m = train_knn(X_tr, y_tr_bin, y_tr_multi)
    rf_b,  rf_m  = train_rf(X_tr, y_tr_bin, y_tr_multi)

    try:
        train_deep(X_tr, X_te, y_tr_bin, y_te_bin, y_tr_multi, y_te_multi, n_classes)
    except ImportError:
        print("\n⚠️  TensorFlow not installed — skipping CNN & LSTM training.")
        print("   Install with: pip3 install tensorflow")
    except Exception as e:
        print(f"\n⚠️  Deep learning training failed: {e}")

    evaluate((knn_b,knn_m,rf_b,rf_m), X_te, y_te_bin, y_te_multi, le_multi)

    print("\n✅ All models saved to:", MODELS_DIR)
    print("   Start the web app with: npm start\n")
