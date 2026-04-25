#!/usr/bin/env python3
"""
NIDS Parameter Prediction Script
Usage: python3 nids_parameter_prediction.py <model> <class_type> <json_params>
"""

import sys
import json
import numpy as np
import os
import warnings
warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

# ── Feature columns (41) ──────────────────────────────────────────────────────
FEATURE_COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate'
]

# ── Categorical encodings (consistent with training) ──────────────────────────
PROTOCOL_MAP = {'tcp':0,'udp':1,'icmp':2}
SERVICE_MAP  = {
    'aol':0,'auth':1,'bgp':2,'courier':3,'csnet_ns':4,'ctf':5,'daytime':6,
    'discard':7,'domain':8,'domain_u':9,'echo':10,'eco_i':11,'ecr_i':12,
    'efs':13,'exec':14,'finger':15,'ftp':16,'ftp_data':17,'gopher':18,
    'harvest':19,'hostnames':20,'http':21,'http_2784':22,'http_443':23,
    'http_8001':24,'imap4':25,'IRC':26,'iso_tsap':27,'klogin':28,'kshell':29,
    'ldap':30,'link':31,'login':32,'mtp':33,'name':34,'netbios_dgm':35,
    'netbios_ns':36,'netbios_ssn':37,'netstat':38,'nnsp':39,'nntp':40,
    'ntp_u':41,'other':42,'pm_dump':43,'pop_2':44,'pop_3':45,'printer':46,
    'private':47,'red_i':48,'remote_job':49,'rje':50,'shell':51,'smtp':52,
    'sql_net':53,'ssh':54,'ssrp':55,'sunrpc':56,'supdup':57,'systat':58,
    'telnet':59,'tftp_u':60,'tim_i':61,'time':62,'urh_i':63,'urp_i':64,
    'uucp':65,'uucp_path':66,'vmnet':67,'whois':68,'X11':69,'Z39_50':70
}
FLAG_MAP = {'OTH':0,'REJ':1,'RSTO':2,'RSTOS0':3,'RSTR':4,'S0':5,'S1':6,'S2':7,'S3':8,'SF':9,'SH':10}

LABEL_BINARY = ['Normal','Attack']
LABEL_MULTI  = ['DoS','Normal','Probe','R2L','U2R']  # alphabetical from LabelEncoder

ATTACK_DESCRIPTIONS = {
    'Normal': 'Regular network traffic with no malicious activity detected.',
    'DoS':    'Denial of Service — Flood attack aimed at overwhelming resources to disrupt service availability.',
    'Probe':  'Surveillance/Probing — Network scanning to gather information for potential future attacks.',
    'R2L':    'Remote to Local — Unauthorized remote access attempts to gain local system access.',
    'U2R':    'User to Root — Privilege escalation attempts to gain root/superuser access.',
    'Attack': 'Malicious network activity detected.'
}

# ── Encode input params → numpy array ────────────────────────────────────────
def encode_input(params):
    features = []
    for col in FEATURE_COLS:
        val = params.get(col, 0)
        if col == 'protocol_type':
            val = PROTOCOL_MAP.get(str(val).lower(), 0)
        elif col == 'service':
            val = SERVICE_MAP.get(str(val).lower(), SERVICE_MAP.get(str(val), 42))
        elif col == 'flag':
            val = FLAG_MAP.get(str(val).upper(), 0)
        else:
            try:
                val = float(val)
            except (ValueError, TypeError):
                val = 0.0
        features.append(float(val))
    X = np.array([features], dtype=np.float32)
    # Apply scaler if available
    scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
    if os.path.exists(scaler_path):
        import joblib
        scaler = joblib.load(scaler_path)
        X = scaler.transform(X)
    return X

# ── Sklearn prediction ────────────────────────────────────────────────────────
def predict_sklearn(model_path, X, class_type):
    import joblib
    model = joblib.load(model_path)
    pred  = int(model.predict(X)[0])
    prob  = None
    if hasattr(model, 'predict_proba'):
        proba = model.predict_proba(X)[0]
        prob  = float(np.max(proba))
    return pred, prob

# ── Deep learning prediction ──────────────────────────────────────────────────
def predict_deep(model_path, X, class_type):
    import tensorflow as tf
    model    = tf.keras.models.load_model(model_path, compile=False)
    pred_raw = model.predict(X, verbose=0)
    if class_type == 'binary':
        p    = float(pred_raw[0][0])
        pred = 1 if p > 0.5 else 0
        prob = max(p, 1.0 - p)
    else:
        pred = int(np.argmax(pred_raw[0]))
        prob = float(np.max(pred_raw[0]))
    return pred, prob

# ── Main prediction function ──────────────────────────────────────────────────
def run_prediction(model_name, class_type, params):
    X = encode_input(params)

    MODEL_MAP = {
        ('knn',           'binary'):     'knn_binary_class.sav',
        ('knn',           'multiclass'): 'knn_multi_class.sav',
        ('random_forest', 'binary'):     'random_forest_binary_class.sav',
        ('random_forest', 'multiclass'): 'random_forest_multi_class.sav',
        ('cnn',           'binary'):     'cnn_binary_class.h5',
        ('cnn',           'multiclass'): 'cnn_multi_class.h5',
        ('lstm',          'binary'):     'lstm_binary_class.h5',
        ('lstm',          'multiclass'): 'lstm_multi_class.h5',
    }

    filename = MODEL_MAP.get((model_name, class_type))
    if not filename:
        raise ValueError(f"Unknown model '{model_name}' / class_type '{class_type}'")

    model_path = os.path.join(MODELS_DIR, filename)

    if not os.path.exists(model_path):
        return simulate_prediction(params, class_type)

    if filename.endswith('.sav'):
        pred, prob = predict_sklearn(model_path, X, class_type)
    else:
        pred, prob = predict_deep(model_path, X, class_type)

    # ── Decode prediction ──────────────────────────────────────────────────
    if class_type == 'binary':
        binary_label = LABEL_BINARY[min(pred, 1)]
        multi_label  = binary_label
        category     = binary_label
    else:
        le_path = os.path.join(MODELS_DIR, 'multi_label_encoder.pkl')
        if os.path.exists(le_path):
            import joblib
            le = joblib.load(le_path)
            multi_label = str(le.inverse_transform([pred])[0])
        else:
            multi_label = LABEL_MULTI[pred % len(LABEL_MULTI)]
        binary_label = 'Normal' if multi_label == 'Normal' else 'Attack'
        category     = multi_label

    return {
        'binary_result':     binary_label,
        'multiclass_result': multi_label,
        'probability':       round(float(prob) * 100, 2) if prob is not None else None,
        'attack_category':   category,
        'description':       ATTACK_DESCRIPTIONS.get(category, ''),
        'is_attack':         binary_label == 'Attack'
    }

# ── Fallback simulation ───────────────────────────────────────────────────────
def simulate_prediction(params, class_type):
    """Rule-based simulation when no trained models exist"""
    try:
        src_bytes    = float(params.get('src_bytes', 0))
        serror_rate  = float(params.get('serror_rate', 0))
        count        = float(params.get('count', 0))
        rerror_rate  = float(params.get('rerror_rate', 0))
        logged_in    = float(params.get('logged_in', 0))
        root_shell   = float(params.get('root_shell', 0))
        duration     = float(params.get('duration', 0))
    except (ValueError, TypeError):
        src_bytes = serror_rate = count = rerror_rate = logged_in = root_shell = duration = 0

    score = 0
    attack_type = 'Normal'

    # DoS heuristics
    if serror_rate > 0.5 and count > 100: score += 4; attack_type = 'DoS'
    elif serror_rate > 0.3:               score += 2; attack_type = 'DoS'

    # Probe heuristics
    if rerror_rate > 0.3 and count > 50:  score = max(score, 3); attack_type = 'Probe'

    # R2L heuristics
    if src_bytes > 50000 and not logged_in and duration > 0:
        score = max(score, 3); attack_type = 'R2L'

    # U2R heuristics
    if root_shell == 1:                   score = max(score, 4); attack_type = 'U2R'

    is_attack    = score >= 3
    binary_label = 'Attack' if is_attack else 'Normal'
    multi_label  = attack_type if is_attack else 'Normal'

    if class_type == 'binary':
        multi_label = binary_label

    return {
        'binary_result':     binary_label,
        'multiclass_result': multi_label,
        'probability':       round(min(60 + score * 8, 97), 2),
        'attack_category':   multi_label,
        'description':       ATTACK_DESCRIPTIONS.get(multi_label, ''),
        'is_attack':         is_attack,
        'simulated':         True
    }

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(json.dumps({'error': 'Usage: script.py <model> <class_type> <json_params>'}))
        sys.exit(0)

    model_name = sys.argv[1].strip()
    class_type = sys.argv[2].strip()

    try:
        params = json.loads(sys.argv[3])
    except json.JSONDecodeError as e:
        print(json.dumps({'error': f'Invalid JSON params: {e}'}))
        sys.exit(0)

    try:
        result = run_prediction(model_name, class_type, params)
    except Exception as e:
        result = simulate_prediction(params, class_type)
        result['note'] = f'Simulation used (model error: {str(e)})'

    print(json.dumps(result))
