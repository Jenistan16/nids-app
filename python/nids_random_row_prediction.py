#!/usr/bin/env python3
"""
NIDS Random Row Prediction Script
Picks a random record from NSL-KDD dataset and predicts
Usage: python3 nids_random_row_prediction.py <model> <class_type>
"""

import sys
import json
import os
import random
import warnings
warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, 'dataset', 'nsl-kdd.csv')

# Add python dir to path so we can import from nids_parameter_prediction
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

NSL_KDD_COLUMNS = [
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

ATTACK_CATEGORY_MAP = {
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

FEATURE_COLS = NSL_KDD_COLUMNS[:41]  # all except label, difficulty

def get_random_row_from_dataset():
    """Read a random row from NSL-KDD dataset"""
    import pandas as pd
    df = pd.read_csv(DATASET_PATH, header=None, names=NSL_KDD_COLUMNS)
    df = df.drop('difficulty_level', axis=1)
    row = df.sample(1).iloc[0]
    params = {col: str(row[col]) for col in FEATURE_COLS}
    actual_label    = str(row['label']).replace('.','').strip().lower()
    actual_category = ATTACK_CATEGORY_MAP.get(actual_label, 'Unknown')
    return params, actual_label, actual_category

def generate_synthetic_row():
    """Generate a realistic random test record when dataset is unavailable"""
    attack_scenario = random.choice([
        'normal', 'neptune', 'portsweep', 'ipsweep',
        'guess_passwd', 'buffer_overflow', 'smurf'
    ])

    base = {
        'duration': str(random.randint(0, 58329)),
        'protocol_type': random.choice(['tcp', 'udp', 'icmp']),
        'service': random.choice(['http', 'ftp', 'smtp', 'ssh', 'other', 'private', 'telnet']),
        'flag': random.choice(['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'SH']),
        'src_bytes': str(random.randint(0, 1379963888)),
        'dst_bytes': str(random.randint(0, 1309937401)),
        'land': '0', 'wrong_fragment': str(random.randint(0,3)),
        'urgent': '0', 'hot': str(random.randint(0,101)),
        'num_failed_logins': str(random.randint(0,5)),
        'logged_in': str(random.randint(0,1)),
        'num_compromised': str(random.randint(0,7479)),
        'root_shell': str(random.randint(0,1)),
        'su_attempted': str(random.randint(0,2)),
        'num_root': str(random.randint(0,7468)),
        'num_file_creations': str(random.randint(0,100)),
        'num_shells': str(random.randint(0,5)),
        'num_access_files': str(random.randint(0,9)),
        'num_outbound_cmds': '0',
        'is_host_login': '0', 'is_guest_login': str(random.randint(0,1)),
        'count': str(random.randint(0,511)),
        'srv_count': str(random.randint(0,511)),
        'serror_rate': str(round(random.uniform(0,1),2)),
        'srv_serror_rate': str(round(random.uniform(0,1),2)),
        'rerror_rate': str(round(random.uniform(0,1),2)),
        'srv_rerror_rate': str(round(random.uniform(0,1),2)),
        'same_srv_rate': str(round(random.uniform(0,1),2)),
        'diff_srv_rate': str(round(random.uniform(0,1),2)),
        'srv_diff_host_rate': str(round(random.uniform(0,1),2)),
        'dst_host_count': str(random.randint(0,255)),
        'dst_host_srv_count': str(random.randint(0,255)),
        'dst_host_same_srv_rate': str(round(random.uniform(0,1),2)),
        'dst_host_diff_srv_rate': str(round(random.uniform(0,1),2)),
        'dst_host_same_src_port_rate': str(round(random.uniform(0,1),2)),
        'dst_host_srv_diff_host_rate': str(round(random.uniform(0,1),2)),
        'dst_host_serror_rate': str(round(random.uniform(0,1),2)),
        'dst_host_srv_serror_rate': str(round(random.uniform(0,1),2)),
        'dst_host_rerror_rate': str(round(random.uniform(0,1),2)),
        'dst_host_srv_rerror_rate': str(round(random.uniform(0,1),2)),
    }

    # Tweak params to match attack scenario
    if attack_scenario == 'neptune':
        base.update({'serror_rate':'1.0','srv_serror_rate':'1.0',
                     'dst_host_serror_rate':'1.0','flag':'S0','count':str(random.randint(200,511))})
    elif attack_scenario == 'smurf':
        base.update({'protocol_type':'icmp','service':'eco_i','src_bytes':'1032',
                     'dst_bytes':'0','count':str(random.randint(400,511))})
    elif attack_scenario in ('portsweep','ipsweep'):
        base.update({'serror_rate':'0.0','rerror_rate':str(round(random.uniform(0.3,0.9),2)),
                     'diff_srv_rate':str(round(random.uniform(0.5,1.0),2))})

    actual_category = ATTACK_CATEGORY_MAP.get(attack_scenario, 'Normal')
    return base, attack_scenario, actual_category

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(json.dumps({'error': 'Usage: script.py <model> <class_type>'}))
        sys.exit(0)

    model_name = sys.argv[1].strip()
    class_type = sys.argv[2].strip()

    # Get row
    try:
        if os.path.exists(DATASET_PATH):
            params, actual_label, actual_category = get_random_row_from_dataset()
        else:
            params, actual_label, actual_category = generate_synthetic_row()
    except Exception as e:
        params, actual_label, actual_category = generate_synthetic_row()

    # Run prediction
    try:
        from nids_parameter_prediction import run_prediction, simulate_prediction
        result = run_prediction(model_name, class_type, params)
    except Exception as e:
        from nids_parameter_prediction import simulate_prediction
        result = simulate_prediction(params, class_type)
        result['note'] = f'Simulation used: {str(e)}'

    result['input_row']       = params
    result['actual_label']    = actual_label
    result['actual_category'] = actual_category

    print(json.dumps(result))
