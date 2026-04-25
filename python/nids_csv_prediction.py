#!/usr/bin/env python3
"""
NIDS CSV Batch Prediction Script
Processes an uploaded CSV and runs prediction on every row
Usage: python3 nids_csv_prediction.py <model> <class_type> <csv_filepath>
"""

import sys
import json
import os
import warnings
warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nids_parameter_prediction import FEATURE_COLS, run_prediction, simulate_prediction

MAX_ROWS = 200  # cap for performance

def process_csv(filepath, model_name, class_type):
    try:
        import pandas as pd
    except ImportError:
        return {'error': 'pandas not installed. Run: pip3 install pandas'}

    if not os.path.exists(filepath):
        return {'error': f'File not found: {filepath}'}

    # Read CSV
    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        return {'error': f'Could not read CSV: {str(e)}'}

    # Normalise column names
    df.columns = [c.strip().lower().replace(' ','_').replace('-','_') for c in df.columns]

    total_rows = len(df)
    df = df.head(MAX_ROWS)

    predictions  = []
    attack_count = 0
    normal_count = 0
    category_counts = {}
    errors = 0

    # Pre-load model once (for sklearn) to avoid reloading each row
    for idx, row in df.iterrows():
        params = {}
        for col in FEATURE_COLS:
            val = row.get(col, row.get(col.replace('_',''), 0))
            params[col] = str(val) if val is not None else '0'

        try:
            result = run_prediction(model_name, class_type, params)
        except Exception as e:
            result = simulate_prediction(params, class_type)
            errors += 1

        binary    = result.get('binary_result', 'Unknown')
        multi     = result.get('multiclass_result', binary)
        prob      = result.get('probability', 0)
        is_attack = result.get('is_attack', False)

        if is_attack:
            attack_count += 1
        else:
            normal_count += 1

        category_counts[multi] = category_counts.get(multi, 0) + 1

        predictions.append({
            'row':              int(idx) + 1,
            'binary_result':    binary,
            'multiclass_result': multi,
            'probability':      prob,
            'is_attack':        is_attack,
            'simulated':        result.get('simulated', False)
        })

    total = len(predictions)
    return {
        'predictions': predictions,
        'summary': {
            'total':              total,
            'total_in_file':      total_rows,
            'attack_count':       attack_count,
            'normal_count':       normal_count,
            'attack_percentage':  round((attack_count / total) * 100, 2) if total > 0 else 0,
            'category_breakdown': category_counts,
            'errors':             errors
        },
        'model':      model_name,
        'class_type': class_type
    }

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(json.dumps({'error': 'Usage: script.py <model> <class_type> <csv_path>'}))
        sys.exit(0)

    model_name = sys.argv[1].strip()
    class_type = sys.argv[2].strip()
    csv_path   = sys.argv[3].strip()

    result = process_csv(csv_path, model_name, class_type)
    print(json.dumps(result))
