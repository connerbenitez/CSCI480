import os
import pandas as pd
import numpy as np
import torch
import joblib
from pathlib import Path
import sys

ml_dir = Path(os.environ.get("CSCI480_ML_ROOT") or Path(__file__).parent)
if str(ml_dir) not in sys.path:
    sys.path.insert(0, str(ml_dir))

try:
    import numpy.core as numpy_core

    sys.modules.setdefault("numpy._core", numpy_core)
    for _module_name in ("_multiarray_umath", "multiarray", "numeric", "numerictypes", "umath"):
        try:
            _module = __import__(f"numpy.core.{_module_name}", fromlist=[_module_name])
            sys.modules.setdefault(f"numpy._core.{_module_name}", _module)
        except Exception:
            continue
except Exception:
    pass

from model_defs import Autoencoder, FlowGNN, PPOPolicyNetwork, knn_edge_index


def artifact_path(directory: Path, filename: str) -> Path:
    base = directory / filename
    optimized = directory / f"{base.stem}_optimized{base.suffix}"
    return optimized if optimized.exists() else base


def load_required(loader, description):
    try:
        return loader()
    except Exception as exc:
        raise RuntimeError(f"{description}: {exc}") from exc


def load_optional(loader, description):
    try:
        return loader()
    except Exception as exc:
        print(f"Warning: Optional {description} unavailable: {exc}")
        return None

def align_features(df, expected_cols):
    """Pad missing columns with 0 and align column order to match scaler expectations."""
    df_aligned = df.copy()
    for col in expected_cols:
        if col not in df_aligned.columns:
            df_aligned[col] = 0
    return df_aligned[expected_cols]

def expected_features(model_entry, key, scaler_key=None):
    names = model_entry.get(key)
    if names:
        return names
    scaler = model_entry.get(scaler_key) if scaler_key else None
    if scaler is not None and hasattr(scaler, 'feature_names_in_'):
        return list(scaler.feature_names_in_)
    return None

def preprocess_flows(df):
    """Preprocess single/multiple flow DataFrames exactly as training."""
    df = df.copy()
    
    # 1. Column standardization
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
    
    # 2. String stripping
    for col in df.select_dtypes(include=['object']).columns:
        df[col] = df[col].str.strip()
    
    # 3. Replace inf/nan
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # 4. Drop cols >30% missing
    df = df.loc[:, df.isna().mean() < 0.3]
    
    # 5. Fill numeric NaN median
    numeric_cols = df.select_dtypes(include=np.number).columns
    df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
    
    # 6. Drop duplicates (Disabled for live prediction to keep row alignments)
    # df.drop_duplicates(inplace=True)
    
    # 7. Drop specific cols
    drop_cols = [
        'fwd_header_length.1', 'fwd_avg_bytes/bulk', 'fwd_avg_packets/bulk', 'fwd_avg_bulk_rate',
        'bwd_avg_bytes/bulk', 'bwd_avg_packets/bulk', 'bwd_avg_bulk_rate'
    ]
    df.drop(columns=[c for c in drop_cols if c in df.columns], inplace=True)
    
    return df

def load_models():
    """Load all models and preprocessors. Returns dict. Called once."""
    models = {}

    def load_ae():
        ae_dir = ml_dir / 'AutoEncoderDumps'
        ae_model_path = artifact_path(ae_dir, 'autoencoder_model.pkl')
        ae_threshold_path = artifact_path(ae_dir, 'autoencoder_threshold.pkl')
        ae_model = torch.load(ae_model_path, map_location="cpu", weights_only=False)
        threshold_payload = joblib.load(ae_threshold_path)
        return {
            'model': ae_model,
            'scaler': joblib.load(artifact_path(ae_dir, 'autoencoder_scaler.pkl')),
            'threshold': threshold_payload['threshold'],
            'risk_thresholds': threshold_payload.get('risk_thresholds', {}),
            'feature_names': joblib.load(artifact_path(ae_dir, 'autoencoder_feature_names.pkl')) if artifact_path(ae_dir, 'autoencoder_feature_names.pkl').exists() else None
        }

    def load_iso():
        iso_dir = ml_dir / 'IsoDumps'
        calibration = joblib.load(artifact_path(iso_dir, 'iso_calibration.pkl')) if artifact_path(iso_dir, 'iso_calibration.pkl').exists() else {}
        return {
            'model': joblib.load(artifact_path(iso_dir, 'iso_forest_model.pkl')),
            'feature_scaler': joblib.load(artifact_path(iso_dir, 'iso_feature_scaler.pkl')),
            'score_scaler': joblib.load(artifact_path(iso_dir, 'iso_score_scaler.pkl')),
            'dropped_features': joblib.load(artifact_path(iso_dir, 'iso_dropped_features.pkl')),
            'feature_names': joblib.load(artifact_path(iso_dir, 'iso_feature_names.pkl')) if artifact_path(iso_dir, 'iso_feature_names.pkl').exists() else None,
            'risk_thresholds': calibration.get('risk_thresholds', {}),
        }

    def load_kmeans():
        k_dir = ml_dir / 'KmeansDumps'
        calibration = joblib.load(artifact_path(k_dir, 'kmeans_calibration.pkl')) if artifact_path(k_dir, 'kmeans_calibration.pkl').exists() else {}
        return {
            'model': joblib.load(artifact_path(k_dir, 'kmeans_model.pkl')),
            'feature_scaler': joblib.load(artifact_path(k_dir, 'kmeans_feature_scaler.pkl')),
            'score_scaler': joblib.load(artifact_path(k_dir, 'kmeans_score_scaler.pkl')),
            'dropped_features': joblib.load(artifact_path(k_dir, 'kmeans_dropped_features.pkl')),
            'feature_names': joblib.load(artifact_path(k_dir, 'kmeans_feature_names.pkl')) if artifact_path(k_dir, 'kmeans_feature_names.pkl').exists() else None,
            'risk_thresholds': calibration.get('risk_thresholds', {}),
        }

    def load_rf():
        rf_dir = ml_dir / 'RandomForestDumps'
        return {
            'model': joblib.load(artifact_path(rf_dir, 'rf_model_multiclass.pkl')),
            'scaler': joblib.load(artifact_path(rf_dir, 'supervised_scaler_multiclass.pkl')),
            'label_encoder': joblib.load(artifact_path(rf_dir, 'label_encoder.pkl')),
            'dropped_features': joblib.load(artifact_path(rf_dir, 'supervised_dropped_features_multiclass.pkl')),
            'feature_names': joblib.load(artifact_path(rf_dir, 'supervised_feature_names_multiclass.pkl')) if artifact_path(rf_dir, 'supervised_feature_names_multiclass.pkl').exists() else None
        }

    core_errors = []
    for key, loader, description in (
        ('ae', load_ae, 'autoencoder bundle'),
        ('iso', load_iso, 'isolation forest bundle'),
        ('kmeans', load_kmeans, 'kmeans bundle'),
        ('rf', load_rf, 'random forest bundle'),
    ):
        try:
            models[key] = load_required(loader, description)
        except Exception as exc:
            core_errors.append(str(exc))
            print(f"Warning: Core {description} unavailable: {exc}")

    if not models:
        raise RuntimeError("; ".join(core_errors) if core_errors else "No ML models could be loaded")

    # Optional models should not prevent the core bundle from starting.
    gbdt_dir = ml_dir / 'GradientBoostedDumps'
    if artifact_path(gbdt_dir, 'gbdt_model_multiclass.pkl').exists():
        optional_gbdt = load_optional(
            lambda: {
                'model': joblib.load(artifact_path(gbdt_dir, 'gbdt_model_multiclass.pkl')),
                'label_encoder': joblib.load(artifact_path(gbdt_dir, 'gbdt_label_encoder.pkl')),
                'dropped_features': joblib.load(artifact_path(gbdt_dir, 'gbdt_dropped_features_multiclass.pkl')),
                'feature_names': joblib.load(artifact_path(gbdt_dir, 'gbdt_feature_names_multiclass.pkl')) if artifact_path(gbdt_dir, 'gbdt_feature_names_multiclass.pkl').exists() else None
            },
            'GBDT model'
        )
        if optional_gbdt:
            models['gbdt'] = optional_gbdt

    ppo_dir = ml_dir / 'PPODumps'
    if artifact_path(ppo_dir, 'ppo_policy.pt').exists():
        def load_ppo():
            ppo_payload = torch.load(artifact_path(ppo_dir, 'ppo_policy.pt'), map_location='cpu', weights_only=False)
            ppo_model = PPOPolicyNetwork(
                input_dim=ppo_payload['input_dim'],
                hidden_dim=ppo_payload['hidden_dim'],
                action_dim=len(ppo_payload['action_labels'])
            )
            ppo_model.load_state_dict(ppo_payload['state_dict'])
            ppo_model.eval()
            return {
                'model': ppo_model,
                'scaler': joblib.load(artifact_path(ppo_dir, 'ppo_scaler.pkl')),
                'labels': ppo_payload['action_labels'],
                'feature_names': joblib.load(artifact_path(ppo_dir, 'ppo_feature_names.pkl')) if artifact_path(ppo_dir, 'ppo_feature_names.pkl').exists() else None,
                'risk_thresholds': ppo_payload.get('risk_thresholds', {}),
                'decision_threshold': ppo_payload.get('decision_threshold', 0.5)
            }
        optional_ppo = load_optional(load_ppo, 'PPO model')
        if optional_ppo:
            models['ppo'] = optional_ppo

    gnn_dir = ml_dir / 'GNNDumps'
    if artifact_path(gnn_dir, 'gnn_model.pt').exists():
        def load_gnn():
            gnn_payload = torch.load(artifact_path(gnn_dir, 'gnn_model.pt'), map_location='cpu', weights_only=False)
            gnn_model = FlowGNN(
                input_dim=gnn_payload['input_dim'],
                hidden_dim=gnn_payload['hidden_dim'],
                output_dim=gnn_payload['output_dim']
            )
            gnn_model.load_state_dict(gnn_payload['state_dict'])
            gnn_model.eval()
            return {
                'model': gnn_model,
                'scaler': joblib.load(artifact_path(gnn_dir, 'gnn_scaler.pkl')),
                'dropped_features': joblib.load(artifact_path(gnn_dir, 'gnn_dropped_features.pkl')),
                'k_neighbors': gnn_payload['k_neighbors'],
                'feature_names': joblib.load(artifact_path(gnn_dir, 'gnn_feature_names.pkl')) if artifact_path(gnn_dir, 'gnn_feature_names.pkl').exists() else None,
                'decision_threshold': gnn_payload.get('decision_threshold', 0.5)
            }
        optional_gnn = load_optional(load_gnn, 'GNN model')
        if optional_gnn:
            models['gnn'] = optional_gnn
    
    return models

def predict_ae(models, X_scaled):
    """AE prediction."""
    model = models['ae']['model']
    threshold = models['ae']['threshold']
    
    model.eval()
    with torch.no_grad():
        data_tensor = torch.tensor(X_scaled, dtype=torch.float32)
        outputs = model(data_tensor)
        errors = torch.mean((outputs - data_tensor)**2, dim=1).numpy()
    
    anomaly_scores = errors  # raw recon err
    anomalies = errors > threshold
    risk_thresholds = models['ae'].get('risk_thresholds', {})
    ae_risk = [get_risk_label(float(s), risk_thresholds) for s in anomaly_scores]
    
    return {
        'ae_score': anomaly_scores.tolist() if len(anomaly_scores) > 1 else float(anomaly_scores[0]),
        'ae_anomaly': anomalies.tolist() if len(anomalies) > 1 else bool(anomalies[0]),
        'ae_risk': ae_risk if len(ae_risk) > 1 else ae_risk[0],
    }

def get_risk_label(score_norm, thresholds=None):
    thresholds = thresholds or {}
    low = float(thresholds.get('low', 0.75))
    med = float(thresholds.get('medium', 0.90))
    high = float(thresholds.get('high', 0.97))
    
    if score_norm >= high:
        return 'high'
    elif score_norm >= med:
        return 'medium'
    elif score_norm >= low:
        return 'low'
    else:
        return 'normal'

def predict_unsupervised(models, X_orig, model_key):
    """Generic Iso/KMeans."""
    dropped = models[model_key]['dropped_features']
    feature_scaler = models[model_key]['feature_scaler']
    score_scaler = models[model_key]['score_scaler']
    model = models[model_key]['model']
    
    feature_cols = [c for c in X_orig.columns if c not in dropped]
    X_feat = X_orig[feature_cols]
    
    feature_names = expected_features(models[model_key], 'feature_names', 'feature_scaler')
    if feature_names:
        X_feat = align_features(X_feat, feature_names)

    X_scaled = feature_scaler.transform(X_feat.to_numpy(dtype=float))
    
    if model_key == 'iso':
        scores_raw = -model.score_samples(X_scaled)
    else:  # kmeans
        dists = np.min(model.transform(X_scaled), axis=1)
        scores_raw = dists

    # Normalize score outputs to [0, 1] regardless of scaler type/config.
    # Some saved scalers (or input drift) can produce values far outside 0..1,
    # which would collapse risk labels to all-normal in downstream logic.
    transformed = score_scaler.transform(scores_raw.reshape(-1, 1)).ravel()
    scores_norm = np.clip(transformed, 0.0, 1.0)

    # Use learned training thresholds when available. Do not force a relative
    # remap for all-normal batches, because that creates artificial positives
    # on ordinary live traffic.
    risk_labels = [get_risk_label(float(s), models[model_key].get('risk_thresholds', {})) for s in scores_norm]
    
    return {
        f'{model_key}_score': scores_norm.tolist() if len(scores_norm)>1 else float(scores_norm[0]),
        f'{model_key}_risk': risk_labels if len(risk_labels)>1 else risk_labels[0]
    }

def predict_rf(models, X_orig):
    """RF multiclass."""
    dropped = models['rf']['dropped_features']
    scaler = models['rf']['scaler']
    le = models['rf']['label_encoder']
    model = models['rf']['model']
    
    feature_cols = [c for c in X_orig.columns if c not in dropped]
    X_feat = X_orig[feature_cols]

    feature_names = expected_features(models['rf'], 'feature_names', 'scaler')
    if feature_names:
        X_feat = align_features(X_feat, feature_names)

    X_scaled = scaler.transform(X_feat.to_numpy(dtype=float))
    probs = model.predict_proba(X_scaled)
    labels = le.inverse_transform(model.predict(X_scaled))
    
    return {
        'rf_labels': labels.tolist() if len(labels)>1 else labels[0],
        'rf_probs': [dict(zip(le.classes_, p)) for p in probs] # Frontend expects this to stay a list
    }

def predict_gbdt(models, X_orig):
    dropped = models['gbdt']['dropped_features']
    le = models['gbdt']['label_encoder']
    model = models['gbdt']['model']

    feature_cols = [c for c in X_orig.columns if c not in dropped]
    X_feat = X_orig[feature_cols]
    if models['gbdt'].get('feature_names'):
        X_feat = align_features(X_feat, models['gbdt']['feature_names'])

    X_arr = X_feat.to_numpy(dtype=float)
    probs = model.predict_proba(X_arr)
    labels = le.inverse_transform(model.predict(X_arr))
    return {
        'gbdt_labels': labels.tolist() if len(labels) > 1 else labels[0],
        'gbdt_probs': [dict(zip(le.classes_, p)) for p in probs]
    }

def predict_ppo(models, X_orig):
    scaler = models['ppo']['scaler']
    model = models['ppo']['model']
    labels = models['ppo']['labels']

    X_feat = X_orig.select_dtypes(include=np.number)
    feature_names = expected_features(models['ppo'], 'feature_names', 'scaler')
    if feature_names:
        X_feat = align_features(X_feat, feature_names)

    X_scaled = scaler.transform(X_feat.to_numpy(dtype=float))
    with torch.no_grad():
        logits, values = model(torch.tensor(X_scaled, dtype=torch.float32))
        probs = torch.softmax(logits, dim=1).cpu().numpy()
        pred_idx = logits.argmax(dim=1).cpu().numpy()

    if len(labels) == 2:
        attack_probs = probs[:, 1]
        thresholds = models['ppo'].get('risk_thresholds', {})
        decision_threshold = float(models['ppo'].get('decision_threshold', 0.5))
        risk_labels = []
        for prob in attack_probs:
            prob = float(prob)
            if prob < decision_threshold:
                risk_labels.append('normal')
            else:
                risk_labels.append(get_risk_label(prob, thresholds))
    else:
        attack_probs = np.max(probs[:, 1:], axis=1) if probs.shape[1] > 1 else probs[:, 0]
        risk_labels = [labels[i] for i in pred_idx]

    return {
        'ppo_risk': risk_labels if len(risk_labels) > 1 else risk_labels[0],
        'ppo_probs': [dict(zip(labels, p)) for p in probs],
        'ppo_value': values.cpu().numpy().tolist() if len(pred_idx) > 1 else float(values.cpu().numpy()[0]),
        'ppo_attack_prob': attack_probs.tolist() if len(attack_probs) > 1 else float(attack_probs[0]),
    }

def predict_gnn(models, X_orig):
    dropped = models['gnn']['dropped_features']
    scaler = models['gnn']['scaler']
    model = models['gnn']['model']

    feature_cols = [c for c in X_orig.select_dtypes(include=np.number).columns if c not in dropped]
    X_feat = X_orig[feature_cols]
    feature_names = expected_features(models['gnn'], 'feature_names', 'scaler')
    if feature_names:
        X_feat = align_features(X_feat, feature_names)

    X_scaled = scaler.transform(X_feat.to_numpy(dtype=float))
    x_tensor = torch.tensor(X_scaled, dtype=torch.float32)
    edge_index = knn_edge_index(x_tensor, k=models['gnn']['k_neighbors'])
    with torch.no_grad():
        logits = model(x_tensor, edge_index)
        probs = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
        preds = (probs >= models['gnn'].get('decision_threshold', 0.5)).astype(int)

    labels = ['normal' if p == 0 else 'attack' for p in preds]
    return {
        'gnn_label': labels if len(labels) > 1 else labels[0],
        'gnn_attack_prob': probs.tolist() if len(probs) > 1 else float(probs[0]),
    }


def label_is_non_benign(label):
    if label is None:
        return False
    return str(label).upper() != 'BENIGN'


def weighted_ensemble_risk(preds):
    ae_risk = str(preds.get('ae_risk', 'normal')).lower()
    iso_risk = str(preds.get('iso_risk', 'normal')).lower()
    km_risk = str(preds.get('kmeans_risk', 'normal')).lower()
    rf_suspicious = label_is_non_benign(preds.get('rf_labels'))
    gbdt_suspicious = label_is_non_benign(preds.get('gbdt_labels'))

    anomaly_votes = sum(
        [
            ae_risk in ('medium', 'high'),
            iso_risk == 'high',
            km_risk == 'high',
        ]
    )

    if rf_suspicious and gbdt_suspicious:
        return 'high'
    if rf_suspicious or gbdt_suspicious:
        return 'medium'
    if anomaly_votes >= 3:
        return 'low'
    if (ae_risk in ('medium', 'high')) and (iso_risk == 'high' or km_risk == 'high'):
        return 'low'
    return 'normal'

def predict_all(models, flows_df):
    """Main entry: df -> predictions dict/list."""
    df_clean = preprocess_flows(flows_df)
    gnn_batch_preds = predict_gnn(models, df_clean) if 'gnn' in models else None
    
    results = []
    for idx, row in df_clean.iterrows():
        flow_df = pd.DataFrame([row])
        
        preds = {}
        
        numeric_features = flow_df.select_dtypes(include=np.number).columns
        X_num = flow_df[numeric_features]
        
        if 'ae' in models:
            corr_matrix = X_num.corr().abs()
            upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
            to_drop = [col for col in upper.columns if any(upper[col] > 0.9)]
            X_ae = X_num.drop(columns=to_drop)
            ae_feature_names = expected_features(models['ae'], 'feature_names', 'scaler')
            if ae_feature_names:
                X_ae = align_features(X_ae, ae_feature_names)
            X_ae_scaled = models['ae']['scaler'].transform(X_ae.to_numpy(dtype=float))
            preds.update(predict_ae(models, X_ae_scaled))
        else:
            preds.update({'ae_score': None, 'ae_anomaly': False, 'ae_risk': 'error'})

        if 'iso' in models:
            preds.update(predict_unsupervised(models, flow_df, 'iso'))
        else:
            preds.update({'iso_score': None, 'iso_risk': 'error'})

        if 'kmeans' in models:
            preds.update(predict_unsupervised(models, flow_df, 'kmeans'))
        else:
            preds.update({'kmeans_score': None, 'kmeans_risk': 'error'})

        if 'rf' in models:
            preds.update(predict_rf(models, flow_df))
        else:
            preds.update({'rf_labels': 'MODELS_UNAVAILABLE', 'rf_probs': []})
        if 'gbdt' in models:
            preds.update(predict_gbdt(models, flow_df))
        if 'ppo' in models:
            preds.update(predict_ppo(models, flow_df))
        if gnn_batch_preds:
            preds['gnn_label'] = gnn_batch_preds['gnn_label'][len(results)] if isinstance(gnn_batch_preds['gnn_label'], list) else gnn_batch_preds['gnn_label']
            preds['gnn_attack_prob'] = gnn_batch_preds['gnn_attack_prob'][len(results)] if isinstance(gnn_batch_preds['gnn_attack_prob'], list) else gnn_batch_preds['gnn_attack_prob']
        
        preds['ensemble_risk'] = weighted_ensemble_risk(preds)
        
        results.append(preds)
    
    return results

if __name__ == '__main__':
    models = load_models()
