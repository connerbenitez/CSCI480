from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
import pandas as pd
import requests
import torch
import torch.nn.functional as F
from sklearn.cluster import KMeans
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.preprocessing import LabelEncoder, MinMaxScaler, StandardScaler

from model_defs import Autoencoder, FlowGNN, PPOPolicyNetwork, hidden_dim_for_features, knn_edge_index


ROOT = Path(__file__).resolve().parent
DATASET_DIR = ROOT.parent / "Dataset"

DATASET_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

DATASET_BASE_URL = "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main"

CSE_CIC_IDS2018_BASE_URL = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms"

CSE_CIC_IDS2018_FILES = [
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
]

CSV_CHUNK_ROWS = 200_000

FIXED_DROP_COLS = [
    "fwd_header_length.1",
    "fwd_avg_bytes/bulk",
    "fwd_avg_packets/bulk",
    "fwd_avg_bulk_rate",
    "bwd_avg_bytes/bulk",
    "bwd_avg_packets/bulk",
    "bwd_avg_bulk_rate",
]

LABEL_REPLACEMENTS = {
    "web attack - brute force": "Web Attack - Brute Force",
    "web attack - xss": "Web Attack - XSS",
    "web attack - sql injection": "Web Attack - SQL Injection",
    "web attack – brute force": "Web Attack - Brute Force",
    "web attack – xss": "Web Attack - XSS",
    "web attack – sql injection": "Web Attack - SQL Injection",
    "web attack � brute force": "Web Attack - Brute Force",
    "web attack � xss": "Web Attack - XSS",
    "web attack � sql injection": "Web Attack - SQL Injection",
    "dos slowloris": "DoS Slowloris",
    "dos slowhttptest": "DoS Slowhttptest",
    "ssh-bruteforce": "SSH-BruteForce",
    "ssh bruteforce": "SSH-BruteForce",
    "ftp-bruteforce": "FTP-BruteForce",
    "ftp bruteforce": "FTP-BruteForce",
    "brute force -web": "Brute Force -Web",
    "brute force -xss": "Brute Force -XSS",
    "dos attacks-hulk": "DoS Hulk",
    "dos attacks-goldeneye": "DoS GoldenEye",
    "dos attacks-slowloris": "DoS Slowloris",
    "dos attacks-slowhttptest": "DoS Slowhttptest",
    "ddos attacks-loic-http": "DDoS LOIC-HTTP",
    "ddos attack-loic-udp": "DDoS LOIC-UDP",
    "ddos attack-hoic": "DDoS HOIC",
    "infilteration": "Infiltration",
    "label": "HEADER_ROW",
}


def download_dataset_files(target_dir: Path, base_url: str, filenames: list[str], overwrite: bool = False) -> list[Path]:
    target_dir.mkdir(parents=True, exist_ok=True)
    downloaded = []

    for filename in filenames:
        target = target_dir / filename
        if target.exists() and not overwrite:
            downloaded.append(target)
            continue

        url = f"{base_url}/{filename}?download=true"
        with requests.get(url, stream=True, timeout=120) as response:
            response.raise_for_status()
            with target.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        handle.write(chunk)
        downloaded.append(target)

    return downloaded


def download_dataset(target_dir: Path, overwrite: bool = False) -> list[Path]:
    return download_dataset_files(target_dir, DATASET_BASE_URL, DATASET_FILES, overwrite=overwrite)


def download_cse_cic_ids2018(target_dir: Path, overwrite: bool = False) -> list[Path]:
    return download_dataset_files(target_dir, CSE_CIC_IDS2018_BASE_URL, CSE_CIC_IDS2018_FILES, overwrite=overwrite)


def read_csv_sample(path: Path, sample_rows: int | None) -> pd.DataFrame:
    if sample_rows is None:
        return pd.read_csv(path, encoding="cp1252", low_memory=False)

    reservoir = None
    for chunk_idx, chunk in enumerate(pd.read_csv(path, encoding="cp1252", low_memory=False, chunksize=CSV_CHUNK_ROWS)):
        chunk = chunk.sample(n=min(len(chunk), sample_rows), random_state=42 + chunk_idx)
        if reservoir is None:
            reservoir = chunk.reset_index(drop=True)
        else:
            reservoir = pd.concat([reservoir, chunk], ignore_index=True)
        if len(reservoir) > sample_rows:
            reservoir = reservoir.sample(n=sample_rows, random_state=42 + chunk_idx).reset_index(drop=True)

    if reservoir is None:
        return pd.DataFrame()
    return reservoir


def normalize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

    for col in df.select_dtypes(include=["object"]).columns:
        df[col] = df[col].astype(str).str.strip()

    df.replace(["Infinity", "NaN", "nan"], np.nan, inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    text_like_cols = {"label", "timestamp", "flow_id", "src_ip", "dst_ip"}
    object_cols = [c for c in df.select_dtypes(include=["object"]).columns if c not in text_like_cols]
    for col in object_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    for col in ["flow_bytes/s", "flow_packets/s"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.loc[:, df.isna().mean() < 0.3]
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].apply(pd.to_numeric, errors="coerce")
    df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
    df[numeric_cols] = df[numeric_cols].astype(np.float32)
    if "label" in df.columns:
        df = df[df["label"].astype(str).str.strip().str.lower() != "label"]
    df.drop_duplicates(inplace=True)
    df.drop(columns=[c for c in FIXED_DROP_COLS if c in df.columns], inplace=True, errors="ignore")

    return df


def normalize_labels(series: pd.Series) -> pd.Series:
    normalized = series.astype(str).str.strip().str.replace(r"\s+", " ", regex=True)
    lowered = normalized.str.lower()
    for old, new in LABEL_REPLACEMENTS.items():
        lowered = lowered.str.replace(old, new.lower(), regex=False)
    normalized = lowered.str.replace("sql", "SQL", regex=False)
    normalized = normalized.str.replace("xss", "XSS", regex=False)
    normalized = normalized.str.replace("brute force", "Brute Force", regex=False)
    normalized = normalized.str.replace("slowloris", "Slowloris", regex=False)
    normalized = normalized.str.replace("slowhttptest", "Slowhttptest", regex=False)
    normalized = normalized.str.replace("goldeneye", "GoldenEye", regex=False)
    normalized = normalized.str.replace("hulk", "Hulk", regex=False)
    normalized = normalized.str.replace("hoic", "HOIC", regex=False)
    normalized = normalized.str.replace("loic-http", "LOIC-HTTP", regex=False)
    normalized = normalized.str.replace("loic-udp", "LOIC-UDP", regex=False)
    normalized = normalized.str.replace("web attack - ", "Web Attack - ", regex=False)
    normalized = normalized.str.replace("dos ", "DoS ", regex=False)
    normalized = normalized.str.replace("dDoS ", "DDoS ", regex=False)
    normalized = normalized.str.replace("bot", "Bot", regex=False)
    normalized = normalized.str.replace("infiltration", "Infiltration", regex=False)
    normalized = normalized.str.replace("heartbleed", "Heartbleed", regex=False)
    normalized = normalized.str.replace("portscan", "PortScan", regex=False)
    normalized = normalized.str.replace("ddos", "DDoS", regex=False)
    normalized = normalized.str.replace("ftp-patator", "FTP-Patator", regex=False)
    normalized = normalized.str.replace("ssh-patator", "SSH-Patator", regex=False)
    normalized = normalized.str.replace("ftp-bruteforce", "FTP-BruteForce", regex=False)
    normalized = normalized.str.replace("ssh-bruteforce", "SSH-BruteForce", regex=False)
    normalized = normalized.str.replace("brute force -web", "Brute Force -Web", regex=False)
    normalized = normalized.str.replace("brute force -xss", "Brute Force -XSS", regex=False)
    normalized = normalized.str.replace("dos attacks-", "DoS ", regex=False)
    normalized = normalized.str.replace("ddos attacks-loic-http", "DDoS LOIC-HTTP", regex=False)
    normalized = normalized.str.replace("ddos attack-loic-udp", "DDoS LOIC-UDP", regex=False)
    normalized = normalized.str.replace("ddos attack-hoic", "DDoS HOIC", regex=False)
    normalized = normalized.str.replace("benign", "BENIGN", regex=False)
    return normalized


def load_dataset(dataset_dir: Path, per_file_rows: int | None = None) -> pd.DataFrame:
    frames = [normalize_dataframe(read_csv_sample(path, per_file_rows)) for path in sorted(dataset_dir.glob("*.csv"))]
    if not frames:
        raise FileNotFoundError(f"No CSV files found in {dataset_dir}")
    df = pd.concat(frames, ignore_index=True)

    if "label" not in df.columns:
        raise ValueError("Expected a 'label' column in CICIDS2017 CSVs.")

    df["label"] = normalize_labels(df["label"])
    df = df[df["label"] != "HEADER_ROW"].copy()
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) > 0:
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
        df[numeric_cols] = df[numeric_cols].astype(np.float32)
    return df


def configure_system_acceleration() -> dict[str, object]:
    cpu_count = os.cpu_count() or 1
    cpu_threads = max(1, cpu_count)
    os.environ.setdefault("OMP_NUM_THREADS", str(cpu_threads))
    os.environ.setdefault("MKL_NUM_THREADS", str(cpu_threads))
    os.environ.setdefault("NUMEXPR_NUM_THREADS", str(cpu_threads))
    os.environ.setdefault("OPENBLAS_NUM_THREADS", str(cpu_threads))

    try:
        torch.set_num_threads(cpu_threads)
    except Exception:
        pass
    try:
        torch.set_num_interop_threads(max(1, min(8, max(1, cpu_threads // 2))))
    except Exception:
        pass

    cuda_available = bool(torch.cuda.is_available())
    device = torch.device("cuda" if cuda_available else "cpu")
    if cuda_available:
        torch.backends.cudnn.benchmark = True

    return {
        "cpu_threads": cpu_threads,
        "cuda_available": cuda_available,
        "device": str(device),
        "gpu_name": torch.cuda.get_device_name(0) if cuda_available else None,
    }


def tensor_batches(tensor: torch.Tensor, batch_size: int):
    for start in range(0, tensor.size(0), batch_size):
        yield tensor[start : start + batch_size]


def select_numeric_features(df: pd.DataFrame, drop_high_corr: bool = True) -> tuple[pd.DataFrame, list[str]]:
    numeric = df.select_dtypes(include=[np.number]).copy()
    dropped = []
    if drop_high_corr and not numeric.empty:
        corr_matrix = numeric.corr().abs()
        upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
        dropped = [col for col in upper.columns if any(upper[col] > 0.95)]
        numeric = numeric.drop(columns=dropped)
    return numeric, dropped


def make_binary_labels(df: pd.DataFrame) -> np.ndarray:
    return (df["label"].str.lower() != "benign").astype(np.int64).to_numpy()


def make_risk_targets(binary_labels: np.ndarray) -> np.ndarray:
    return np.where(binary_labels == 1, 3, 0).astype(np.int64)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def torch_save_atomic(obj, path: Path) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    torch.save(obj, tmp_path)
    try:
        tmp_path.replace(path)
    except PermissionError:
        optimized_path = path.with_name(f"{path.stem}_optimized{path.suffix}")
        if optimized_path.exists():
            optimized_path.unlink()
        tmp_path.replace(optimized_path)


def joblib_dump_atomic(obj, path: Path) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    joblib.dump(obj, tmp_path, compress=3)
    try:
        tmp_path.replace(path)
    except PermissionError:
        optimized_path = path.with_name(f"{path.stem}_optimized{path.suffix}")
        if optimized_path.exists():
            optimized_path.unlink()
        tmp_path.replace(optimized_path)


def multiclass_rebalance_indices(
    labels: np.ndarray,
    benign_index: int,
    benign_cap: int = 140000,
    attack_cap: int = 50000,
    rare_floor: int = 2500,
    seed: int = 42,
) -> np.ndarray:
    rng = np.random.default_rng(seed)
    chosen = []
    for cls in np.unique(labels):
        cls_idx = np.flatnonzero(labels == cls)
        if cls == benign_index:
            target = min(benign_cap, len(cls_idx))
            picked = rng.choice(cls_idx, size=target, replace=False) if target < len(cls_idx) else cls_idx
        else:
            if len(cls_idx) < rare_floor:
                picked = rng.choice(cls_idx, size=rare_floor, replace=True)
            elif len(cls_idx) > attack_cap:
                picked = rng.choice(cls_idx, size=attack_cap, replace=False)
            else:
                picked = cls_idx
        chosen.append(picked)
    combined = np.concatenate(chosen)
    rng.shuffle(combined)
    return combined


def teacher_attack_probability(probs: np.ndarray, label_encoder: LabelEncoder) -> np.ndarray:
    benign_index = int(np.where(label_encoder.classes_ == "BENIGN")[0][0])
    return 1.0 - probs[:, benign_index]


def risk_targets_from_attack_prob(attack_prob: np.ndarray, binary_labels: np.ndarray) -> tuple[np.ndarray, dict[str, float]]:
    attack_only = attack_prob[binary_labels == 1]
    if attack_only.size == 0:
        thresholds = {"low": 0.35, "medium": 0.6, "high": 0.85}
    else:
        thresholds = {
            "low": float(np.quantile(attack_only, 0.45)),
            "medium": float(np.quantile(attack_only, 0.75)),
            "high": float(np.quantile(attack_only, 0.92)),
        }

    risks = np.zeros_like(binary_labels, dtype=np.int64)
    attack_mask = binary_labels == 1
    risks[np.logical_and(attack_mask, attack_prob >= thresholds["low"])] = 1
    risks[np.logical_and(attack_mask, attack_prob >= thresholds["medium"])] = 2
    risks[np.logical_and(attack_mask, attack_prob >= thresholds["high"])] = 3
    return risks, thresholds


def unsupervised_risk_thresholds(scores: np.ndarray) -> dict[str, float]:
    return {
        "low": float(np.quantile(scores, 0.75)),
        "medium": float(np.quantile(scores, 0.90)),
        "high": float(np.quantile(scores, 0.97)),
    }


def train_autoencoder(
    X_train: np.ndarray,
    X_val: np.ndarray,
    y_val_binary: np.ndarray,
    feature_names: list[str],
    dump_dir: Path,
    epochs: int,
    batch_size: int,
) -> dict:
    ensure_dir(dump_dir)
    accel = configure_system_acceleration()
    device = torch.device(accel["device"])
    if len(X_train) > 600000:
        rng = np.random.default_rng(42)
        X_train = X_train[rng.choice(len(X_train), size=600000, replace=False)]
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    model = Autoencoder(input_dim=X_train_scaled.shape[1], hidden_dim=hidden_dim_for_features(X_train_scaled.shape[1])).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)

    train_tensor = torch.tensor(X_train_scaled, dtype=torch.float32, device=device)
    val_tensor = torch.tensor(X_val_scaled, dtype=torch.float32, device=device)
    eval_batch_size = max(batch_size, 8192 if device.type == "cuda" else 2048)

    model.train()
    for _ in range(epochs):
        permutation = torch.randperm(train_tensor.size(0), device=device)
        for start in range(0, train_tensor.size(0), batch_size):
            batch = train_tensor[permutation[start : start + batch_size]]
            outputs = model(batch)
            loss = F.mse_loss(outputs, batch)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

    model.eval()
    with torch.no_grad():
        train_errors = np.concatenate(
            [torch.mean((model(batch) - batch) ** 2, dim=1).detach().cpu().numpy() for batch in tensor_batches(train_tensor, eval_batch_size)]
        )
        val_errors = np.concatenate(
            [torch.mean((model(batch) - batch) ** 2, dim=1).detach().cpu().numpy() for batch in tensor_batches(val_tensor, eval_batch_size)]
        )

    threshold = float(np.percentile(train_errors, 99))
    risk_thresholds = unsupervised_risk_thresholds(train_errors)
    torch_save_atomic(model, dump_dir / "autoencoder_model.pkl")
    joblib_dump_atomic(scaler, dump_dir / "autoencoder_scaler.pkl")
    joblib_dump_atomic({"threshold": threshold, "p99": threshold, "risk_thresholds": risk_thresholds}, dump_dir / "autoencoder_threshold.pkl")
    joblib_dump_atomic(feature_names, dump_dir / "autoencoder_feature_names.pkl")

    return {
        "train_error_mean": float(train_errors.mean()),
        "val_error_mean": float(val_errors.mean()),
        "threshold": threshold,
        "roc_auc": float(roc_auc_score(y_val_binary, val_errors)),
    }


def train_isolation_forest(X_train: np.ndarray, X_val: np.ndarray, y_val_binary: np.ndarray, feature_names: list[str], dump_dir: Path) -> dict:
    ensure_dir(dump_dir)
    if len(X_train) > 700000:
        rng = np.random.default_rng(42)
        X_train = X_train[rng.choice(len(X_train), size=700000, replace=False)]
    feature_scaler = StandardScaler()
    X_train_scaled = feature_scaler.fit_transform(X_train)
    X_val_scaled = feature_scaler.transform(X_val)

    best = None
    candidate_params = [
        {"n_estimators": 300, "contamination": 0.01},
        {"n_estimators": 400, "contamination": 0.03},
        {"n_estimators": 500, "contamination": 0.05},
    ]
    for params in candidate_params:
        model = IsolationForest(
            n_estimators=params["n_estimators"],
            contamination=params["contamination"],
            max_samples=min(256000, len(X_train_scaled)),
            n_jobs=-1,
            random_state=42,
        )
        model.fit(X_train_scaled)
        train_scores = -model.score_samples(X_train_scaled)
        val_scores = -model.score_samples(X_val_scaled)
        score_scaler = MinMaxScaler()
        score_scaler.fit(train_scores.reshape(-1, 1))
        val_norm = np.clip(score_scaler.transform(val_scores.reshape(-1, 1)).ravel(), 0.0, 1.0)
        auc = float(roc_auc_score(y_val_binary, val_norm))
        if best is None or auc > best["roc_auc"]:
            best = {
                "model": model,
                "score_scaler": score_scaler,
                "roc_auc": auc,
                "train_norm": np.clip(score_scaler.transform(train_scores.reshape(-1, 1)).ravel(), 0.0, 1.0),
                "params": params,
            }

    risk_thresholds = unsupervised_risk_thresholds(best["train_norm"])
    joblib_dump_atomic(best["model"], dump_dir / "iso_forest_model.pkl")
    joblib_dump_atomic(feature_scaler, dump_dir / "iso_feature_scaler.pkl")
    joblib_dump_atomic(best["score_scaler"], dump_dir / "iso_score_scaler.pkl")
    joblib_dump_atomic([], dump_dir / "iso_dropped_features.pkl")
    joblib_dump_atomic(feature_names, dump_dir / "iso_feature_names.pkl")
    joblib_dump_atomic({"risk_thresholds": risk_thresholds, "params": best["params"]}, dump_dir / "iso_calibration.pkl")

    return {"roc_auc": best["roc_auc"], "risk_thresholds": risk_thresholds, "best_params": best["params"]}


def train_kmeans(X_train: np.ndarray, X_val: np.ndarray, y_val_binary: np.ndarray, feature_names: list[str], dump_dir: Path) -> dict:
    ensure_dir(dump_dir)
    if len(X_train) > 500000:
        rng = np.random.default_rng(42)
        X_train = X_train[rng.choice(len(X_train), size=500000, replace=False)]
    feature_scaler = StandardScaler()
    X_train_scaled = feature_scaler.fit_transform(X_train)
    X_val_scaled = feature_scaler.transform(X_val)
    candidate_clusters = [16, 24, 32]
    best = None
    for cluster_count in candidate_clusters:
        model = KMeans(n_clusters=cluster_count, init="k-means++", n_init=20, random_state=42)
        model.fit(X_train_scaled)
        train_scores = np.min(model.transform(X_train_scaled), axis=1)
        val_scores = np.min(model.transform(X_val_scaled), axis=1)
        score_scaler = MinMaxScaler()
        score_scaler.fit(train_scores.reshape(-1, 1))
        val_norm = np.clip(score_scaler.transform(val_scores.reshape(-1, 1)).ravel(), 0.0, 1.0)
        auc = float(roc_auc_score(y_val_binary, val_norm))
        if best is None or auc > best["roc_auc"]:
            best = {
                "model": model,
                "score_scaler": score_scaler,
                "roc_auc": auc,
                "train_norm": np.clip(score_scaler.transform(train_scores.reshape(-1, 1)).ravel(), 0.0, 1.0),
                "cluster_count": cluster_count,
            }

    risk_thresholds = unsupervised_risk_thresholds(best["train_norm"])
    joblib_dump_atomic(best["model"], dump_dir / "kmeans_model.pkl")
    joblib_dump_atomic(feature_scaler, dump_dir / "kmeans_feature_scaler.pkl")
    joblib_dump_atomic(best["score_scaler"], dump_dir / "kmeans_score_scaler.pkl")
    joblib_dump_atomic([], dump_dir / "kmeans_dropped_features.pkl")
    joblib_dump_atomic(feature_names, dump_dir / "kmeans_feature_names.pkl")
    joblib_dump_atomic({"risk_thresholds": risk_thresholds, "cluster_count": best["cluster_count"]}, dump_dir / "kmeans_calibration.pkl")

    return {"roc_auc": best["roc_auc"], "risk_thresholds": risk_thresholds, "cluster_count": best["cluster_count"]}


def train_random_forest(X_train: np.ndarray, X_val: np.ndarray, y_train: np.ndarray, y_val: np.ndarray, feature_names: list[str], label_encoder: LabelEncoder, dump_dir: Path) -> dict:
    ensure_dir(dump_dir)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    benign_index = int(np.where(label_encoder.classes_ == "BENIGN")[0][0])
    fit_idx = multiclass_rebalance_indices(y_train, benign_index=benign_index, benign_cap=140000, attack_cap=50000, rare_floor=2500)
    X_fit = X_train_scaled[fit_idx]
    y_fit = y_train[fit_idx]

    best = None
    candidate_params = [
        {"n_estimators": 500, "max_depth": 32, "min_samples_leaf": 1, "min_samples_split": 2, "max_features": "sqrt"},
        {"n_estimators": 700, "max_depth": None, "min_samples_leaf": 1, "min_samples_split": 2, "max_features": "sqrt"},
        {"n_estimators": 500, "max_depth": 40, "min_samples_leaf": 2, "min_samples_split": 4, "max_features": 0.6},
    ]
    labels = np.arange(len(label_encoder.classes_))
    for params in candidate_params:
        model = RandomForestClassifier(
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=42,
            **params,
        )
        model.fit(X_fit, y_fit)
        preds = model.predict(X_val_scaled)
        report = classification_report(
            y_val,
            preds,
            labels=labels,
            target_names=label_encoder.classes_,
            output_dict=True,
            zero_division=0,
        )
        candidate = {
            "model": model,
            "accuracy": float(report["accuracy"]),
            "macro_f1": float(report["macro avg"]["f1-score"]),
            "params": params,
        }
        if best is None or candidate["macro_f1"] > best["macro_f1"] or (
            candidate["macro_f1"] == best["macro_f1"] and candidate["accuracy"] > best["accuracy"]
        ):
            best = candidate

    joblib_dump_atomic(best["model"], dump_dir / "rf_model_multiclass.pkl")
    joblib_dump_atomic(scaler, dump_dir / "supervised_scaler_multiclass.pkl")
    joblib_dump_atomic([], dump_dir / "supervised_dropped_features_multiclass.pkl")
    joblib_dump_atomic(label_encoder, dump_dir / "label_encoder.pkl")
    joblib_dump_atomic(feature_names, dump_dir / "supervised_feature_names_multiclass.pkl")
    joblib_dump_atomic({"best_params": best["params"]}, dump_dir / "rf_metadata.pkl")
    return {"accuracy": best["accuracy"], "macro_f1": best["macro_f1"], "best_params": best["params"]}


def train_gbdt(X_train: np.ndarray, X_val: np.ndarray, y_train: np.ndarray, y_val: np.ndarray, feature_names: list[str], label_encoder: LabelEncoder, dump_dir: Path) -> dict:
    ensure_dir(dump_dir)
    benign_index = int(np.where(label_encoder.classes_ == "BENIGN")[0][0])
    fit_idx = multiclass_rebalance_indices(y_train, benign_index=benign_index, benign_cap=160000, attack_cap=60000, rare_floor=3000)
    X_fit = X_train[fit_idx]
    y_fit = y_train[fit_idx]
    best = None
    labels = np.arange(len(label_encoder.classes_))
    candidate_params = [
        {"learning_rate": 0.05, "max_depth": 16, "max_iter": 400, "min_samples_leaf": 20, "l2_regularization": 0.1},
        {"learning_rate": 0.03, "max_depth": 12, "max_iter": 600, "min_samples_leaf": 10, "l2_regularization": 0.2},
        {"learning_rate": 0.07, "max_depth": 10, "max_iter": 350, "min_samples_leaf": 30, "l2_regularization": 0.05},
    ]
    for params in candidate_params:
        model = HistGradientBoostingClassifier(random_state=42, **params)
        model.fit(X_fit, y_fit)
        preds = model.predict(X_val)
        report = classification_report(
            y_val,
            preds,
            labels=labels,
            target_names=label_encoder.classes_,
            output_dict=True,
            zero_division=0,
        )
        candidate = {
            "model": model,
            "accuracy": float(report["accuracy"]),
            "macro_f1": float(report["macro avg"]["f1-score"]),
            "params": params,
        }
        if best is None or candidate["macro_f1"] > best["macro_f1"] or (
            candidate["macro_f1"] == best["macro_f1"] and candidate["accuracy"] > best["accuracy"]
        ):
            best = candidate

    joblib_dump_atomic(best["model"], dump_dir / "gbdt_model_multiclass.pkl")
    joblib_dump_atomic([], dump_dir / "gbdt_dropped_features_multiclass.pkl")
    joblib_dump_atomic(label_encoder, dump_dir / "gbdt_label_encoder.pkl")
    joblib_dump_atomic(feature_names, dump_dir / "gbdt_feature_names_multiclass.pkl")
    joblib_dump_atomic({"best_params": best["params"]}, dump_dir / "gbdt_metadata.pkl")
    return {"accuracy": best["accuracy"], "macro_f1": best["macro_f1"], "best_params": best["params"], "model": best["model"]}


def train_ppo_policy(
    X_train: np.ndarray,
    X_val: np.ndarray,
    y_train_binary: np.ndarray,
    y_val_binary: np.ndarray,
    feature_names: list[str],
    dump_dir: Path,
    epochs: int,
    teacher_model,
    label_encoder: LabelEncoder,
) -> dict:
    ensure_dir(dump_dir)
    accel = configure_system_acceleration()
    device = torch.device(accel["device"])
    torch.manual_seed(42)
    np.random.seed(42)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    teacher_train_prob = teacher_attack_probability(teacher_model.predict_proba(X_train), label_encoder)
    teacher_val_prob = teacher_attack_probability(teacher_model.predict_proba(X_val), label_encoder)

    model = PPOPolicyNetwork(
        input_dim=X_train_scaled.shape[1],
        hidden_dim=hidden_dim_for_features(X_train_scaled.shape[1], minimum=32),
        action_dim=2,
    ).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=3e-4)

    states = torch.tensor(X_train_scaled, dtype=torch.float32, device=device)
    actions = torch.tensor(y_train_binary, dtype=torch.long, device=device)
    returns = torch.tensor(np.where(y_train_binary == 1, 1.0, 0.0), dtype=torch.float32, device=device)
    sampled_idx = balanced_sample_indices(y_train_binary, max_per_class=120000)
    states = states[sampled_idx]
    actions = actions[sampled_idx]
    returns = returns[sampled_idx]
    teacher_targets = torch.tensor(teacher_train_prob[sampled_idx], dtype=torch.float32, device=device)

    present_classes = np.unique(actions.detach().cpu().numpy())
    class_weights = compute_class_weight(class_weight="balanced", classes=present_classes, y=actions.detach().cpu().numpy())
    expanded_weights = np.ones(2, dtype=np.float32)
    for cls, weight in zip(present_classes, class_weights):
        expanded_weights[int(cls)] = float(weight)
    class_weights_t = torch.tensor(expanded_weights, dtype=torch.float32, device=device)

    for _ in range(max(4, epochs)):
        logits, values = model(states)
        supervised_loss = F.cross_entropy(logits, actions, weight=class_weights_t)
        attack_logits = logits[:, 1] - logits[:, 0]
        distill_loss = F.binary_cross_entropy_with_logits(attack_logits, teacher_targets)
        value_loss = F.mse_loss(values, returns)
        loss = 0.7 * supervised_loss + 0.3 * distill_loss + 0.5 * value_loss
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

    for _ in range(epochs):
        logits_old, _ = model(states)
        dist_old = torch.distributions.Categorical(logits=logits_old.detach())
        old_log_probs = dist_old.log_prob(actions)

        for _ in range(4):
            logits, values = model(states)
            dist = torch.distributions.Categorical(logits=logits)
            log_probs = dist.log_prob(actions)
            advantages = (returns - values.detach())
            ratios = torch.exp(log_probs - old_log_probs)
            clipped = torch.clamp(ratios, 0.8, 1.2) * advantages
            policy_loss = -torch.min(ratios * advantages, clipped).mean()
            supervised_loss = F.cross_entropy(logits, actions, weight=class_weights_t)
            attack_logits = logits[:, 1] - logits[:, 0]
            distill_loss = F.binary_cross_entropy_with_logits(attack_logits, teacher_targets)
            value_loss = F.mse_loss(values, returns)
            entropy_bonus = dist.entropy().mean()
            loss = 0.4 * policy_loss + 0.6 * supervised_loss + 0.25 * distill_loss + 0.4 * value_loss - 0.01 * entropy_bonus
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

    model.eval()
    with torch.no_grad():
        train_logits, _ = model(torch.tensor(X_train_scaled, dtype=torch.float32, device=device))
        train_probs_full = torch.softmax(train_logits, dim=1)[:, 1].cpu().numpy()
        logits, _ = model(torch.tensor(X_val_scaled, dtype=torch.float32, device=device))
        val_probs = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
    fpr, tpr, roc_thresholds = roc_curve(y_train_binary, train_probs_full)
    best_idx = int(np.argmax(tpr - fpr))
    decision_threshold = float(roc_thresholds[best_idx])
    preds = (val_probs >= decision_threshold).astype(np.int64)
    thresholds = {
        "low": float(np.quantile(train_probs_full, 0.70)),
        "medium": float(np.quantile(train_probs_full, 0.88)),
        "high": float(np.quantile(train_probs_full, 0.96)),
    }

    torch_save_atomic(
        {
            "state_dict": model.state_dict(),
            "input_dim": X_train_scaled.shape[1],
            "hidden_dim": hidden_dim_for_features(X_train_scaled.shape[1], minimum=32),
            "action_labels": ["normal", "attack"],
            "decision_threshold": decision_threshold,
            "risk_thresholds": thresholds,
        },
        dump_dir / "ppo_policy.pt",
    )
    joblib_dump_atomic(scaler, dump_dir / "ppo_scaler.pkl")
    joblib_dump_atomic(feature_names, dump_dir / "ppo_feature_names.pkl")

    return {
        "binary_accuracy": float((preds == y_val_binary).mean()),
        "roc_auc": float(roc_auc_score(y_val_binary, val_probs)),
        "decision_threshold": decision_threshold,
        "high_risk_rate": float((val_probs >= thresholds["high"]).mean()),
        "teacher_alignment": float((((val_probs >= decision_threshold).astype(np.int64)) == (teacher_val_prob >= 0.5).astype(np.int64)).mean()),
        "risk_thresholds": thresholds,
    }


def train_gnn(X_train: np.ndarray, X_val: np.ndarray, y_train_binary: np.ndarray, y_val_binary: np.ndarray, feature_names: list[str], dump_dir: Path, epochs: int) -> dict:
    ensure_dir(dump_dir)
    accel = configure_system_acceleration()
    device = torch.device(accel["device"])
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    sampled_idx = balanced_sample_indices(y_train_binary, max_per_class=12000)
    X_train_scaled = X_train_scaled[sampled_idx]
    y_train_binary = y_train_binary[sampled_idx]

    train_x = torch.tensor(X_train_scaled, dtype=torch.float32, device=device)
    val_x = torch.tensor(X_val_scaled, dtype=torch.float32, device=device)
    train_y = torch.tensor(y_train_binary, dtype=torch.long, device=device)
    best = None
    class_weights = compute_class_weight(class_weight="balanced", classes=np.array([0, 1]), y=y_train_binary)
    class_weights_t = torch.tensor(class_weights, dtype=torch.float32, device=device)
    for k_neighbors in (6, 8, 12):
        train_edges = knn_edge_index(train_x, k=k_neighbors)
        val_edges = knn_edge_index(val_x, k=k_neighbors)
        model = FlowGNN(input_dim=train_x.shape[1], hidden_dim=hidden_dim_for_features(train_x.shape[1], minimum=32), output_dim=2).to(device)
        optimizer = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-4)
        for _ in range(epochs):
            model.train()
            logits = model(train_x, train_edges)
            loss = F.cross_entropy(logits, train_y, weight=class_weights_t)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            train_logits = model(train_x, train_edges)
            train_probs = torch.softmax(train_logits, dim=1)[:, 1].cpu().numpy()
            val_logits = model(val_x, val_edges)
            val_probs = torch.softmax(val_logits, dim=1)[:, 1].cpu().numpy()
        fpr, tpr, thresholds = roc_curve(y_train_binary, train_probs)
        best_idx = int(np.argmax(tpr - fpr))
        decision_threshold = float(thresholds[best_idx])
        val_preds = (val_probs >= decision_threshold).astype(np.int64)
        candidate = {
            "model": model,
            "k_neighbors": k_neighbors,
            "decision_threshold": decision_threshold,
            "binary_accuracy": float((val_preds == y_val_binary).mean()),
            "roc_auc": float(roc_auc_score(y_val_binary, val_probs)),
        }
        if best is None or candidate["roc_auc"] > best["roc_auc"] or (
            candidate["roc_auc"] == best["roc_auc"] and candidate["binary_accuracy"] > best["binary_accuracy"]
        ):
            best = candidate

    torch_save_atomic(
        {
            "state_dict": best["model"].state_dict(),
            "input_dim": train_x.shape[1],
            "hidden_dim": hidden_dim_for_features(train_x.shape[1], minimum=32),
            "output_dim": 2,
            "k_neighbors": best["k_neighbors"],
            "decision_threshold": best["decision_threshold"],
        },
        dump_dir / "gnn_model.pt",
    )
    joblib_dump_atomic(scaler, dump_dir / "gnn_scaler.pkl")
    joblib_dump_atomic([], dump_dir / "gnn_dropped_features.pkl")
    joblib_dump_atomic(feature_names, dump_dir / "gnn_feature_names.pkl")

    return {
        "binary_accuracy": best["binary_accuracy"],
        "roc_auc": best["roc_auc"],
        "decision_threshold": best["decision_threshold"],
        "k_neighbors": best["k_neighbors"],
    }


def export_report(report_path: Path, metrics: dict) -> None:
    report_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")


def safe_stratify_labels(labels: np.ndarray) -> np.ndarray | None:
    _, counts = np.unique(labels, return_counts=True)
    return labels if counts.min() >= 2 else None


def balanced_sample_indices(labels: np.ndarray, max_per_class: int, seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    selected = []
    for cls in np.unique(labels):
        cls_idx = np.flatnonzero(labels == cls)
        take = min(max_per_class, len(cls_idx))
        if take == len(cls_idx):
            selected.append(cls_idx)
        else:
            selected.append(rng.choice(cls_idx, size=take, replace=False))
    result = np.concatenate(selected)
    rng.shuffle(result)
    return result


def apply_profile_defaults(args) -> None:
    profile = getattr(args, "profile", "balanced")
    if profile == "fast":
        if args.per_file_rows is None:
            args.per_file_rows = 25000
        args.gnn_rows = min(args.gnn_rows, 8000)
        args.ae_epochs = min(args.ae_epochs, 4)
        args.ppo_epochs = min(args.ppo_epochs, 4)
        args.gnn_epochs = min(args.gnn_epochs, 4)
        args.batch_size = max(args.batch_size, 1024)
    elif profile == "balanced":
        if args.per_file_rows is None:
            args.per_file_rows = 50000
        args.gnn_rows = min(args.gnn_rows, 20000)
        args.batch_size = max(args.batch_size, 2048)
    elif profile == "full":
        args.batch_size = max(args.batch_size, 4096)


def main() -> None:
    parser = argparse.ArgumentParser(description="Download CICIDS2017 and retrain network intrusion models.")
    parser.add_argument("--download", action="store_true", help="Download CICIDS2017 CSV files before training.")
    parser.add_argument("--download-cicids2018", action="store_true", help="Download official CSE-CIC-IDS2018 processed CSV files before training.")
    parser.add_argument("--overwrite-downloads", action="store_true", help="Re-download dataset files even if they already exist.")
    parser.add_argument("--dataset-dir", default=str(DATASET_DIR))
    parser.add_argument("--profile", choices=["fast", "balanced", "full"], default="balanced", help="Training runtime profile.")
    parser.add_argument("--per-file-rows", type=int, default=None, help="Optional cap per CSV for faster smoke runs.")
    parser.add_argument("--gnn-rows", type=int, default=30000, help="Rows used to train the GNN subset.")
    parser.add_argument("--ppo-epochs", type=int, default=12)
    parser.add_argument("--ae-epochs", type=int, default=20)
    parser.add_argument("--gnn-epochs", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--skip-ae", action="store_true")
    parser.add_argument("--skip-iso", action="store_true")
    parser.add_argument("--skip-kmeans", action="store_true")
    args = parser.parse_args()
    apply_profile_defaults(args)
    accel = configure_system_acceleration()

    dataset_dir = Path(args.dataset_dir)
    if args.download:
        print("Downloading dataset...")
        download_dataset(dataset_dir, overwrite=args.overwrite_downloads)
    if args.download_cicids2018:
        print("Downloading official CSE-CIC-IDS2018 processed CSV files...")
        download_cse_cic_ids2018(dataset_dir, overwrite=args.overwrite_downloads)

    print(
        f"System acceleration: cpu_threads={accel['cpu_threads']} "
        f"device={accel['device']} gpu={accel['gpu_name'] or 'none'}"
    )
    print(f"Loading dataset with profile={args.profile} per_file_rows={args.per_file_rows} ...")
    df = load_dataset(dataset_dir, per_file_rows=args.per_file_rows)
    print(f"Loaded {len(df)} rows with {df['label'].nunique()} labels.")
    X_numeric, dropped_features = select_numeric_features(df)
    y_binary = make_binary_labels(df)

    label_encoder = LabelEncoder()
    y_multi = label_encoder.fit_transform(df["label"])

    X_train, X_val, y_train_multi, y_val_multi, y_train_binary, y_val_binary = train_test_split(
        X_numeric.to_numpy(dtype=np.float32),
        y_multi,
        y_binary,
        test_size=0.2,
        stratify=safe_stratify_labels(y_multi),
        random_state=42,
    )

    X_train_benign = X_train[y_train_binary == 0]

    metrics = {
        "profile": args.profile,
        "dataset_rows": int(len(df)),
        "feature_count": int(X_numeric.shape[1]),
        "dropped_correlated_features": dropped_features,
    }

    if not args.skip_ae:
        print("Training autoencoder...")
        metrics["autoencoder"] = train_autoencoder(
            X_train_benign,
            X_val,
            y_val_binary,
            X_numeric.columns.tolist(),
            ROOT / "AutoEncoderDumps",
            epochs=args.ae_epochs,
            batch_size=args.batch_size,
        )
    else:
        metrics["autoencoder"] = {"skipped": True}
    if not args.skip_iso:
        print("Training isolation forest...")
        metrics["isolation_forest"] = train_isolation_forest(X_train_benign, X_val, y_val_binary, X_numeric.columns.tolist(), ROOT / "IsoDumps")
    else:
        metrics["isolation_forest"] = {"skipped": True}
    if not args.skip_kmeans:
        print("Training k-means...")
        metrics["kmeans"] = train_kmeans(X_train_benign, X_val, y_val_binary, X_numeric.columns.tolist(), ROOT / "KmeansDumps")
    else:
        metrics["kmeans"] = {"skipped": True}
    print("Training random forest...")
    metrics["random_forest"] = train_random_forest(
        X_train,
        X_val,
        y_train_multi,
        y_val_multi,
        X_numeric.columns.tolist(),
        label_encoder,
        ROOT / "RandomForestDumps",
    )
    print("Training gradient boosted tree...")
    gbdt_result = train_gbdt(
        X_train,
        X_val,
        y_train_multi,
        y_val_multi,
        X_numeric.columns.tolist(),
        label_encoder,
        ROOT / "GradientBoostedDumps",
    )
    metrics["gradient_boosted_tree"] = {k: v for k, v in gbdt_result.items() if k != "model"}
    print("Training PPO policy...")
    metrics["ppo_policy"] = train_ppo_policy(
        X_train,
        X_val,
        y_train_binary,
        y_val_binary,
        X_numeric.columns.tolist(),
        ROOT / "PPODumps",
        epochs=args.ppo_epochs,
        teacher_model=gbdt_result["model"],
        label_encoder=label_encoder,
    )

    gnn_rows = min(args.gnn_rows, len(X_numeric))
    gnn_df = df.sample(n=gnn_rows, random_state=42) if gnn_rows < len(df) else df
    gnn_features, _ = select_numeric_features(gnn_df)
    gnn_binary = make_binary_labels(gnn_df)
    X_gnn_train, X_gnn_val, y_gnn_train, y_gnn_val = train_test_split(
        gnn_features.to_numpy(dtype=np.float32),
        gnn_binary,
        test_size=0.2,
        stratify=safe_stratify_labels(gnn_binary),
        random_state=42,
    )
    print("Training GNN detector...")
    metrics["gnn_detector"] = train_gnn(
        X_gnn_train,
        X_gnn_val,
        y_gnn_train,
        y_gnn_val,
        gnn_features.columns.tolist(),
        ROOT / "GNNDumps",
        epochs=args.gnn_epochs,
    )

    print("Writing training report...")
    export_report(ROOT / "training_report.json", metrics)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
