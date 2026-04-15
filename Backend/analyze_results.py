#!/usr/bin/env python3
"""
Analysis script for live network test results.
Provides detailed analysis of captured flows and model predictions.

Usage:
    python analyze_results.py live_test_results.csv
    python analyze_results.py live_test_results.csv --risk high
    python analyze_results.py live_test_results.csv --anomalies
"""

import argparse
import sys
import pandas as pd
from pathlib import Path
from collections import Counter


def load_results(filepath):
    """Load and validate results CSV."""
    try:
        df = pd.read_csv(filepath)
        print(f"✓ Loaded {len(df)} flows from {filepath}\n")
        return df
    except FileNotFoundError:
        print(f"✗ File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error loading file: {e}")
        sys.exit(1)


def print_overview(df):
    """Print overview statistics."""
    print("="*70)
    print("OVERVIEW")
    print("="*70)
    print(f"Total flows captured: {len(df)}")
    print(f"Date range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    print()


def print_ensemble_risk_distribution(df):
    """Analyze ensemble risk distribution."""
    print("="*70)
    print("ENSEMBLE RISK DISTRIBUTION")
    print("="*70)
    
    if 'ensemble_risk' not in df.columns:
        print("⚠️  'ensemble_risk' column not found in results")
        return
    
    risk_dist = df['ensemble_risk'].value_counts()
    total = len(df)
    
    risk_order = ['high', 'medium', 'low', 'normal', 'error']
    for risk in risk_order:
        if risk in risk_dist.index:
            count = risk_dist[risk]
            pct = (count / total * 100)
            bar = "█" * int(pct / 2)
            print(f"{risk.upper():8} : {count:4} ({pct:5.1f}%) {bar}")
    print()


def print_model_agreement(df):
    """Analyze model prediction agreement."""
    print("="*70)
    print("MODEL AGREEMENT ANALYSIS")
    print("="*70)
    
    required_cols = ['ae_anomaly', 'iso_risk', 'kmeans_risk', 'rf_labels']
    missing = [col for col in required_cols if col not in df.columns]
    
    if missing:
        print(f"⚠️  Missing columns: {missing}")
        return
    
    # Convert risks to binary consistent format
    ae_anomalies = (df['ae_anomaly'] == True).sum()
    iso_high = (df['iso_risk'] == 'high').sum()
    km_high = (df['kmeans_risk'] == 'high').sum()
    
    print(f"AutoEncoder anomalies: {ae_anomalies:4} ({ae_anomalies/len(df)*100:5.1f}%)")
    print(f"IsoForest high-risk  : {iso_high:4} ({iso_high/len(df)*100:5.1f}%)")
    print(f"KMeans high-risk     : {km_high:4} ({km_high/len(df)*100:5.1f}%)")
    
    # Check agreement
    high_risk_mask = (df['iso_risk'] == 'high') | (df['kmeans_risk'] == 'high')
    agreement = ((df['ae_anomaly']) & (high_risk_mask)).sum()
    print(f"\nAll 3 models agree   : {agreement:4} ({agreement/len(df)*100:5.1f}%)")
    print()


def print_rf_classification(df):
    """Analyze RandomForest multiclass predictions."""
    print("="*70)
    print("SUPERVISED LEARNING CLASSIFICATION (RandomForest)")
    print("="*70)
    
    if 'rf_labels' not in df.columns:
        print("⚠️  'rf_labels' column not found")
        return
    
    label_dist = df['rf_labels'].value_counts()
    print(f"Unique traffic classes: {len(label_dist)}\n")
    
    for label, count in label_dist.head(15).items():
        pct = (count / len(df) * 100)
        bar = "█" * int(pct / 2)
        print(f"{str(label):20} : {count:4} ({pct:5.1f}%) {bar}")
    
    if len(label_dist) > 15:
        print(f"... and {len(label_dist) - 15} more")
    print()


def print_high_risk_flows(df, limit=20):
    """Print high-risk flows."""
    print("="*70)
    print(f"HIGH-RISK FLOWS (Top {limit})")
    print("="*70)
    
    high_risk = df[df.get('ensemble_risk', None) == 'high']
    
    if high_risk.empty:
        print("No high-risk flows detected.\n")
        return
    
    print(f"Total: {len(high_risk)} flows\n")
    
    display_cols = ['src_ip', 'dst_ip', 'proto', 'sport', 'dport', 
                   'total_fwd_packets', 'flow_bytes/s', 'ae_anomaly', 
                   'iso_risk', 'kmeans_risk', 'rf_labels']
    
    available_cols = [col for col in display_cols if col in high_risk.columns]
    
    for idx, (_, flow) in enumerate(high_risk.head(limit).iterrows(), 1):
        print(f"{idx}. {flow['src_ip']} -> {flow['dst_ip']}:{flow['dport']} (proto={flow['proto']})")
        print(f"   Packets: {flow.get('total_fwd_packets', 'N/A')} | Bytes/s: {flow.get('flow_bytes/s', 'N/A'):.0f}")
        print(f"   AE: {flow.get('ae_anomaly', 'N/A')} | ISO: {flow.get('iso_risk', 'N/A'):6} | KMeans: {flow.get('kmeans_risk', 'N/A'):6} | RF: {flow.get('rf_labels', 'N/A')}")
        print()
    
    if len(high_risk) > limit:
        print(f"... and {len(high_risk) - limit} more high-risk flows")
    print()


def print_anomalies(df, limit=20):
    """Print flows detected as anomalies by AutoEncoder."""
    print("="*70)
    print(f"AUTOENCODER ANOMALIES (Top {limit})")
    print("="*70)
    
    if 'ae_anomaly' not in df.columns:
        print("⚠️  'ae_anomaly' column not found")
        return
    
    anomalies = df[df['ae_anomaly'] == True]
    
    if anomalies.empty:
        print("No anomalies detected.\n")
        return
    
    print(f"Total: {len(anomalies)} anomalies ({len(anomalies)/len(df)*100:.1f}%)\n")
    
    for idx, (_, flow) in enumerate(anomalies.head(limit).iterrows(), 1):
        print(f"{idx}. {flow['src_ip']:15} -> {flow['dst_ip']:15}:{flow['dport']:5} | {flow.get('rf_labels', 'N/A'):15} | Ensemble: {flow.get('ensemble_risk', 'N/A')}")
    
    if len(anomalies) > limit:
        print(f"... and {len(anomalies) - limit} more")
    print()


def print_top_destinations(df, limit=20):
    """Print most contacted destinations."""
    print("="*70)
    print(f"TOP DESTINATIONS (Top {limit})")
    print("="*70)
    
    dest_counts = df['dst_ip'].value_counts()
    
    for idx, (dest, count) in enumerate(dest_counts.head(limit).items(), 1):
        pct = (count / len(df) * 100)
        
        # Show any high-risk flows to this destination
        dest_flows = df[df['dst_ip'] == dest]
        high_risk_to_dest = (dest_flows.get('ensemble_risk', None) == 'high').sum() if 'ensemble_risk' in dest_flows.columns else 0
        
        risk_indicator = f" [⚠️  {high_risk_to_dest} high-risk]" if high_risk_to_dest > 0 else ""
        
        print(f"{idx:2}. {dest:15} : {count:4} flows ({pct:5.1f}%){risk_indicator}")
    
    print()


def print_port_analysis(df, limit=20):
    """Analyze destination ports."""
    print("="*70)
    print(f"TOP DESTINATION PORTS (Top {limit})")
    print("="*70)
    
    if 'dport' not in df.columns:
        print("⚠️  'dport' column not found")
        return
    
    port_counts = df['dport'].value_counts()
    common_ports = {
        80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 
        25: 'SMTP', 53: 'DNS', 3306: 'MySQL', 5432: 'PostgreSQL',
        8080: 'HTTP-alt', 3389: 'RDP', 139: 'NetBIOS', 445: 'SMB'
    }
    
    for idx, (port, count) in enumerate(port_counts.head(limit).items(), 1):
        pct = (count / len(df) * 100)
        service = common_ports.get(port, 'Unknown')
        print(f"{idx:2}. {port:5} ({service:12}) : {count:4} flows ({pct:5.1f}%)")
    
    print()


def print_protocol_analysis(df):
    """Analyze protocols."""
    print("="*70)
    print("PROTOCOL DISTRIBUTION")
    print("="*70)
    
    if 'proto' not in df.columns:
        print("⚠️  'proto' column not found")
        return
    
    proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 41: 'IPv6'}
    proto_counts = df['proto'].value_counts()
    
    for proto, count in proto_counts.items():
        pct = (count / len(df) * 100)
        proto_name = proto_map.get(proto, f'Other ({proto})')
        bar = "█" * int(pct / 2)
        print(f"{proto_name:20} : {count:4} ({pct:5.1f}%) {bar}")
    
    print()


def filter_and_export(df, filter_type, output_file):
    """Filter and export results."""
    if filter_type == 'high':
        filtered = df[df['ensemble_risk'] == 'high']
    elif filter_type == 'anomalies':
        filtered = df[df['ae_anomaly'] == True]
    elif filter_type == 'medium_high':
        filtered = df[df['ensemble_risk'].isin(['high', 'medium'])]
    else:
        print(f"Unknown filter type: {filter_type}")
        return
    
    if not filtered.empty:
        filtered.to_csv(output_file, index=False)
        print(f"✓ Exported {len(filtered)} flows to {output_file}")
    else:
        print(f"No flows matched filter '{filter_type}'")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze live network test results',
        epilog='Example: python analyze_results.py live_test_results.csv --risk high'
    )
    parser.add_argument('input_file',
                       help='CSV results file from test_live_network.py')
    parser.add_argument('--risk', choices=['high', 'medium', 'medium_high'],
                       help='Filter and export specific risk level')
    parser.add_argument('--anomalies', action='store_true',
                       help='Filter and export anomalies')
    parser.add_argument('--output', '-o', default=None,
                       help='Output file for filtered results')
    
    args = parser.parse_args()
    
    df = load_results(args.input_file)
    
    # Print full analysis
    print_overview(df)
    print_ensemble_risk_distribution(df)
    print_model_agreement(df)
    print_rf_classification(df)
    print_port_analysis(df)
    print_protocol_analysis(df)
    print_top_destinations(df)
    print_high_risk_flows(df)
    print_anomalies(df)
    
    # Handle filtering/export
    if args.risk or args.anomalies:
        if not args.output:
            print("⚠️  --output required when using --risk or --anomalies")
            return
        
        if args.anomalies:
            filter_and_export(df, 'anomalies', args.output)
        else:
            filter_and_export(df, args.risk, args.output)


if __name__ == '__main__':
    main()
