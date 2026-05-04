#!/usr/bin/env python3
"""
Demo Orchestrator for CSCI480 Layered IDS/IPS
CSCI480 Layered IDS/IPS - Senior Capstone Project
Orchestrates a scripted demo sequence showing all system features
"""

import time
import subprocess
import sys
from datetime import datetime

class DemoOrchestrator:
    def __init__(self):
        self.target_ip = "127.0.0.1"
        self.target_port = 5000
        self.scenarios = []
    
    def print_header(self, title):
        print("\n" + "=" * 70)
        print(title)
        print("=" * 70 + "\n")
    
    def print_step(self, step_num, description):
        print(f"\n[STEP {step_num}] {description}")
        print("-" * 70)
    
    def wait_for_user(self, message="Press Enter to continue..."):
        input(f"\n{message}")
    
    def scenario_1_benign_baseline(self):
        """Scenario 1: Baseline Detection"""
        self.print_step(1, "Benign Traffic Baseline (2 minutes)")
        print("This scenario demonstrates normal traffic classification.")
        print()
        print("Instructions:")
        print("1. Ensure IDS/IPS system is running")
        print("2. Start capture on your network interface")
        print("3. Run the benign traffic generator")
        print("4. Observe traffic classified as NORMAL/LOW risk")
        print()
        
        self.wait_for_user("Press Enter to start benign traffic generation...")
        
        try:
            subprocess.run([sys.executable, "generate_benign_traffic.py"], 
                          cwd=".", timeout=120)
        except subprocess.TimeoutExpired:
            print("\n[INFO] Benign traffic generation completed (2 minutes)")
        except KeyboardInterrupt:
            print("\n[INFO] Stopped by user")
    
    def scenario_2_port_scan(self):
        """Scenario 2: Port Scan Detection"""
        self.print_step(2, "Port Scan Detection (2 minutes)")
        print("This scenario demonstrates port scanning detection.")
        print()
        print("Instructions:")
        print("1. Ensure IDS/IPS system is running and capturing")
        print("2. Run the port scan simulator")
        print("3. Observe MEDIUM/HIGH risk scores")
        print("4. Check if decoys are automatically deployed")
        print()
        
        self.wait_for_user("Press Enter to start port scan simulation...")
        
        try:
            # Run with stdin to automatically select option 1
            process = subprocess.Popen(
                [sys.executable, "simulate_port_scan.py"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            process.communicate(input="1\n", timeout=120)
        except subprocess.TimeoutExpired:
            print("\n[INFO] Port scan simulation completed (2 minutes)")
        except KeyboardInterrupt:
            print("\n[INFO] Stopped by user")
    
    def scenario_3_dos_attack(self):
        """Scenario 3: DoS Attack Detection"""
        self.print_step(3, "DoS Attack Detection (2 minutes)")
        print("This scenario demonstrates DoS/flood attack detection.")
        print()
        print("Instructions:")
        print("1. Ensure IDS/IPS system is running and capturing")
        print("2. Ensure prevention is enabled in Defense & Prevention tab")
        print("3. Run the DoS simulator")
        print("4. Observe HIGH risk scores and automatic blocking")
        print()
        
        self.wait_for_user("Press Enter to start DoS simulation...")
        
        try:
            # Run with stdin to automatically select option 1
            process = subprocess.Popen(
                [sys.executable, "simulate_dos.py"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            process.communicate(input="1\n", timeout=120)
        except subprocess.TimeoutExpired:
            print("\n[INFO] DoS simulation completed (2 minutes)")
        except KeyboardInterrupt:
            print("\n[INFO] Stopped by user")
    
    def scenario_4_pcap_replay(self):
        """Scenario 4: PCAP Replay Analysis"""
        self.print_step(4, "PCAP Replay Analysis (2 minutes)")
        print("This scenario demonstrates historical traffic analysis.")
        print()
        print("Instructions:")
        print("1. Ensure IDS/IPS system is running")
        print("2. Navigate to PCAP Replay tab in dashboard")
        print("3. Upload an attack PCAP file from Dataset folder")
        print("4. Observe attack classification and model agreement")
        print()
        
        self.wait_for_user("Press Enter when ready to proceed...")
        print("[INFO] Please manually upload a PCAP file via the dashboard")
        print("[INFO] Recommended: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    
    def scenario_5_decoy_deployment(self):
        """Scenario 5: Decoy Deployment"""
        self.print_step(5, "Adaptive Decoy Deployment (1 minute)")
        print("This scenario demonstrates threat deception.")
        print()
        print("Instructions:")
        print("1. Navigate to Defense & Prevention tab")
        print("2. Deploy a decoy (e.g., fake_ssh)")
        print("3. Observe decoy appears in active list")
        print("4. Note the port and protocol information")
        print()
        
        self.wait_for_user("Press Enter when decoy is deployed...")
        print("[INFO] Decoy deployment demonstrated")
    
    def run_full_demo(self):
        """Run complete demo sequence"""
        self.print_header("CSCI480 LAYERED IDS/IPS - FULL DEMO ORCHESTRATION")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Target: {self.target_ip}:{self.target_port}")
        print(f"Estimated Duration: 9 minutes")
        print()
        print("This orchestrator will guide you through all demo scenarios.")
        print("Press Ctrl+C at any time to skip a scenario or exit.")
        print()
        
        self.wait_for_user("Press Enter to begin the demo...")
        
        try:
            # Scenario 1: Benign Baseline
            self.scenario_1_benign_baseline()
            time.sleep(2)
            
            # Scenario 2: Port Scan
            self.scenario_2_port_scan()
            time.sleep(2)
            
            # Scenario 3: DoS Attack
            self.scenario_3_dos_attack()
            time.sleep(2)
            
            # Scenario 4: PCAP Replay
            self.scenario_4_pcap_replay()
            time.sleep(2)
            
            # Scenario 5: Decoy Deployment
            self.scenario_5_decoy_deployment()
            
            # Demo Complete
            self.print_header("DEMO COMPLETE")
            print("All scenarios have been demonstrated.")
            print()
            print("Summary:")
            print("- Benign traffic classification (NORMAL/LOW risk)")
            print("- Port scan detection (MEDIUM/HIGH risk)")
            print("- DoS attack detection (HIGH risk + auto-blocking)")
            print("- PCAP replay analysis (historical attack detection)")
            print("- Adaptive decoy deployment (threat deception)")
            print()
            print("Thank you for viewing the CSCI480 Layered IDS/IPS demonstration!")
            print()
            
        except KeyboardInterrupt:
            print("\n[INFO] Demo orchestration stopped by user")
            print("[INFO] You can continue with individual scenarios")
    
    def run_custom_scenario(self, scenario_num):
        """Run a specific scenario"""
        scenarios = {
            "1": ("Benign Baseline", self.scenario_1_benign_baseline),
            "2": ("Port Scan Detection", self.scenario_2_port_scan),
            "3": ("DoS Attack Detection", self.scenario_3_dos_attack),
            "4": ("PCAP Replay Analysis", self.scenario_4_pcap_replay),
            "5": ("Decoy Deployment", self.scenario_5_decoy_deployment),
        }
        
        if scenario_num in scenarios:
            name, func = scenarios[scenario_num]
            self.print_header(f"SCENARIO {scenario_num}: {name.upper()}")
            func()
        else:
            print("[ERROR] Invalid scenario number")

if __name__ == "__main__":
    print("=" * 70)
    print("CSCI480 LAYERED IDS/IPS - DEMO ORCHESTRATOR")
    print("=" * 70)
    print()
    print("Choose demo mode:")
    print("1. Full Demo (all scenarios, ~9 minutes)")
    print("2. Individual Scenario")
    print()
    
    try:
        choice = input("Enter choice (1-2): ").strip()
        
        orchestrator = DemoOrchestrator()
        
        if choice == "1":
            orchestrator.run_full_demo()
        elif choice == "2":
            print("\nAvailable scenarios:")
            print("1. Benign Baseline")
            print("2. Port Scan Detection")
            print("3. DoS Attack Detection")
            print("4. PCAP Replay Analysis")
            print("5. Decoy Deployment")
            print()
            
            scenario = input("Enter scenario number (1-5): ").strip()
            orchestrator.run_custom_scenario(scenario)
        else:
            print("[INFO] Invalid choice, running full demo")
            orchestrator.run_full_demo()
            
    except KeyboardInterrupt:
        print("\n[INFO] Exiting")
