#!/usr/bin/env python3
"""
PCAP Replay Tool with GUI
CSCI480 Layered IDS/IPS - Senior Capstone Project
Simple GUI for replaying PCAP files using Scapy
"""

import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.all import *
import os

class PCAPReplayGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PCAP Replay Tool - CSCI480 IDS/IPS")
        self.root.geometry("500x400")
        
        self.selected_file = None
        self.interface = self.get_wifi_interface()
        
        self.create_widgets()
    
    def get_wifi_interface(self):
        """Get WiFi interface name"""
        try:
            interfaces = get_if_list()
            wifi_names = ['Wi-Fi', 'WiFi', 'Wireless', 'wlan', 'WLAN']
            for iface in interfaces:
                for wifi_name in wifi_names:
                    if wifi_name.lower() in iface.lower():
                        return iface
            return interfaces[0] if interfaces else None
        except:
            return None
    
    def create_widgets(self):
        """Create GUI widgets"""
        # Title
        title = tk.Label(self.root, text="PCAP Replay Tool", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # File selection
        file_frame = tk.Frame(self.root)
        file_frame.pack(pady=10)
        
        tk.Label(file_frame, text="PCAP File:").pack(side=tk.LEFT)
        self.file_label = tk.Label(file_frame, text="No file selected", fg="gray")
        self.file_label.pack(side=tk.LEFT, padx=5)
        
        tk.Button(file_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT)
        
        # Interface selection
        if_frame = tk.Frame(self.root)
        if_frame.pack(pady=10)
        
        tk.Label(if_frame, text="Interface:").pack(side=tk.LEFT)
        self.interface_label = tk.Label(if_frame, text=self.interface or "No interface found")
        self.interface_label.pack(side=tk.LEFT, padx=5)
        
        # Available PCAP files
        pcap_frame = tk.Frame(self.root)
        pcap_frame.pack(pady=10)
        
        tk.Label(pcap_frame, text="Available PCAP Files:", font=("Arial", 10, "bold")).pack()
        
        self.pcap_listbox = tk.Listbox(pcap_frame, height=6)
        self.pcap_listbox.pack(fill=tk.X, padx=10)
        
        self.load_pcap_files()
        
        # Replay button
        self.replay_button = tk.Button(self.root, text="Replay PCAP", command=self.replay_pcap, 
                                       bg="#4CAF50", fg="white", font=("Arial", 12), state=tk.DISABLED)
        self.replay_button.pack(pady=20)
        
        # Status
        self.status_label = tk.Label(self.root, text="Ready", fg="green")
        self.status_label.pack(pady=5)
        
        # Bind listbox selection
        self.pcap_listbox.bind('<<ListboxSelect>>', self.on_pcap_select)
    
    def load_pcap_files(self):
        """Load available PCAP files"""
        pcap_files = [f for f in os.listdir('.') if f.endswith('.pcap')]
        for f in pcap_files:
            self.pcap_listbox.insert(tk.END, f)
    
    def on_pcap_select(self, event):
        """Handle PCAP file selection from listbox"""
        selection = self.pcap_listbox.curselection()
        if selection:
            self.selected_file = self.pcap_listbox.get(selection[0])
            self.file_label.config(text=self.selected_file, fg="black")
            self.replay_button.config(state=tk.NORMAL)
    
    def browse_file(self):
        """Browse for PCAP file"""
        file_path = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")]
        )
        if file_path:
            self.selected_file = os.path.basename(file_path)
            self.file_label.config(text=self.selected_file, fg="black")
            self.replay_button.config(state=tk.NORMAL)
    
    def replay_pcap(self):
        """Replay selected PCAP file"""
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a PCAP file first")
            return
        
        if not os.path.exists(self.selected_file):
            messagebox.showerror("Error", f"File not found: {self.selected_file}")
            return
        
        self.status_label.config(text="Replaying...", fg="orange")
        self.root.update()
        
        try:
            packets = rdpcap(self.selected_file)
            self.status_label.config(text=f"Sending {len(packets)} packets...", fg="blue")
            self.root.update()
            
            for i, packet in enumerate(packets):
                sendp(packet, iface=self.interface, verbose=False)
                if (i + 1) % 10 == 0:
                    self.status_label.config(text=f"Sent {i + 1}/{len(packets)} packets...", fg="blue")
                    self.root.update()
            
            self.status_label.config(text=f"Done! Sent {len(packets)} packets", fg="green")
            messagebox.showinfo("Success", f"Successfully replayed {len(packets)} packets")
            
        except Exception as e:
            self.status_label.config(text="Error", fg="red")
            messagebox.showerror("Error", f"Failed to replay PCAP: {e}")

def main():
    root = tk.Tk()
    app = PCAPReplayGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
