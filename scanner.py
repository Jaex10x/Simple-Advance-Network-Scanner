import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import ARP, Ether, srp, wrpcap
import socket
import requests
import threading
import time


def get_local_subnet():
    local_ip = socket.gethostbyname(socket.gethostname())
    return ".".join(local_ip.split(".")[:-1]) + ".0/24"


def get_mac_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return "Unknown Vendor"


def scan_network(target_ip, tree, progress_label):
    progress_label.config(text=f"Scanning {target_ip}...")
    tree.delete(*tree.get_children())
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=5, verbose=0)[0]
    clients = []

    for _, received in result:
        vendor = get_mac_vendor(received.hwsrc)
        clients.append({"ip": received.psrc, "mac": received.hwsrc, "vendor": vendor})
        tree.insert("", tk.END, values=(received.psrc, received.hwsrc, vendor))

    progress_label.config(text=f"Scan complete! {len(clients)} devices found.")
    return clients


def save_to_pcap(clients):
    if not clients:
        messagebox.showwarning("No Data", "No devices to save. Please scan first.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
    if not file_path:
        return

    packets = []
    for client in clients:
        arp = ARP(pdst=client["ip"], hwdst=client["mac"])
        ether = Ether(dst=client["mac"])
        packets.append(ether / arp)

    wrpcap(file_path, packets)
    messagebox.showinfo("Saved", f"Captured packets saved to:\n{file_path}")


def threaded_scan(target_ip, tree, progress_label, clients_holder):
    clients_holder.clear()
    clients = scan_network(target_ip, tree, progress_label)
    clients_holder.extend(clients)


def start_scan(tree, progress_label, clients_holder, ip_entry):
    target_ip = ip_entry.get().strip()
    if not target_ip:
        messagebox.showwarning("Missing Input", "Please enter a target subnet or IP.")
        return

    progress_label.config(text="Starting scan...")
    thread = threading.Thread(target=threaded_scan, args=(target_ip, tree, progress_label, clients_holder))
    thread.start()



root = tk.Tk()
root.title("Advanced Network Scanner")
root.geometry("700x450")
root.resizable(False, False)


ttk.Label(root, text="Simple Ambot na advanced Network Scanner", font=("Segoe UI", 16, "bold")).pack(pady=10)


frame_input = ttk.Frame(root)
frame_input.pack(pady=5)
ttk.Label(frame_input, text="Target IP/Subnet: ").pack(side=tk.LEFT, padx=5)

ip_var = tk.StringVar(value=get_local_subnet())
ip_entry = ttk.Entry(frame_input, textvariable=ip_var, width=25)
ip_entry.pack(side=tk.LEFT, padx=5)


frame_buttons = ttk.Frame(root)
frame_buttons.pack(pady=10)

clients_holder = []  

ttk.Button(frame_buttons, text="Scan Network", command=lambda: start_scan(tree, progress_label, clients_holder, ip_entry)).pack(side=tk.LEFT, padx=5)
ttk.Button(frame_buttons, text="Save to PCAP", command=lambda: save_to_pcap(clients_holder)).pack(side=tk.LEFT, padx=5)


progress_label = ttk.Label(root, text="Ready.")
progress_label.pack(pady=5)


columns = ("IP", "MAC", "Vendor")
tree = ttk.Treeview(root, columns=columns, show="headings", height=12)
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=200)
tree.pack(padx=10, pady=10, fill=tk.BOTH)


root.mainloop()
