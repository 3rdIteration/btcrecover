import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import threading
import os

class RecoveryLogic:
    def run_password_recovery(self, wallet_file, passwordlist, output_callback):
        if not wallet_file or not passwordlist:
            output_callback("Error: Wallet File and Password List are required.\n")
            return

        command = [
            "python3",
            "btcrecover.py",
            "--wallet",
            wallet_file,
            "--passwordlist",
            passwordlist
        ]
        self.run_command(command, output_callback)

    def run_seed_recovery(self, mnemonic, wallet_type, address, addr_limit, output_callback):
        if not mnemonic:
            output_callback("Error: Mnemonic is required.\n")
            return

        command = [
            "python3",
            "seedrecover.py",
            "--no-gui",
            "--mnemonic",
            mnemonic,
        ]

        if wallet_type:
            command.extend(["--wallet-type", wallet_type])
        
        if address:
            command.extend(["--addrs", address])

        if addr_limit:
            command.extend(["--addr-limit", str(addr_limit)])

        self.run_command(command, output_callback)

    def run_command(self, command, output_callback):
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
        for line in iter(process.stdout.readline, ''):
            output_callback(line)
        process.stdout.close()
        process.wait()

class BTCRecoverGUI(tk.Tk):
    def __init__(self, logic):
        super().__init__()
        self.logic = logic
        self.title("BTCRecover GUI")
        self.geometry("800x600")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, padx=10, fill="both", expand=True)

        self.password_tab = ttk.Frame(self.notebook)
        self.seed_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.password_tab, text="Password Recovery")
        self.notebook.add(self.seed_tab, text="Seed Recovery")

        self.create_password_tab()
        self.create_seed_tab()

        self.output_text = tk.Text(self, height=15, width=100)
        self.output_text.pack(pady=10, padx=10, fill="both", expand=True)

        self.run_button = tk.Button(self, text="Run Recovery", command=self.run_recovery)
        self.run_button.pack(pady=10)
        
    def create_password_tab(self):
        # --- Wallet File ---
        wallet_file_frame = tk.Frame(self.password_tab)
        wallet_file_frame.pack(fill="x", padx=5, pady=5)

        wallet_file_label = tk.Label(wallet_file_frame, text="Wallet File:")
        wallet_file_label.pack(side="left", padx=5)
        self.wallet_file_entry = tk.Entry(wallet_file_frame, width=60)
        self.wallet_file_entry.pack(side="left", expand=True, fill="x", padx=5)
        wallet_file_button = tk.Button(wallet_file_frame, text="Browse...", command=self.browse_wallet_file)
        wallet_file_button.pack(side="left", padx=5)
        ToolTip(wallet_file_label, "The path to your wallet file.")

        # --- Password List ---
        passwordlist_frame = tk.Frame(self.password_tab)
        passwordlist_frame.pack(fill="x", padx=5, pady=5)

        passwordlist_label = tk.Label(passwordlist_frame, text="Password List:")
        passwordlist_label.pack(side="left", padx=5)
        self.passwordlist_entry = tk.Entry(passwordlist_frame, width=60)
        self.passwordlist_entry.pack(side="left", expand=True, fill="x", padx=5)
        passwordlist_button = tk.Button(passwordlist_frame, text="Browse...", command=self.browse_passwordlist)
        passwordlist_button.pack(side="left", padx=5)
        ToolTip(passwordlist_label, "A file containing a list of passwords to try, one per line.")

    def browse_wallet_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.wallet_file_entry.delete(0, tk.END)
            self.wallet_file_entry.insert(0, filename)

    def browse_passwordlist(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.passwordlist_entry.delete(0, tk.END)
            self.passwordlist_entry.insert(0, filename)

    def create_seed_tab(self):
        # --- Mnemonic ---
        mnemonic_frame = tk.Frame(self.seed_tab)
        mnemonic_frame.pack(fill="x", padx=5, pady=5)

        mnemonic_label = tk.Label(mnemonic_frame, text="Mnemonic:")
        mnemonic_label.pack(side="left", padx=5)
        self.mnemonic_entry = tk.Entry(mnemonic_frame, width=60)
        self.mnemonic_entry.pack(side="left", expand=True, fill="x", padx=5)
        ToolTip(mnemonic_label, "Your best guess for the mnemonic (seed phrase).")

        # --- Wallet Type ---
        wallet_type_frame = tk.Frame(self.seed_tab)
        wallet_type_frame.pack(fill="x", padx=5, pady=5)

        wallet_type_label = tk.Label(wallet_type_frame, text="Wallet Type:")
        wallet_type_label.pack(side="left", padx=5)

        self.wallet_type_var = tk.StringVar()
        wallet_types = ["BIP39", "Electrum", "Ethereum"] # Add more as needed
        self.wallet_type_menu = ttk.Combobox(wallet_type_frame, textvariable=self.wallet_type_var, values=wallet_types)
        self.wallet_type_menu.pack(side="left", padx=5)
        self.wallet_type_menu.set("BIP39")
        ToolTip(wallet_type_label, "The type of wallet you are trying to recover.")

        # --- Address ---
        address_frame = tk.Frame(self.seed_tab)
        address_frame.pack(fill="x", padx=5, pady=5)

        address_label = tk.Label(address_frame, text="Address:")
        address_label.pack(side="left", padx=5)
        self.address_entry = tk.Entry(address_frame, width=60)
        self.address_entry.pack(side="left", expand=True, fill="x", padx=5)
        ToolTip(address_label, "An address from the wallet you are trying to recover.")

        # --- Address Limit ---
        addr_limit_frame = tk.Frame(self.seed_tab)
        addr_limit_frame.pack(fill="x", padx=5, pady=5)

        addr_limit_label = tk.Label(addr_limit_frame, text="Address Limit:")
        addr_limit_label.pack(side="left", padx=5)
        self.addr_limit_entry = tk.Entry(addr_limit_frame, width=10)
        self.addr_limit_entry.insert(0, "10")
        self.addr_limit_entry.pack(side="left", padx=5)
        ToolTip(addr_limit_label, "The number of addresses to check. Smaller is faster.")

    def run_recovery(self):
        self.output_text.delete("1.0", tk.END)
        tab_index = self.notebook.index(self.notebook.select())

        if tab_index == 0: # Password Recovery
            wallet_file = self.wallet_file_entry.get()
            passwordlist = self.passwordlist_entry.get()
            thread = threading.Thread(target=self.logic.run_password_recovery, args=(wallet_file, passwordlist, self.update_output))
            thread.start()
        elif tab_index == 1: # Seed Recovery
            mnemonic = self.mnemonic_entry.get()
            wallet_type = self.wallet_type_var.get()
            address = self.address_entry.get()
            addr_limit = self.addr_limit_entry.get()
            thread = threading.Thread(target=self.logic.run_seed_recovery, args=(mnemonic, wallet_type, address, addr_limit, self.update_output))
            thread.start()

    def update_output(self, text):
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.update_idletasks()

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)

    def enter(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25

        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")

        label = tk.Label(self.tooltip, text=self.text, background="lightyellow", relief="solid", borderwidth=1,
                         wraplength=200)
        label.pack(ipadx=1)

    def leave(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

if __name__ == "__main__":
    import sys

    def test_output_callback(text):
        print(text, end="")

    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        logic = RecoveryLogic()
        
        # Test password recovery
        print("--- Testing Password Recovery ---")
        logic.run_password_recovery(
            "btcrecover/test/test-wallets/bitcoincore-wallet.dat",
            "btcrecover/test/test-listfiles/passwordListTest.txt",
            test_output_callback
        )

        # Test seed recovery
        print("\n--- Testing Seed Recovery ---")
        logic.run_seed_recovery(
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",
            "BIP39",
            "17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8",
            10,
            test_output_callback
        )
    else:
        logic = RecoveryLogic()
        app = BTCRecoverGUI(logic)
        app.mainloop()
