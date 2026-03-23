#!/usr/bin/env python3
import os
import sys
import struct
import random
import lz4.block
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from dataclasses import dataclass
from enum import IntEnum
import threading

HASH_INITVAL = 0x000C5EDE
IV_XOR = 0x60616263
XOR_DELTAS = (0x00000000, 0x0A0A0A0A, 0x0C0C0C0C, 0x06060606, 0x0E0E0E0E, 0x0A0A0A0A, 0x06060606, 0x02020202)

class CompressionMethod(IntEnum):
    NONE, PARTIAL, LZ4, ZLIB, QUICKLZ = 0, 1, 2, 3, 4

class EncryptionMethod(IntEnum):
    NONE, CHACHA20 = 0, 3

@dataclass(slots=True)
class FileEntry:
    name_offset: int; offset: int; compress_size: int; decompress_size: int; paz_index: int; flags: int
    @property
    def encryption_raw(self) -> int: return self.flags >> 4
    @property
    def compression_raw(self) -> int: return self.flags & 0x0F

def _rot32(v, b): return ((v << b) | (v >> (32 - b))) & 0xFFFFFFFF
def _add32(l, r): return (l + r) & 0xFFFFFFFF
def _sub32(l, r): return (l - r) & 0xFFFFFFFF

def hashlittle(data: bytes, initval: int = 0) -> int:
    length = len(data); a = b = c = _add32(0xDEADBEEF + length, initval)
    offset = 0; remaining = length
    while remaining > 12:
        a = _add32(a, struct.unpack_from("<I", data, offset)[0])
        b = _add32(b, struct.unpack_from("<I", data, offset + 4)[0])
        c = _add32(c, struct.unpack_from("<I", data, offset + 8)[0])
        a = _sub32(a, c); a ^= _rot32(c, 4); c = _add32(c, b)
        b = _sub32(b, a); b ^= _rot32(a, 6); a = _add32(a, c)
        c = _sub32(c, b); c ^= _rot32(b, 8); b = _add32(b, a)
        a = _sub32(a, c); a ^= _rot32(c, 16); c = _add32(c, b)
        b = _sub32(b, a); b ^= _rot32(a, 19); a = _add32(a, c)
        c = _sub32(c, b); c ^= _rot32(b, 4); b = _add32(b, a)
        offset += 12; remaining -= 12
    tail = data[offset:] + (b"\x00" * 12)
    if remaining >= 12: c = _add32(c, struct.unpack_from("<I", tail, 8)[0])
    elif remaining >= 9: c = _add32(c, struct.unpack_from("<I", tail, 8)[0] & (0xFFFFFFFF >> (8 * (12 - remaining))))
    if remaining >= 8: b = _add32(b, struct.unpack_from("<I", tail, 4)[0])
    elif remaining >= 5: b = _add32(b, struct.unpack_from("<I", tail, 4)[0] & (0xFFFFFFFF >> (8 * (8 - remaining))))
    if remaining >= 4: a = _add32(a, struct.unpack_from("<I", tail, 0)[0])
    elif remaining >= 1: a = _add32(a, struct.unpack_from("<I", tail, 0)[0] & (0xFFFFFFFF >> (8 * (4 - remaining))))
    elif remaining == 0: return c
    c ^= b; c = _sub32(c, _rot32(b, 14)); a ^= c; a = _sub32(a, _rot32(c, 11)); b ^= a; b = _sub32(b, _rot32(a, 25))
    c ^= b; c = _sub32(c, _rot32(b, 16)); a ^= c; a = _sub32(a, _rot32(c, 4)); b ^= a; b = _sub32(b, _rot32(a, 14))
    c ^= b; c = _sub32(c, _rot32(b, 24)); return c

def pad_or_truncate(data: bytes, size: int) -> bytes: return data[:size] if len(data) >= size else data + (b"\x00" * (size - len(data)))

def _evaluate_lz4_trial(data, target_comp_size):
    configs = [("default", {})] + [(f"fast/{acc}", {"mode": "fast", "acceleration": acc}) for acc in (1, 2, 4, 8, 16, 32, 64, 128, 256)]
    best_under = None; best_under_size = -1
    for label, kwargs in configs:
        packed = lz4.block.compress(data, store_size=False, **kwargs)
        if len(packed) == target_comp_size: return packed, None
        if len(packed) < target_comp_size and len(packed) > best_under_size:
            best_under = packed; best_under_size = len(packed)
    return None, best_under

def match_lz4_compressed_size(plaintext: bytes, target_comp_size: int, target_orig_size: int, log_fn):
    padding_budget = max(0, target_orig_size - len(plaintext))
    if padding_budget <= 0:
        exact, _ = _evaluate_lz4_trial(plaintext, target_comp_size)
        if exact is not None: return plaintext, exact
        raise ValueError(f"No budget to match {target_comp_size:,} exact.")

    log_fn(f"    - Calibrating entropy (budget: {padding_budget:,})")
    rng = random.Random(42)
    pool = rng.getrandbits(8 * min(padding_budget, 1024*1024)).to_bytes(min(padding_budget, 1024*1024), 'little')
    if len(pool) < padding_budget: pool = (pool * (padding_budget // len(pool) + 1))[:padding_budget]

    low, high, best_exact, best_cand_size, best_cand_noise = 0, padding_budget, None, -1, -1
    for _ in range(32):
        nl = (low + high) // 2
        trial = plaintext + pool[:nl] + b"\x00" * (padding_budget - nl)
        exact, cand = _evaluate_lz4_trial(trial, target_comp_size)
        if exact is not None: best_exact = (trial, exact); break
        if cand is not None:
            sz = len(cand); low, best_cand_size, best_cand_noise = (nl + 1, sz, nl) if sz < target_comp_size else (low, best_cand_size, best_cand_noise)
            high = high if sz < target_comp_size else nl - 1
        else: high = nl - 1
    
    if best_exact: return best_exact
    if abs(best_cand_size - target_comp_size) < 16384:
        for nl in range(max(0, best_cand_noise - 4096), min(padding_budget, best_cand_noise + 4096)):
            trial = plaintext + pool[:nl] + b"\x00" * (padding_budget - nl)
            exact, _ = _evaluate_lz4_trial(trial, target_comp_size)
            if exact is not None: return trial, exact
    raise ValueError(f"Failed to match {target_comp_size:,}. Best: {best_cand_size:,}")

def read_pamt(path: Path):
    with path.open("rb") as h:
        _, p_count, _ = struct.unpack("<III", h.read(12)); h.read(12 * p_count)
        d_size, = struct.unpack("<I", h.read(4)); d_data = h.read(d_size)
        n_size, = struct.unpack("<I", h.read(4)); n_names = h.read(n_size)
        h_count, = struct.unpack("<I", h.read(4)); folders = [struct.unpack("<IIII", h.read(16)) for _ in range(h_count)]
        f_count, = struct.unpack("<I", h.read(4)); files = [FileEntry(*struct.unpack("<IIIIHH", h.read(20))) for _ in range(f_count)]
    return d_data, n_names, folders, files

class VfsPathResolver:
    def __init__(self, b): self.b = b
    def get_path(self, off):
        if off == 0xFFFFFFFF or off >= len(self.b): return ""
        p = []; c = off
        while c != 0xFFFFFFFF and c + 5 <= len(self.b):
            po = struct.unpack_from("<I", self.b, c)[0]; l = self.b[c+4]
            p.append(self.b[c+5:c+5+l].decode("utf-8", errors="replace")); c = po
        return "".join(reversed(p)).replace("\\", "/")

class FontModGUI:
    def __init__(self, root):
        self.root = root; root.title("Auto Font Modder"); root.geometry("700x600")
        style = ttk.Style(); style.theme_use('clam')
        
        main_frame = ttk.Frame(root, padding="20"); main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Auto Font Modder", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 10))
        ttk.Label(main_frame, text="Coded by Ameer Xoshnaw", font=("Segoe UI", 9, "italic")).grid(row=1, column=0, columnspan=2, pady=(0, 20))
        
        ttk.Label(main_frame, text="Game Directory:", font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky=tk.W, pady=5)
        self.game_path = tk.StringVar(value=self._get_default_game_path())
        ttk.Entry(main_frame, textvariable=self.game_path, width=70).grid(row=3, column=0, padx=5); ttk.Button(main_frame, text="Browse", command=self.browse_game).grid(row=3, column=1)
        
        ttk.Label(main_frame, text="Custom Font file (.ttf):", font=("Segoe UI", 10, "bold")).grid(row=4, column=0, sticky=tk.W, pady=(15, 5))
        self.font_path = tk.StringVar(); ttk.Entry(main_frame, textvariable=self.font_path, width=70).grid(row=5, column=0, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_font).grid(row=5, column=1)
        
        self.btn_mod = ttk.Button(main_frame, text="Repack Custom Font into Game", command=self.start_mod)
        self.btn_mod.grid(row=6, column=0, columnspan=2, pady=25, sticky=tk.EW)
        
        self.log = scrolledtext.ScrolledText(main_frame, height=15, font=("Consolas", 9), bg="#1e1e1e", fg="#dcdcdc")
        self.log.grid(row=7, column=0, columnspan=2, sticky=tk.NSEW)
        main_frame.rowconfigure(7, weight=1)

    def _get_default_game_path(self):
        for p in [r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert", r"D:\SteamLibrary\steamapps\common\Crimson Desert"]:
            if os.path.exists(p): return p
        return ""

    def log_msg(self, m): self.log.insert(tk.END, m + "\n"); self.log.see(tk.END); self.root.update_idletasks()

    def browse_game(self):
        d = filedialog.askdirectory(initialdir=self.game_path.get())
        if d: self.game_path.set(d)

    def browse_font(self):
        f = filedialog.askopenfilename(filetypes=[("Font files", "*.ttf *.otf")])
        if f: self.font_path.set(f)

    def start_mod(self):
        if not self.game_path.get() or not self.font_path.get():
            messagebox.showerror("Error", "Please select both Game Directory and Font file."); return
        self.btn_mod.state(['disabled']); threading.Thread(target=self.run_mod_task, daemon=True).start()

    def run_mod_task(self):
        try:
            self.log.delete(1.0, tk.END); self.log_msg("[*] Initializing mod process..."); game_root = Path(self.game_path.get())
            pamt_path = game_root / "0012" / "0.pamt"
            if not pamt_path.exists(): raise FileNotFoundError("Could not find 0012/0.pamt in the game directory.")
            
            self.log_msg(f"[*] Reading metadata: {pamt_path.name}"); d_data, n_names, folders, files = read_pamt(pamt_path)
            dr, fr = VfsPathResolver(d_data), VfsPathResolver(n_names)
            franges = [(f[2], f[2] + f[3], dr.get_path(f[1]).replace("\\", "/").strip("/")) for f in folders]
            
            def find_entry(path):
                for i, e in enumerate(files):
                    rp = fr.get_path(e.name_offset).replace("\\", "/").strip("/")
                    gd = ""
                    for s, ed, cd in franges:
                        if s <= i < ed: gd = cd; break
                    gp = (f"{gd}/{rp}" if gd else rp).strip("/")
                    if gp.endswith(path): return e
                return None

            targets = ["ui/fonts/basefont.ttf", "ui/fonts/basefont_eng.ttf"]
            font_data_full = Path(self.font_path.get()).read_bytes()
            font_data = font_data_full.rstrip(b"\x00")
            
            for path in targets:
                self.log_msg(f"[*] Processing {path}...")
                e = find_entry(path)
                if not e: self.log_msg(f"    - Warning: {path} not found in archive. Skipping."); continue
                
                if len(font_data) > e.decompress_size: raise ValueError(f"Input font is too large for {path} budget ({len(font_data)} > {e.decompress_size}).")
                
                _, payload = match_lz4_compressed_size(font_data, e.compress_size, e.decompress_size, self.log_msg)
                paz = pamt_path.parent / f"{e.paz_index}.paz"
                self.log_msg(f"    - Patching {paz.name} at 0x{e.offset:X}")
                with paz.open("r+b") as h: h.seek(e.offset); h.write(payload)
                self.log_msg(f"    - Match found and written successfully.")
            
            self.log_msg("\n[!] SUCCESS! All fonts have been modded. You can start the game."); messagebox.showinfo("Success", "Font mod applied successfully!")
        except Exception as ex: 
            self.log_msg(f"\n[ERROR] {str(ex)}")
            messagebox.showerror("Error", f"Modding failed: {str(ex)}")
        finally: self.root.after(0, lambda: self.btn_mod.state(['!disabled']))

if __name__ == "__main__":
    root = tk.Tk(); app = FontModGUI(root); root.mainloop()
