#!/usr/bin/env pythonw
# -*- coding: utf-8 -*-

import io
import os
import sys
import json
import zlib
import struct
import traceback
from pathlib import Path
from dataclasses import dataclass
from typing import List
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from PIL import Image, ImageTk
except Exception:
    Image = None
    ImageTk = None


MAGIC1 = b"STKFile0PIDX"
MAGIC2 = b"STKFile0PACKFILE"
DEFAULT_KEY = "82EE1DB357E92CC22F547B104C9A7549"


def resource_path(relative_path: str) -> str:
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(os.path.dirname(__file__)) if "__file__" in globals() else os.path.abspath(".")
    return os.path.join(base_path, relative_path)


def set_windows_appusermodelid() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SchoolDays.GPKUtility")
    except Exception:
        pass


def parse_key(key_str: str) -> bytes:
    key_str = key_str.replace(" ", "").replace("-", "")
    key = bytes.fromhex(key_str)
    if len(key) != 16:
        raise ValueError("The key must be exactly 16 bytes.")
    return key


def xor_crypt(data: bytes, key: bytes, start_pos: int = 0) -> bytes:
    out = bytearray(data)
    klen = len(key)
    for i in range(len(out)):
        out[i] ^= key[(start_pos + i) % klen]
    return bytes(out)


@dataclass
class GpkEntry:
    name: str
    unk1: int
    unk2: int
    offset: int
    size: int
    unk3: int
    unpacked_size: int
    header: bytes

    @property
    def is_packed(self) -> bool:
        return self.unpacked_size != 0


class GpkArchive:
    def __init__(self, path: str, key: bytes):
        self.path = path
        self.key = key
        self.blob = Path(path).read_bytes()
        self.entries: List[GpkEntry] = []
        self.footer_offset = 0
        self.index_offset = 0
        self.index_size = 0
        self.prefix_len = 0

    def open(self):
        if len(self.blob) < 32:
            raise ValueError("File too small.")

        self.footer_offset = len(self.blob) - 32

        if self.blob[self.footer_offset:self.footer_offset + 12] != MAGIC1:
            raise ValueError("Invalid footer: STKFile0PIDX missing.")
        if self.blob[self.footer_offset + 16:self.footer_offset + 32] != MAGIC2:
            raise ValueError("Invalid footer: STKFile0PACKFILE missing.")

        self.index_size = struct.unpack_from("<I", self.blob, self.footer_offset + 12)[0]
        self.index_offset = self.footer_offset - self.index_size

        if self.index_offset < 0:
            raise ValueError("Index out of bounds.")

        enc_index = self.blob[self.index_offset:self.footer_offset]
        plain = xor_crypt(enc_index, self.key, 0)

        if len(plain) < 4:
            raise ValueError("Index too small.")

        comp = plain[4:]
        try:
            raw_index = zlib.decompress(comp)
        except zlib.error as e:
            raise ValueError("Could not decompress index: %s" % e)

        self.entries = self._parse_index(raw_index)

        if not self.entries:
            raise ValueError("No entries found.")

        self.prefix_len = min(e.offset for e in self.entries)
        return self

    def _parse_index(self, raw: bytes) -> List[GpkEntry]:
        bio = io.BytesIO(raw)
        entries: List[GpkEntry] = []

        while True:
            head = bio.read(2)
            if len(head) < 2:
                break

            name_len_chars = struct.unpack("<H", head)[0]
            if name_len_chars == 0:
                break

            name_bytes = bio.read(name_len_chars * 2)
            if len(name_bytes) != name_len_chars * 2:
                raise ValueError("Truncated index while reading name.")
            name = name_bytes.decode("utf-16-le")

            fixed = bio.read(23)
            if len(fixed) != 23:
                raise ValueError("Truncated index while reading fixed fields.")

            unk1, unk2, offset, size, unk3, unpacked_size, header_len = struct.unpack(
                "<ihIIiIB", fixed
            )

            header = bio.read(header_len)
            if len(header) != header_len:
                raise ValueError("Truncated index while reading header.")

            entries.append(GpkEntry(
                name=name,
                unk1=unk1,
                unk2=unk2,
                offset=offset,
                size=size,
                unk3=unk3,
                unpacked_size=unpacked_size,
                header=header
            ))

        return entries

    def get_prefix(self) -> bytes:
        return self.blob[:self.prefix_len]

    def get_stored_bytes(self, entry: GpkEntry) -> bytes:
        return self.blob[entry.offset:entry.offset + entry.size]

    def get_raw_bytes(self, entry: GpkEntry) -> bytes:
        stored = self.get_stored_bytes(entry)
        if not entry.is_packed:
            return stored
        return zlib.decompress(entry.header + stored)


def build_index(entries: List[GpkEntry]) -> bytes:
    bio = io.BytesIO()

    for e in entries:
        name_bytes = e.name.encode("utf-16-le")
        bio.write(struct.pack("<H", len(name_bytes) // 2))
        bio.write(name_bytes)

        bio.write(struct.pack("<i", e.unk1))
        bio.write(struct.pack("<h", e.unk2))
        bio.write(struct.pack("<I", e.offset))
        bio.write(struct.pack("<I", e.size))
        bio.write(struct.pack("<i", e.unk3))
        bio.write(struct.pack("<I", e.unpacked_size))
        bio.write(struct.pack("<B", len(e.header)))
        if e.header:
            bio.write(e.header)

    bio.write(struct.pack("<H", 0))
    return bio.getvalue()


def inspect_gpk(gpk_path: str, key: bytes):
    arc = GpkArchive(gpk_path, key).open()
    lines = []
    lines.append("File             : %s" % arc.path)
    lines.append("Size             : %d" % len(arc.blob))
    lines.append("Footer offset    : %d" % arc.footer_offset)
    lines.append("Index offset     : %d" % arc.index_offset)
    lines.append("Index size       : %d" % arc.index_size)
    lines.append("Hybrid prefix    : %d" % arc.prefix_len)
    lines.append("Entries          : %d" % len(arc.entries))
    lines.append("")

    for i, e in enumerate(arc.entries[:30]):
        lines.append("%04d  %s | off=%d size=%d unpacked=%d hdr=%d packed=%s" % (
            i, e.name, e.offset, e.size, e.unpacked_size, len(e.header), e.is_packed
        ))
    return "\n".join(lines)


def unpack_gpk(gpk_path: str, out_dir: str, key: bytes):
    arc = GpkArchive(gpk_path, key).open()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    (out / "_prefix.bin").write_bytes(arc.get_prefix())

    manifest = {
        "source_gpk": gpk_path,
        "prefix_len": arc.prefix_len,
        "entries": []
    }

    for e in arc.entries:
        target = out / Path(e.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(arc.get_raw_bytes(e))

        manifest["entries"].append({
            "name": e.name,
            "unk1": e.unk1,
            "unk2": e.unk2,
            "unk3": e.unk3,
            "offset": e.offset,
            "size": e.size,
            "unpacked_size": e.unpacked_size,
            "header_hex": e.header.hex(),
            "is_packed": e.is_packed
        })

    (out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    return "[OK] Extraction complete: %s\n[OK] Prefix saved: %d bytes\n[OK] Entries: %d" % (
        out_dir, arc.prefix_len, len(arc.entries)
    )


def repack_gpk(original_gpk: str, input_dir: str, output_gpk: str, key: bytes):
    arc = GpkArchive(original_gpk, key).open()
    in_dir = Path(input_dir)

    out = io.BytesIO()
    prefix = arc.get_prefix()
    out.write(prefix)

    new_entries: List[GpkEntry] = []

    for old in arc.entries:
        disk_path = in_dir / Path(old.name)

        new_entry = GpkEntry(
            name=old.name,
            unk1=old.unk1,
            unk2=old.unk2,
            offset=out.tell(),
            size=0,
            unk3=old.unk3,
            unpacked_size=old.unpacked_size,
            header=old.header
        )

        if disk_path.exists():
            raw = disk_path.read_bytes()

            if not old.is_packed:
                out.write(raw)
                new_entry.size = len(raw)
                new_entry.unpacked_size = 0
                new_entry.header = b""
            else:
                z = zlib.compress(raw, level=9)
                header_len = len(old.header)

                if header_len > len(z):
                    raise ValueError("Header too long for entry %s" % old.name)

                new_entry.header = z[:header_len]

                if header_len > 0:
                    stored = z[header_len:] + z[-header_len:]
                else:
                    stored = z

                out.write(stored)
                new_entry.size = len(stored)
                new_entry.unpacked_size = len(raw)
        else:
            stored = arc.get_stored_bytes(old)
            out.write(stored)
            new_entry.size = len(stored)

        new_entries.append(new_entry)

    raw_index = build_index(new_entries)
    comp_index = zlib.compress(raw_index, level=6)

    payload = struct.pack("<I", len(raw_index)) + comp_index
    enc_index = xor_crypt(payload, key, 0)

    out.write(enc_index)
    out.write(MAGIC1)
    out.write(struct.pack("<I", len(enc_index)))
    out.write(MAGIC2)

    Path(output_gpk).write_bytes(out.getvalue())

    return "[OK] Repack complete: %s\n[OK] Prefix kept: %d bytes\n[OK] Entries written: %d" % (
        output_gpk, len(prefix), len(new_entries)
    )


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("School Days GPK Utility")
        self.geometry("880x760")
        self.minsize(820, 680)
        self.configure(bg="#f2f2f2")
        self.logo_img = None
        self._set_icon()
        self._build_ui()
        self._load_bottom_logo()

    def _set_icon(self):
        ico_path = resource_path("Adobe_Express_-_file.ico")
        if os.path.exists(ico_path):
            try:
                self.iconbitmap(ico_path)
            except Exception:
                pass

    def _build_ui(self):
        main = ttk.Frame(self, padding=12)
        main.pack(fill="both", expand=True)

        title = ttk.Label(main, text="School Days GPK Utility", font=("Segoe UI", 16, "bold"))
        title.pack(anchor="w", pady=(0, 10))

        form = ttk.LabelFrame(main, text="Settings", padding=10)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Key:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        self.key_var = tk.StringVar(value=DEFAULT_KEY)
        ttk.Entry(form, textvariable=self.key_var).grid(row=0, column=1, columnspan=2, sticky="ew", pady=4)

        ttk.Label(form, text="GPK:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        self.gpk_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.gpk_var).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(form, text="Browse", command=self.browse_gpk).grid(row=1, column=2, padx=(8, 0), pady=4)

        ttk.Label(form, text="Folder:").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        self.dir_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.dir_var).grid(row=2, column=1, sticky="ew", pady=4)
        ttk.Button(form, text="Browse", command=self.browse_dir).grid(row=2, column=2, padx=(8, 0), pady=4)

        ttk.Label(form, text="Output GPK:").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        self.out_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.out_var).grid(row=3, column=1, sticky="ew", pady=4)
        ttk.Button(form, text="Browse", command=self.browse_out).grid(row=3, column=2, padx=(8, 0), pady=4)

        btns = ttk.Frame(main)
        btns.pack(fill="x", pady=(12, 10))
        ttk.Button(btns, text="Inspect", command=self.run_inspect).pack(side="left")
        ttk.Button(btns, text="Unpack", command=self.run_unpack).pack(side="left", padx=8)
        ttk.Button(btns, text="Repack", command=self.run_repack).pack(side="left")
        ttk.Button(btns, text="Clear log", command=self.clear_log).pack(side="right")

        log_frame = ttk.LabelFrame(main, text="Log", padding=8)
        log_frame.pack(fill="both", expand=True)
        self.log = tk.Text(log_frame, wrap="word", height=20, font=("Consolas", 10))
        self.log.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        scroll.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=scroll.set)

        self.bottom_frame = ttk.Frame(main)
        self.bottom_frame.pack(fill="x", pady=(10, 0))

    def _load_bottom_logo(self):
        img_path = resource_path("TITLE_AC.PNG")
        if not os.path.exists(img_path) or Image is None or ImageTk is None:
            return
        try:
            img = Image.open(img_path)
            max_w = 760
            if img.width > max_w:
                ratio = max_w / float(img.width)
                new_size = (int(img.width * ratio), int(img.height * ratio))
                img = img.resize(new_size, Image.LANCZOS)
            self.logo_img = ImageTk.PhotoImage(img)
            lbl = ttk.Label(self.bottom_frame, image=self.logo_img)
            lbl.pack(anchor="center")
        except Exception as e:
            self.write_log("[WARN] Could not load TITLE_AC.PNG: %s\n" % e)

    def browse_gpk(self):
        path = filedialog.askopenfilename(filetypes=[("GPK files", "*.gpk"), ("All files", "*.*")])
        if path:
            self.gpk_var.set(path)
            if not self.out_var.get():
                p = Path(path)
                self.out_var.set(str(p.with_name(p.stem + "_new" + p.suffix)))

    def browse_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.dir_var.set(path)

    def browse_out(self):
        path = filedialog.asksaveasfilename(defaultextension=".GPK", filetypes=[("GPK files", "*.gpk"), ("All files", "*.*")])
        if path:
            self.out_var.set(path)

    def write_log(self, text: str):
        self.log.insert("end", text)
        self.log.see("end")
        self.update_idletasks()

    def clear_log(self):
        self.log.delete("1.0", "end")

    def _get_key(self) -> bytes:
        return parse_key(self.key_var.get())

    def run_inspect(self):
        try:
            gpk = self.gpk_var.get().strip()
            if not gpk:
                raise ValueError("Choose a GPK file.")
            result = inspect_gpk(gpk, self._get_key())
            self.write_log(result + "\n\n")
        except Exception as e:
            self.write_log("[ERROR] %s\n%s\n" % (e, traceback.format_exc()))
            messagebox.showerror("Error", str(e))

    def run_unpack(self):
        try:
            gpk = self.gpk_var.get().strip()
            out_dir = self.dir_var.get().strip()
            if not gpk:
                raise ValueError("Choose a GPK file.")
            if not out_dir:
                raise ValueError("Choose an output folder.")
            result = unpack_gpk(gpk, out_dir, self._get_key())
            self.write_log(result + "\n\n")
            messagebox.showinfo("Done", "Unpack complete.")
        except Exception as e:
            self.write_log("[ERROR] %s\n%s\n" % (e, traceback.format_exc()))
            messagebox.showerror("Error", str(e))

    def run_repack(self):
        try:
            original_gpk = self.gpk_var.get().strip()
            input_dir = self.dir_var.get().strip()
            output_gpk = self.out_var.get().strip()
            if not original_gpk:
                raise ValueError("Choose the original GPK.")
            if not input_dir:
                raise ValueError("Choose the folder to repack.")
            if not output_gpk:
                raise ValueError("Choose the output file.")
            result = repack_gpk(original_gpk, input_dir, output_gpk, self._get_key())
            self.write_log(result + "\n\n")
            messagebox.showinfo("Done", "Repack complete.")
        except Exception as e:
            self.write_log("[ERROR] %s\n%s\n" % (e, traceback.format_exc()))
            messagebox.showerror("Error", str(e))


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
