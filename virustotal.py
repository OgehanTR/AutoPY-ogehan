import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import requests
import hashlib

API_KEY = "599ff03dd3bb3201826c67cad6000d87f41981c2beb439132a8950de1cdbfcbc"

class IndirmeOlayIsleyici(FileSystemEventHandler):
    def __init__(self, arayuz):
        self.arayuz = arayuz

    def on_created(self, event):
        if not event.is_directory:
            dosya_adi = os.path.basename(event.src_path)
            indirme_zamani = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.arayuz.indirme_ekle(dosya_adi, indirme_zamani, event.src_path)

class Uygulama:
    def __init__(self, kok):
        self.kok = kok
        self.kok.title("Ogehan Virüs Kontrol")
        self.agac = ttk.Treeview(kok, columns=("Dosya Adı", "İndirme Tarihi", "Yol"), show="headings")
        self.agac.heading("Dosya Adı", text="Dosya Adı")
        self.agac.heading("İndirme Tarihi", text="İndirme Tarihi")
        self.agac.heading("Yol", text="Yol")
        self.agac.pack(fill=tk.BOTH, expand=True)

        self.agac.bind("<Double-1>", self.satir_cift_tiklama)

    def indirme_ekle(self, dosya_adi, indirme_zamani, yol):
        self.agac.insert("", tk.END, values=(dosya_adi, indirme_zamani, yol))

    def satir_cift_tiklama(self, event):
        item = self.agac.selection()[0]
        dosya_yolu = self.agac.item(item, "values")[2]
        self.dosya_kontrol(dosya_yolu)

    def dosya_kontrol(self, dosya_yolu):
        with open(dosya_yolu, "rb") as f:
            dosya_hash = hashlib.sha256(f.read()).hexdigest()

        url = f"https://www.virustotal.com/vtapi/v2/file/report?apikey={API_KEY}&resource={dosya_hash}"
        response = requests.get(url)
        result = response.json()

        if result["response_code"] == 1:
            positives = result["positives"]
            total = result["total"]
            result_str = f"{total} taramadan {positives} zararlı yazılım çıktı ! @ogehan"
        else:
            result_str = "Dosyada Virüse Rastlanılmadı @ogehan"

        messagebox.showinfo("VirusTotal Sonucu @ogehan", result_str)

if __name__ == "__main__":
    kok = tk.Tk()
    uygulama = Uygulama(kok)

    indirmeler_yolu = os.path.expanduser("~/Downloads")
    olay_isleyici = IndirmeOlayIsleyici(uygulama)
    gozlemci = Observer()
    gozlemci.schedule(olay_isleyici, indirmeler_yolu, recursive=False)
    gozlemci.start()

    try:
        kok.mainloop()
    except KeyboardInterrupt:
        gozlemci.stop()

    gozlemci.join()
