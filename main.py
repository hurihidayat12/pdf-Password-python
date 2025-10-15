import customtkinter as ctk
from tkinter import filedialog, messagebox
from PyPDF2 import PdfReader, PdfWriter
import os, secrets, hashlib

# ---------- LOGIC BAGIAN ENKRIPSI ----------
def generate_password():
    password = secrets.token_urlsafe(10)
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()
    return password, salt.hex(), hashed

def protect_pdf(input_path, output_path, password):
    reader = PdfReader(input_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer.encrypt(password)
    with open(output_path, "wb") as f:
        writer.write(f)


# ---------- UI BAGIAN ----------
class PDFProtectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PDF Password Protector")
        self.geometry("600x480")
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Judul
        self.label_title = ctk.CTkLabel(
            self, 
            text="🔒 PDF Password Protector",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.label_title.pack(pady=20)

        # File input
        frame = ctk.CTkFrame(self)
        frame.pack(pady=10, padx=20, fill="x")

        self.file_entry = ctk.CTkEntry(frame, placeholder_text="Select your PDF file...", width=350)
        self.file_entry.pack(side="left", padx=10, pady=10)

        self.browse_btn = ctk.CTkButton(frame, text="📁 Browse", width=100, command=self.browse_file)
        self.browse_btn.pack(side="left", padx=5)

        # Tombol utama
        self.encrypt_btn = ctk.CTkButton(
            self,
            text="Generate Password & Protect PDF",
            fg_color="#0066CC",
            hover_color="#004C99",
            width=300,
            height=40,
            command=self.encrypt_action
        )
        self.encrypt_btn.pack(pady=25)

        # Kotak log
        self.log_box = ctk.CTkTextbox(self, width=520, height=200)
        self.log_box.pack(pady=10)

        self.footer = ctk.CTkLabel(
            self,
            text="© 2025 PDF Helper Tools | Secure your documents easily",
            font=ctk.CTkFont(size=12, slant="italic")
        )
        self.footer.pack(pady=10)

    def browse_file(self):
        path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
        if path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, path)

    def encrypt_action(self):
        pdf_path = self.file_entry.get()
        if not pdf_path or not os.path.exists(pdf_path):
            messagebox.showerror("Error", "Please select a valid PDF file.")
            return

        try:
            pwd, salt, hashed = generate_password()
            output_path = pdf_path.replace(".pdf", "_protected.pdf")
            protect_pdf(pdf_path, output_path, pwd)

            self.log_box.delete("1.0", "end")
            self.log_box.insert(
                "end",
                f"✅ PDF successfully encrypted!\n\n"
                f"🔐 Password: {pwd}\n"
                f"🧂 Salt: {salt}\n"
                f"🧾 Hash: {hashed}\n\n"
                f"💾 Saved to: {output_path}\n"
            )
            messagebox.showinfo("Success", "PDF has been encrypted successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}")


# ---------- JALANKAN APLIKASI ----------
if __name__ == "__main__":
    app = PDFProtectorApp()
    app.mainloop()
