import tkinter as tk
from tkinter import messagebox, ttk

from views.decode_view import DecodeView
from views.encode_view import EncodeView


class UtilityApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Utility App for Encoding and Decoding Base64 Files")
        self.geometry("600x400")

        self.create_menu()
        self.create_main_view()

    def create_menu(self):
        menu = tk.Menu(self)
        self.config(menu=menu)

        file_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.quit)

        help_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def show_about(self):
        messagebox.showinfo(
            "About", "This is a utility app for encoding and decoding base64 files."
        )

    def create_main_view(self):
        tab_control = ttk.Notebook(self)
        tab_control.pack(expand=1, fill="both")

        encode_tab = ttk.Frame(tab_control)
        tab_control.add(encode_tab, text="Encode")
        self.create_encode_view(encode_tab)

        decode_tab = ttk.Frame(tab_control)
        tab_control.add(decode_tab, text="Decode")
        self.create_decode_view(decode_tab)

    def create_encode_view(self, parent):
        EncodeView(parent)

    def create_decode_view(self, parent):
        DecodeView(parent)


if __name__ == "__main__":
    app = UtilityApp()
    app.mainloop()
