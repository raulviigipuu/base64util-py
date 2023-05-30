import os
import tkinter as tk
from tkinter import filedialog, ttk

from base64_utils import decode_from_base64_file, decode_from_base64_string
from crypto_utils import decrypt


class DecodeView(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        self.create_decode_view(parent)

    def create_decode_view(self, parent):
        # Data fields
        self.selected_base64_file_path = tk.StringVar()
        self.selected_base64_file_path.set("<empty>")
        self.selected_decode_output_dir = tk.StringVar()
        self.selected_decode_output_dir.set(os.path.expanduser("~"))

        self.decrypt_password = tk.StringVar()

        # Input
        input_label_frame = ttk.LabelFrame(parent, text="Input")
        input_label_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        label_selected_base64_input_path = ttk.Label(
            input_label_frame, text="Selected base64 input path: "
        )
        label_selected_base64_input_path.grid(row=0, column=0, sticky="w", padx=10)
        label_selected_base64_input_path_value = ttk.Label(
            input_label_frame, textvariable=self.selected_base64_file_path
        )
        label_selected_base64_input_path_value.grid(row=0, column=1, sticky="w")

        button_select_base64_file = ttk.Button(
            input_label_frame,
            text="Select base64 file",
            command=self.select_base64_file,
        )
        button_select_base64_file.grid(row=1, column=0, pady=10, padx=10, sticky="w")

        label_selected_base64_file_path_value = ttk.Label(
            input_label_frame, textvariable=self.selected_base64_file_path
        )
        label_selected_base64_file_path_value.grid(row=0, column=1, sticky="w")

        # Output
        output_label_frame = ttk.LabelFrame(parent, text="Output")
        output_label_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        label_output_dir = ttk.Label(
            output_label_frame, text="Selected output directory: "
        )
        label_output_dir.grid(row=0, column=0, sticky="w", padx=10)
        label_selected_output_dir_value = ttk.Label(
            output_label_frame, textvariable=self.selected_decode_output_dir
        )
        label_selected_output_dir_value.grid(row=0, column=1, sticky="w")

        button_select_output_dir = ttk.Button(
            output_label_frame,
            text="Select directory",
            command=self.select_decode_output_dir,
        )
        button_select_output_dir.grid(row=1, column=0, pady=10, padx=10, sticky="w")

        # Decrypt
        label_frame_decrypt = ttk.LabelFrame(parent, text="Decrypt")
        label_frame_decrypt.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

        label_password = ttk.Label(label_frame_decrypt, text="Password (optional):")
        label_password.grid(row=0, column=0, sticky="w", padx=10, pady=(0, 10))
        entry_password = ttk.Entry(
            label_frame_decrypt, textvariable=self.decrypt_password, show="*"
        )
        entry_password.grid(row=0, column=1, sticky="w", pady=(0, 10))

        # Action
        button_decode = ttk.Button(
            parent, text="Decode", command=self.decode_button_action
        )
        button_decode.grid(row=3, columnspan=2, pady=10)

        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=1)

    def decode_button_action(self):
        base64_file_path = self.selected_base64_file_path.get()
        output_dir = self.selected_decode_output_dir.get()
        password = self.decrypt_password.get()

        if password:
            with open(base64_file_path, "rb") as file:
                decrypted_base64_data = decrypt(file.read(), password)
                decode_from_base64_string(decrypted_base64_data, output_dir)

        else:
            decode_from_base64_file(base64_file_path, output_dir)

    def select_base64_file(self):
        base64_file_path = filedialog.askopenfilename(
            initialdir=os.getcwd(), filetypes=[("Base64 Text files", "*.base64.txt")]
        )
        if base64_file_path:
            self.selected_base64_file_path.set(base64_file_path)

    def select_decode_output_dir(self):
        output_dir = filedialog.askdirectory(initialdir=os.path.expanduser("~"))
        if output_dir:
            self.selected_decode_output_dir.set(output_dir)
