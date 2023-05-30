import os
import tkinter as tk
from tkinter import ttk, filedialog
from base64_utils import encode_to_base64
from crypto_utils import encrypt
from dto.FileData import FileData


class EncodeView(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        self.create_encode_view(parent)

    def create_encode_view(self, parent):
        # Data fields
        self.selected_input_path = tk.StringVar()
        self.selected_input_path.set(os.getcwd())

        self.selected_encode_output_dir = tk.StringVar()
        self.selected_encode_output_dir.set(os.path.expanduser("~"))

        self.encrypt_password = tk.StringVar()

        # Input
        label_frame_input = ttk.LabelFrame(parent, text="Input")
        label_frame_input.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        label_selected_input_path = ttk.Label(
            label_frame_input, text="Selected input path: "
        )
        label_selected_input_path.grid(row=0, column=0, sticky="w", padx=10)
        label_selected_input_path_value = ttk.Label(
            label_frame_input, textvariable=self.selected_input_path
        )
        label_selected_input_path_value.grid(row=0, column=1, sticky="w")

        button_select_input_file = ttk.Button(
            label_frame_input, text="Select file", command=self.select_encode_input_file
        )
        button_select_input_file.grid(row=1, column=0, pady=10, padx=10, sticky="w")

        button_select_input_dir = ttk.Button(
            label_frame_input,
            text="Select directory",
            command=self.select_encode_input_dir,
        )
        button_select_input_dir.grid(row=1, column=1, pady=10, padx=10, sticky="w")

        # Output
        label_frame_output = ttk.LabelFrame(parent, text="Output")
        label_frame_output.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        label_output_dir = ttk.Label(label_frame_output, text="Selected directory: ")
        label_output_dir.grid(row=0, column=0, sticky="w", padx=10)
        label_selected_output_dir_value = ttk.Label(
            label_frame_output, textvariable=self.selected_encode_output_dir
        )
        label_selected_output_dir_value.grid(row=0, column=1, sticky="w")

        button_select_output_file = ttk.Button(
            label_frame_output,
            text="Select output directory",
            command=self.select_encode_output_dir,
        )
        button_select_output_file.grid(row=1, column=0, pady=10, padx=10, sticky="w")

        # Encrypt
        label_frame_encrypt = ttk.LabelFrame(parent, text="Encrypt")
        label_frame_encrypt.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

        label_password = ttk.Label(label_frame_encrypt, text="Password (optional):")
        label_password.grid(row=0, column=0, sticky="w", padx=10, pady=(0, 10))
        entry_password = ttk.Entry(
            label_frame_encrypt, textvariable=self.encrypt_password, show="*"
        )
        entry_password.grid(row=0, column=1, sticky="w", pady=(0, 10))

        # Action
        button_encode = ttk.Button(
            parent,
            text="Encode",
            command=self.encode_button_action,
        )
        button_encode.grid(row=3, columnspan=2, pady=10)

        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=1)

    def encode_button_action(self):
        input_path = self.selected_input_path.get()
        output_dir = self.selected_encode_output_dir.get()
        password = self.encrypt_password.get()
        encoded_data: FileData = encode_to_base64(input_path, output_dir)

        if password:
            encrypted_data = encrypt(encoded_data.content, password)
            # Save the encrypted data to a file
            with open(os.path.join(output_dir, encoded_data.path), "w") as f:
                f.write(encrypted_data)
        else:
            # Save the encoded data to a file
            with open(os.path.join(output_dir, encoded_data.path), "w") as f:
                f.write(encoded_data.content)

    def select_encode_input_file(self):
        selected_path = filedialog.askopenfilename(
            initialdir=os.getcwd(),
            filetypes=[("All files", "*")],
            title="Select a File",
        )
        if selected_path:
            self.selected_input_path.set(selected_path)

    def select_encode_input_dir(self):
        selected_path = filedialog.askdirectory(
            initialdir=os.getcwd(), title="Select a Directory"
        )
        if selected_path:
            self.selected_input_path.set(selected_path)

    def select_encode_output_dir(self):
        output_dir = filedialog.askdirectory(initialdir=os.path.expanduser("~"))
        if output_dir:
            self.selected_encode_output_dir.set(output_dir)
