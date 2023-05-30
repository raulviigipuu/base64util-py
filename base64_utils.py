import os
import base64

from dto.FileData import FileData


def encode_to_base64(input_path, output_dir=None):
    if os.path.isdir(input_path):
        base64_data = ""
        for root, dirs, files in os.walk(input_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                with open(file_path, "rb") as file:
                    encoded_data = base64.b64encode(file.read())
                    relative_file_path = os.path.relpath(
                        file_path, os.path.dirname(input_path)
                    )
                    base64_data += (
                        f"{relative_file_path}\n{encoded_data.decode('utf-8')}\n"
                    )
        output_file_name = os.path.basename(input_path) + ".base64.txt"
    else:
        with open(input_path, "rb") as file:
            encoded_data = base64.b64encode(file.read())
            base64_data = (
                f"{os.path.basename(input_path)}\n{encoded_data.decode('utf-8')}\n"
            )
        output_file_name = os.path.basename(input_path) + ".base64.txt"

    output_file_path = os.path.join(output_dir, output_file_name)
    return FileData(output_file_path, base64_data)


def decode_from_base64_file(base64_file_path: str, output_directory: str = None):
    with open(base64_file_path, "r", encoding="utf-8") as base64_file:
        content = base64_file.read()
    decode_from_base64_string(content, output_directory)


def decode_from_base64_string(base64_string: str, output_directory: str = None):
    lines = base64_string.split("\n")
    for i in range(0, len(lines) - 1, 2):  # Update loop range
        line = lines[i].strip()
        if line and i + 1 < len(lines):  # Check if index is within bounds
            file_path = (
                os.path.join(output_directory, line) if output_directory else line
            )
            directory_path = os.path.dirname(file_path)
            if not os.path.exists(directory_path):
                os.makedirs(directory_path)
            encoded_data = lines[i + 1].strip()
            decoded_data = base64.b64decode(encoded_data)
            with open(file_path, "wb") as output_file:
                output_file.write(decoded_data)
