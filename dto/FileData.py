from dataclasses import dataclass


@dataclass
class FileData:
    path: str
    content: str
