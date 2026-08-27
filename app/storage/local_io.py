import os

class LocalIO:
    """
    Handles file I/O operations on the combined encrypted binary file.
    Appends packed records and reads specific record chunks using byte offsets.
    """

    @staticmethod
    def append_record(file_path: str, record_bytes: bytes) -> tuple[int, int]:
        """
        Appends serialized record bytes to the target binary file.
        Returns a tuple of (start_offset, record_length).
        """
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        
        # Determine starting byte offset based on existing file size
        offset = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        length = len(record_bytes)

        with open(file_path, "ab") as f:
            f.write(record_bytes)

        return offset, length

    @staticmethod
    def read_record_by_offset(file_path: str, offset: int, length: int) -> bytes:
        """
        Extracts a specific byte chunk from a binary file using offset seeking.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Binary file not found: {file_path}")

        with open(file_path, "rb") as f:
            f.seek(offset)
            data = f.read(length)

        if len(data) != length:
            raise IOError(f"Expected to read {length} bytes at offset {offset}, but got {len(data)} bytes.")

        return data