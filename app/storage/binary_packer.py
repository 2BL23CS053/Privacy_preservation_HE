import struct
from typing import Dict

class BinaryPacker:
    """
    Packs and unpacks dictionary representations of encrypted patient fields 
    into a single cohesive binary record object.
    
    Binary Format:
    - 2 Bytes: Total number of fields (unsigned short)
    - Per Field:
      - 2 Bytes: Field key length (unsigned short)
      - 4 Bytes: Field value length (unsigned int)
      - N Bytes: UTF-8 Field key string
      - M Bytes: Raw encrypted field value (AES or BFV payload)
    """

    @staticmethod
    def pack_record(field_dict: Dict[str, bytes]) -> bytes:
        """
        Packs a dictionary of encrypted byte fields into a binary byte string.
        """
        payload = bytearray()
        
        # Write total field count (2 bytes, big-endian)
        payload.extend(struct.pack(">H", len(field_dict)))
        
        for key, val_bytes in field_dict.items():
            if not isinstance(val_bytes, bytes):
                raise TypeError(f"Value for field '{key}' must be of type bytes.")
                
            key_bytes = key.encode('utf-8')
            key_len = len(key_bytes)
            val_len = len(val_bytes)
            
            # Pack field key length (2 bytes) and value length (4 bytes)
            payload.extend(struct.pack(">HI", key_len, val_len))
            # Append key string bytes
            payload.extend(key_bytes)
            # Append value raw cipher bytes
            payload.extend(val_bytes)
            
        return bytes(payload)

    @staticmethod
    def unpack_record(binary_payload: bytes) -> Dict[str, bytes]:
        """
        Unpacks a serialized binary record back into a dictionary of field bytes.
        """
        offset = 0
        total_len = len(binary_payload)
        
        if total_len < 2:
            raise ValueError("Invalid binary payload: too short.")
            
        num_fields = struct.unpack_from(">H", binary_payload, offset)[0]
        offset += 2
        
        record = {}
        for _ in range(num_fields):
            if offset + 6 > total_len:
                raise ValueError("Corrupted binary payload header.")
                
            key_len, val_len = struct.unpack_from(">HI", binary_payload, offset)
            offset += 6
            
            if offset + key_len + val_len > total_len:
                raise ValueError("Corrupted binary payload content.")
                
            key_bytes = binary_payload[offset : offset + key_len]
            offset += key_len
            
            val_bytes = binary_payload[offset : offset + val_len]
            offset += val_len
            
            record[key_bytes.decode('utf-8')] = val_bytes
            
        return record