import os
import tenseal as ts

class BFVManager:
    def __init__(self, key_dir: str, hospital_id: str):
        self.key_dir = key_dir
        self.hospital_id = hospital_id
        self.secret_key_path = os.path.join(
            self.key_dir,
            f"{self.hospital_id}_bfv.secret"
        )
        self.context = self._load_or_create_context()

    def _load_or_create_context(self):

        if os.path.exists(self.secret_key_path):
            with open(self.secret_key_path, "rb") as f:
                context = ts.context_from(f.read())

        else:
            context = ts.context(
                ts.SCHEME_TYPE.BFV,
                poly_modulus_degree=4096,
                plain_modulus=65537
            )

            # REQUIRED
            context.generate_relin_keys()

            os.makedirs(self.key_dir, exist_ok=True)

            with open(self.secret_key_path, "wb") as f:
                f.write(context.serialize(save_secret_key=True))

        return context

    def encrypt_vector(self, values):
        vec = ts.bfv_vector(self.context, [int(v) for v in values])
        return vec.serialize()

    def decrypt_vector(self, data):
        vec = ts.bfv_vector_from(self.context, data)
        return vec.decrypt()