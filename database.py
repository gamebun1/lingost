import os
from utils import data_clean

class DatabaseManager:
    def __init__(self, db_file="passwords"):
        self.db_file = db_file

    def load_db(self, vault):
        if not os.path.exists(self.db_file):
            return {}
        
        try:
            with open(self.db_file, "rb") as f:
                content = bytearray(f.read())

            if len(content) < 32:
                data_clean(content)
                return {}
            content = content[32:]
            dec_content = vault.decrypt_data(content)
            data_clean(content)

            if dec_content is None:
                return None 

            ram_data = {}
            for site, creds in dec_content.items():
                pwd_enc = vault.encrypt_ram_pwd(site, creds['password'])
                ram_data[site] = {
                    "email": creds['email'],
                    "password": pwd_enc
                }

                data_clean(creds['password']) 

            return ram_data
        except Exception as e:
            print(f"Ошибка загрузки БД: {e}")
            return None

    def save_db(self, vault, curr_data):
        try:
            data = {}
            for site, creds in curr_data.items():
                data[site] = {
                    "email": creds['email'],
                    "password": vault.decrypt_ram_pwd(creds['password'], site)
                }
            
            enc_bytes = vault.encrypt_data(data)

            for site, creds in data.items():
                data_clean(creds['password'])
            data.clear()

            with open(self.db_file, "wb") as f:
                f.write(bytes(vault.salt))
                f.write(bytes(enc_bytes))

            if isinstance(enc_bytes, bytearray):
                data_clean(enc_bytes)

            return True
        except Exception as e:

            import traceback
            traceback.print_exc()

            print("Ошибка", repr(e), "error")
            return False

    def delete_db(self):
        if os.path.exists(self.db_file):
            os.remove(self.db_file)
            return True
        return False