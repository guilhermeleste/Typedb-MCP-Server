import os
import hvac
import tempfile
from pydantic_settings import BaseSettings

class VaultConnectionSettings(BaseSettings):
    VAULT_ADDR: str = "http://127.0.0.1:8200"
    SENTINEL_ROLE_ID: str
    SENTINEL_SECRET_ID: str

_vault_client = None

def get_vault_client():
    global _vault_client
    if _vault_client and _vault_client.is_authenticated():
        return _vault_client

    # Corrected: Load .env file if SENTINEL_ENV_FILE is not set or points to a non-existent file.
    # Pydantic_settings by default looks for a ".env" file in the current working directory
    # if _env_file is not specified or if the specified file doesn't exist and load_dotenv is true (default).
    env_file_path = os.getenv("SENTINEL_ENV_FILE")
    if env_file_path and os.path.exists(env_file_path):
        conn_settings = VaultConnectionSettings(_env_file=env_file_path)
    else:
        # Attempt to load from default .env or environment variables if SENTINEL_ENV_FILE is not set/valid
        conn_settings = VaultConnectionSettings()

    client = hvac.Client(url=conn_settings.VAULT_ADDR)
    client.auth.approle.login(role_id=conn_settings.SENTINEL_ROLE_ID, secret_id=conn_settings.SENTINEL_SECRET_ID)
    _vault_client = client
    return client

def get_oidc_token(role_name: str):
    client = get_vault_client()
    # Corrected: Use appropriate method for generating OIDC token based on Vault version/setup.
    # Assuming OIDC Identity Secrets Engine is mounted at 'oidc' path.
    # The path "oidc/token/:name" is a common way to generate OIDC tokens.
    response = client.secrets.identity.generate_signed_id_token(name=role_name) # Changed from generate_oidc_token
    return response['data']['token']

_ca_path = None
def get_ca_cert_path():
    global _ca_path
    if _ca_path and os.path.exists(_ca_path): # Check if file still exists
        return _ca_path
    client = get_vault_client()

    # Ensure 'data' and 'certificate' keys exist
    ca_response = client.secrets.pki.read_ca_certificate(mount_point='pki') # More direct method
    if 'data' in ca_response and 'certificate' in ca_response['data']:
        ca_cert_str = ca_response['data']['certificate']
    else:
        # Fallback to direct read if the above method is not available or path is different
        # This was the original approach, ensure path is correct.
        raw_ca_resp = client.read('pki/ca/pem')
        if raw_ca_resp and 'data' in raw_ca_resp and 'certificate' in raw_ca_resp['data']:
            ca_cert_str = raw_ca_resp['data']['certificate']
        else:
            raise ValueError("Failed to retrieve CA certificate from Vault. Response did not contain expected data.")

    with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.pem', prefix="vault_ca_") as ca_file:
        ca_file.write(ca_cert_str)
        _ca_path = ca_file.name
    return _ca_path
