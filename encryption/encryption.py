import os
import base64
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key,
    load_der_private_key, load_der_public_key,
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from config import SERVER_KEY

logger = logging.getLogger(__name__)

class EncryptionService:
    """Service for handling encryption/decryption operations using cryptography"""

    @staticmethod
    def verify_key_pair(private_key_pem, encrypted_public_key):
        """Verify that a private key matches the stored encrypted public key"""
        try:
            if not private_key_pem or not encrypted_public_key:
                return False
                
            # Decrypt stored public key
            public_key_pem = EncryptionService.decrypt_public_key(encrypted_public_key)
            if not public_key_pem:
                return False
                
            # Load keys
            private_key = load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            public_key = load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )

            # Generate test message
            test_message = os.urandom(32)
            
            # Sign with private key
            signature = private_key.sign(
                test_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Verify with public key
            try:
                public_key.verify(
                    signature,
                    test_message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            except Exception:
                return False
        except Exception as e:
            logger.error(f"Error verifying key pair: {e}")
            return False

    @staticmethod
    def generate_rsa_key_pair():
        """Generate a new RSA key pair"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,  # Standard value for e
                key_size=2048,
                backend=default_backend()
            )
            if not private_key:
                logger.error("Failed to generate private key")
                return None, None

            # Export keys in PEM format (similar to what Web Crypto exports as PKCS8/SPKI)
            private_pem = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ).decode('utf-8')

            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            return private_pem, public_pem
        except Exception as e:
            logger.error(f"Error generating RSA key pair: {e}")
            return None, None

    @staticmethod
    def _try_load_public_key(key_data):
        """Try different methods to load a public key"""
        try:
            # Try loading as PEM format
            return load_pem_public_key(key_data.encode('utf-8'), backend=default_backend())
        except Exception as e:
            logger.debug(f"Failed to load as PEM: {str(e)}")
            try:
                # Try loading as base64-encoded DER format (used by Web Crypto API)
                der_data = base64.b64decode(key_data)
                return load_der_public_key(der_data, backend=default_backend())
            except Exception as e2:
                logger.debug(f"Failed to load as DER: {str(e2)}")
                # Try loading as raw DER format
                try:
                    return load_der_public_key(key_data.encode('utf-8'), backend=default_backend())
                except Exception as e3:
                    logger.error(f"Failed to load public key in any format: {str(e3)}")
                    raise ValueError("Unable to load public key")

    @staticmethod
    def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
        """Encrypt AES key using recipient's RSA public key"""
        try:
            public_key = EncryptionService._try_load_public_key(rsa_public_key)

            # Use OAEP padding with SHA-256 to match Web Crypto API
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return base64.b64encode(encrypted_aes_key).decode('utf-8')
        except Exception as e:
            logger.error(f"Error encrypting AES key: {str(e)}")
            raise

    @staticmethod
    def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
        """Decrypt AES key using user's RSA private key"""
        try:
            # Try to load the private key
            try:
                private_key = load_pem_private_key(
                    rsa_private_key.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
            except Exception:
                # Try as base64-encoded DER format
                der_data = base64.b64decode(rsa_private_key)
                private_key = load_der_private_key(
                    der_data,
                    password=None,
                    backend=default_backend()
                )

            encrypted_aes_key_bytes = base64.b64decode(encrypted_aes_key)

            # Decrypt with OAEP padding
            decrypted_key = private_key.decrypt(
                encrypted_aes_key_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return decrypted_key
        except Exception as e:
            logger.error(f"Error decrypting AES key: {str(e)}")
            raise

    @staticmethod
    def encrypt_message_with_aes(message, aes_key):
        """Encrypt message using AES-GCM (matching Web Crypto API)"""
        try:
            # Generate a random 12-byte IV (nonce) for AES-GCM
            iv = os.urandom(12)

            # Create a GCM encryptor
            encryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv),
                backend=default_backend()
            ).encryptor()

            # Encrypt and get auth tag
            ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

            # Combine IV, ciphertext, and auth tag in a format matching JS implementation
            iv_b64 = base64.b64encode(iv).decode('utf-8')
            ct_b64 = base64.b64encode(ciphertext + encryptor.tag).decode('utf-8')

            return f"{iv_b64}:{ct_b64}"
        except Exception as e:
            logger.error(f"Error encrypting message with AES: {str(e)}")
            raise

    @staticmethod
    def decrypt_message_with_aes(encrypted_message, aes_key):
        """Decrypt message using AES-GCM"""
        try:
            # Parse the encrypted message
            iv_b64, ct_b64 = encrypted_message.split(':')
            iv = base64.b64decode(iv_b64)
            ct_with_tag = base64.b64decode(ct_b64)

            # Split ciphertext and auth tag (last 16 bytes)
            ciphertext = ct_with_tag[:-16]
            tag = ct_with_tag[-16:]

            # Create a GCM decryptor
            decryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()

            # Decrypt
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            logger.error(f"Error decrypting message with AES: {str(e)}")
            raise

    @staticmethod
    def generate_aes_key():
        """Generate a random 256-bit AES key (for AES-GCM)"""
        return os.urandom(32)  # 256-bit AES key to match Web Crypto API

    @staticmethod
    def encrypt_public_key(public_key):
        """Encrypt a public key for storage in the database"""
        try:
            # Derive a key from SERVER_KEY
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(SERVER_KEY.encode('utf-8'))

            # Use AES-GCM for encrypting the public key
            iv = os.urandom(12)
            encryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=default_backend()
            ).encryptor()

            ciphertext = encryptor.update(public_key.encode('utf-8')) + encryptor.finalize()

            # Encode all components for storage
            salt_b64 = base64.b64encode(salt).decode('utf-8')
            iv_b64 = base64.b64encode(iv).decode('utf-8')
            tag_b64 = base64.b64encode(encryptor.tag).decode('utf-8')
            ct_b64 = base64.b64encode(ciphertext).decode('utf-8')

            return f"{salt_b64}:{iv_b64}:{tag_b64}:{ct_b64}"
        except Exception as e:
            logger.error(f"Error encrypting public key: {str(e)}")
            raise

    @staticmethod
    def decrypt_public_key(encrypted_public_key):
        """Decrypt a public key from the database"""
        try:
            # Parse the encrypted data
            parts = encrypted_public_key.split(':')
            if len(parts) != 4:
                # Try legacy format (for backwards compatibility)
                return EncryptionService._decrypt_public_key_legacy(encrypted_public_key)

            salt_b64, iv_b64, tag_b64, ct_b64 = parts
            salt = base64.b64decode(salt_b64)
            iv = base64.b64decode(iv_b64)
            tag = base64.b64decode(tag_b64)
            ciphertext = base64.b64decode(ct_b64)

            # Derive the key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(SERVER_KEY.encode('utf-8'))

            # Decrypt
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            logger.error(f"Error decrypting public key: {str(e)}")
            raise

    @staticmethod
    def _decrypt_public_key_legacy(encrypted_public_key):
        """Legacy method for backwards compatibility"""
        try:
            import Crypto.Cipher.AES
            import Crypto.Util.Padding

            key = SERVER_KEY.encode('utf-8')[:16].ljust(16, b'\0')
            iv, ct = encrypted_public_key.split(':')
            iv = base64.b64decode(iv)
            ct = base64.b64decode(ct)
            cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
            pt = Crypto.Util.Padding.unpad(cipher.decrypt(ct), Crypto.Cipher.AES.block_size)
            return pt.decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to decrypt public key with legacy method: {str(e)}")
            raise