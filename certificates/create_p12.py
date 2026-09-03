from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes
import datetime

# Load private key
with open('certificates/private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Load certificate (DER format from Apple)
with open('certificates/distribution.cer', 'rb') as f:
    cert_der = f.read()

try:
    cert = x509.load_der_x509_certificate(cert_der)
    print("Format: DER")
except Exception:
    cert = x509.load_pem_x509_certificate(cert_der)
    print("Format: PEM")

print("Certificat:", cert.subject)

# Check if key matches cert
from cryptography.hazmat.primitives.asymmetric import rsa
pub = cert.public_key()
print("Public key type:", type(pub).__name__)

# Extract public key from private
priv_pub = private_key.public_key()

# Compare public numbers
cert_pub_num = pub.public_numbers() if isinstance(pub, rsa.RSAPublicKey) else None
priv_pub_num = priv_pub.public_numbers() if isinstance(priv_pub, rsa.RSAPublicKey) else None

if cert_pub_num == priv_pub_num:
    print("La cle privee MATCH le certificat - OK")
else:
    print("ATTENTION: la cle privee ne correspond pas au certificat.")

# Encrypt private key with a password and package as PKCS12 (.p12)
password = b"nsmobile2024"
p12_data = pkcs12.serialize_key_and_certificates(
    name=b"NSMobile Distribution",
    key=private_key,
    cert=cert,
    cas=None,
    encryption_algorithm=serialization.BestAvailableEncryption(password)
)

with open('certificates/distribution.p12', 'wb') as f:
    f.write(p12_data)

print("P12 cree: certificates/distribution.p12")
