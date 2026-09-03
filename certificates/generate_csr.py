from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

with open('certificates/private_key.pem', 'wb') as f:
    f.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, 'NSMobile'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Salim Benfarhat'),
    x509.NameAttribute(NameOID.COUNTRY_NAME, 'CH'),
])).sign(key, hashes.SHA256())

with open('certificates/request_new.csr', 'wb') as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

print('OK - CSR and key generated')
