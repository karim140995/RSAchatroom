from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import (Encoding,PrivateFormat,NoEncryption)
import datetime
import uuid

private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size = 2048,
    backend = default_backend()
)

def certificateRequest():
    builder = x509.CertificationSigningRequestBUilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'USER:mfdutra'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID,STATE_OR_PROVINCE_NAME,u'California'),
        x509.NameAttribute(NameOID.LOCALITY_NAME,u'Menlo Park'),
    ]))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False,path_length=None), Critical= True
    )
    request = builder.sign(
        private_key, hashes.SHA256(),default_backend()
    )
    with open('mfdutra.csr','wb') as f :
        f.write(request.public_bytes(encoding.PEM))
    with open('mfdutra.key','wb') as f :
        f.write(privat_key.private_bytes(Encoding.PEM,
            PrivateFormat.TraditionalOpenSSL, NoEncryption()))
def createCertificate() :
    pem_csr = open('mfdutra.csr','rb').read()
    csr = x509.load_pem_x509_csr(pem_csr,default_backend())
    pem_cert = open('ca.crt').read()
    ca = x509.load_pem_x509_certificate(pem_cert,default_backend())
    ca_key = serialization.load_pem_private_key(pem_key,password= None,backend= default_backend())
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca.subject)
    builder = builder.not_valid_before(datetime.datetime.now())
    builder = builder.not_valid_after(datetime.datetime.now()+datetime.timedelta(7))
    builder = builder.public_key(csr_public())
    builder = builder.serial_number(int(uuid.uuid4()))
    for ext in csr.extensions :
        builder = builder.add_extension(ext.value,ext.critical)
    certificate = builder.sign(
        private_key = ca_key,
        algorithm = hashes.SHA256(),
        backend = default_backend()
    )
    with open('mfdutra.crt','wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    

        

    




    



    
        
    
