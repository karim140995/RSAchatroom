from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import (Encoding,PrivateFormat,NoEncryption,load_pem_public_key)
from cryptography.hazmat.primitives.serialization import PublicFormat 
import ldap
import ldap.modlist as modlist
import datetime
import uuid
import base64
import asn1
import re

#Ldap configuration
ldap_base= "dc=rsacrypto,dc=com"
con  = ldap.initialize("ldap://127.0.0.1")
con.simple_bind_s("cn=admin,dc=rsacrypto,dc=com","koukou1414")

#Create the application instance
app = Flask(__name__,template_folder = "templates")

#Generating a new certificate request
@app.route('/csr',methods=["POST"])
def certificateRequest():

    user = request.form['user']
    country = request.form['country']
    state = request.form['state']
    locality = request.form['locality']
    
    private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size = 2048,
    backend = default_backend()
    )    
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,str(user)),
        x509.NameAttribute(NameOID.COUNTRY_NAME, str(country)),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, str(state)),
        x509.NameAttribute(NameOID.LOCALITY_NAME,str(locality)),
    ]))
    requestcsr = builder.sign(
        private_key, hashes.SHA256(),default_backend()
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False,path_length=None), critical= True
    )
    csrpem = requestcsr.public_bytes(Encoding.PEM)
    with open(user+'.csr','wb') as f :
        f.write(csrpem)
        
    keypem = private_key.private_bytes(Encoding.PEM,
            PrivateFormat.TraditionalOpenSSL, NoEncryption())
    with open(user+'.key','wb') as f :
        f.write(keypem)
    json_response = {
        "csr" : csrpem,
        "key" : keypem
    }
    return jsonify(json_response)

#Signing a certificate request and returning CRT
@app.route('/crt',methods=["POST"])
def createCertificate() :
    
    # Reading certification request
    pem_csr = request.form["csr"]
    pem_csr = str.encode(pem_csr)
    csr = x509.load_pem_x509_csr(pem_csr,default_backend())

    # Reading ca certification
    pem_cert = open('ca.crt','rb').read()
    ca = x509.load_pem_x509_certificate(pem_cert,default_backend())

    # Reading ca key for signing
    pem_key = open('ca.key','rb').read()
    ca_key = serialization.load_pem_private_key(pem_key,password= None,backend= default_backend())

    # Creating a crt and signing it
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca.subject)
    builder = builder.not_valid_before(datetime.datetime.now())
    builder = builder.not_valid_after(datetime.datetime.now()+datetime.timedelta(7))
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(int(uuid.uuid4()))
    for ext in csr.extensions :
        builder = builder.add_extension(ext.value,ext.critical)
    certificate = builder.sign(
        private_key = ca_key,
        algorithm = hashes.SHA256(),
        backend = default_backend()
    )
    # Stored in ldap entry
    crt = certificate.public_bytes(serialization.Encoding.DER)
    # Returned to client
    crt_pem = certificate.public_bytes(serialization.Encoding.PEM)

    subjectName = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    with open(subjectName + '.DER','wb') as f:
        f.write(crt)
    der_cert = open(subjectName + '.DER','rb').read()
    #pem_cert = base64.b64encode(pem_cert)
    dn = "cn="+subjectName+","+ldap_base
    mlist = {
        "objectClass" : [b"inetOrgPerson"],
        "userCertificate;binary" : [der_cert],
        "sn" : [subjectName.encode("utf-8")]
    }
    try : 
        result = con.add_s(dn,modlist.addModlist(mlist))
    except ldap.LDAPError:
        return jsonify("User already exists"),401
    json_response ={
        "crt" : crt_pem
    }
    return jsonify(json_response)

#Login with user certificate
@app.route("/login",methods = ["POST"])    
def search_entries() :
        
    # Reading certification request
    crt_request = request.form["certificate"]
    crt_request = str.encode(crt_request)
    # Search parameters
    cn = request.form["cn"]
    cn = re.sub('[^A-Za-z0-9]+', '', cn )
    searchScope = ldap.SCOPE_SUBTREE
    searchFilter = "cn=*"+cn+"*"
    retrieveAttributes = None

    #Searching LDAP entry
    result  = con.search_s(ldap_base,searchScope,searchFilter,retrieveAttributes)
    if( not result) :
        return jsonify("Entry not found"),401
    #Getting DER certificate and converting it to PEM
    der_cert = result[0][1]
    der_cert = der_cert.get("userCertificate;binary")[0]
    try : 
        certificate = x509.load_der_x509_certificate(der_cert,default_backend())
        crt = certificate.public_bytes(serialization.Encoding.PEM)
    except ldap.LDAPError:
        return jsonify("Bad certification format"),401
    if(crt == crt_request ) :
        return jsonify(crt),200
    else :
        return jsonify("Unvalid certificate"),401
    
#Route that return all users
@app.route("/user",methods = ["GET"])
def get_users() :
    searchScope = ldap.SCOPE_SUBTREE
    searchFilter = "(objectClass=inetOrgPerson)"
    retrieveAttributes = None
    result  = con.search_s(ldap_base,searchScope,searchFilter,retrieveAttributes)
    users = []
    for user in result :
        
        #Retrieving certificate and public key
        inetOrgPerson = user[1]
        certificateDER = inetOrgPerson.get("userCertificate;binary")[0] 
        certificatePEM = x509.load_der_x509_certificate(certificateDER,default_backend())
        pubkey = certificatePEM.public_key()
        pubkey = pubkey.public_bytes(serialization.Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
        
        #Converting certificate to PEM
        certificatePEM = certificatePEM.public_bytes(serialization.Encoding.PEM)    

        entry={}
        cn = inetOrgPerson.get("cn")[0]
        entry["cn"] = cn
        entry["certificate"] = certificatePEM
        entry["pubkey"] = pubkey
        users.append(entry)
    return jsonify(users)

#Route to delete a user
@app.route("/user",methods = ["POST"])
def delete_user() :
    subjectName=request.form["cn"]
    dn = "cn="+subjectName+","+ldap_base
    try : 
        con.delete_s(dn)
    except ldap.LDAPError:
        return jsonify("Invalid cn"),401
                 

            
