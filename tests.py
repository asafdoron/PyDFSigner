#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      asafd
#
# Created:     17/06/2011
# Copyright:   (c) asafd 2011
# Licence:     <your licence>
#-------------------------------------------------------------------------------
#!/usr/bin/env python

from x509Generator import *
from cms import *
from pdfSigner import *

from tlslite.api import *

from io import BytesIO

def testPDFSigner():
    stream = BytesIO()
    with open('d:\\2.pdf','rb') as f:
        stream.write(f.read())
    x509stream = BytesIO()
    with open('d:\\rsax509Cert.cer','rb') as f:
        x509stream.write(f.read())
    rsastream = BytesIO()
    with open('d:\\rsax509key.pem','rb') as f:
        rsastream.write(f.read())
    signer = PdfSigner(stream,x509stream,rsastream)
    stream = signer.Sign()
    with open('d:\\2_sign.pdf', "wb") as f:
        f.write(stream.getvalue())
    stream.close()

def testCMS():
    p7 = cms()
    data = bytes.fromhex('385DC6AA523D22E5F9558001EBAFCBAEFC842FB8')
##    m = hashlib.sha1()
##    m.update(data)
##    #h = m.hexdigest()
##    h = m.digest()
##    p7.createPKCS7(h)

    x509stream = BytesIO()
    with open('d:\\rsax509Cert.cer','rb') as f:
        x509stream.write(f.read())
    rsastream = BytesIO()
    with open('d:\\rsax509key.pem','rb') as f:
        rsastream.write(f.read())
    p7.createPKCS7(data,x509stream,rsastream)

def testx509Generator():
    x509gen = x509Generator()
    x509gen.generate('asaf','asaf.doron@gmail.com')
    
    s = BytesIO()
    s = x509gen.writeRSAPrivateKeyPEM(s)
    
    with open('d:\\rsax509key.pem', "w") as f:
        f.write(s.getvalue())
    s.close()
    
    s = BytesIO()
    s = x509gen.writeX509PEM(s)
    with open('d:\\rsax509Cert.cer', "w") as f:
        f.write(s.getvalue())
    s.close()



def testRSAPrvKeyParser():
    stream = BytesIO()
    with open('D:\\downloads\\Python\\pdfSigner\\rsax509key.pem','r') as f:
        stream.write(f.read())
    stream.seek(0,0)
    s = ''
    for line in stream:
        s = s + line
    rsakey = parsePEMKey(s,True,False,None,["python"])
    stream.close()

def main():
    testx509Generator()
    testPDFSigner()
    pass

if __name__ == '__main__':
    main()
