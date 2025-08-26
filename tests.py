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

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

def testPDFSigner():
    stream = StringIO()
    f = file('d:\\2.pdf','rb')
    stream.write(f.read())
    f.close()
    x509stream = StringIO()
    f = file('d:\\rsax509Cert.cer','rb')
    x509stream.write(f.read())
    f.close()
    rsastream = StringIO()
    f = file('d:\\rsax509key.pem','rb')
    rsastream.write(f.read())
    f.close()
    signer = PdfSigner(stream,x509stream,rsastream)
    stream = signer.Sign()
    f = file('d:\\2_sign.pdf', "wb")
    f.write(stream.getvalue())
    f.close()
    stream.close()

def testCMS():
    p7 = cms()
    data = '385DC6AA523D22E5F9558001EBAFCBAEFC842FB8'.decode('hex')
##    m = hashlib.sha1()
##    m.update(data)
##    #h = m.hexdigest()
##    h = m.digest()
##    p7.createPKCS7(h)

    x509stream = StringIO()
    f = file('d:\\rsax509Cert.cer','rb')
    x509stream.write(f.read())
    f.close()
    rsastream = StringIO()
    f = file('d:\\rsax509key.pem','rb')
    rsastream.write(f.read())
    f.close()
    p7.createPKCS7(data,x509stream,rsastream)

def testx509Generator():
    x509gen = x509Generator()
    x509gen.generate('asaf','asaf.doron@gmail.com')
    
    s = StringIO()
    s = x509gen.writeRSAPrivateKeyPEM(s)
    
    f = file('d:\\rsax509key.pem', "w")
    f.write(s.getvalue())
    f.close()
    s.close()
    
    s = StringIO()
    s = x509gen.writeX509PEM(s)
    f = file('d:\\rsax509Cert.cer', "w")
    f.write(s.getvalue())
    f.close()
    s.close()



def testRSAPrvKeyParser():
    stream = StringIO()
    f = file('D:\\downloads\\Python\\pdfSigner\\rsax509key.pem','r')
    stream.write(f.read())
    f.close()
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
