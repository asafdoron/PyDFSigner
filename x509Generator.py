
"""  Generate x509 certificate   """


from datetime import datetime,timedelta
import string, base64
import pyasn1.codec.der.encoder
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
import hashlib
from tlslite.api import *
import array
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from x509 import *

import logging
logging.basicConfig(level=logging.DEBUG)

class x509Generator(object):
    def __init__(self):
        self.x509 = Certificate()
        self.rsakey = None
        self.SubjectSeq = Name()
        self.SerialNumber = None

    def toBitString_(self, num):
        """ Converts a long into the bit string. """
        buf = ''
        while num > 1:
          buf = str(num & 1) + buf
          num = num >> 1
        buf = str(num) + buf
        return buf

    def BytesToBin(self, bytes):
        """Convert byte string to bit string."""
        return "".join([self._PadByte(self.IntToBin(ord(byte))) for byte in bytes])

    def _PadByte(self, bits):
        """Pad a string of bits with zeros to make its length a multiple of 8."""
        r = len(bits) % 8
        return ((8-r) % 8)*'0' + bits

    def IntToBin(self, n):
        if n == 0 or n == 1:
            return str(n)
        elif n % 2 == 0:
            return self.IntToBin(n/2) + "0"
        else:
            return self.IntToBin(n/2) + "1"


    def generate(self, sCN, sEmail):
        logging.debug("generate")

        # Version
        version = Version(2)

        now = datetime.utcnow() - timedelta(days=1)
        strnow = now.strftime('%y%m%d%H%M%S')
        #Serial Number

        sn = int(strnow)
        self.SerialNumber = univ.Integer(sn)

        # Validity
        notBefore = now
        notAfter = notBefore + timedelta(days=365*30)
        strNotBefore = strnow + 'Z'
        strNotAfter = notAfter.strftime('%y%m%d%H%M%S') + 'Z'
        validity = Validity()
        t1 = Time()
        t1.setComponentByName('utcTime', strNotBefore)
        validity.setComponentByName('notBefore', t1)
        t2 = Time()
        t2.setComponentByName('utcTime', strNotAfter)
        validity.setComponentByName('notAfter', t2)

        # CommonName
        commonname = AttributeTypeAndValue()
        commonname.setComponentByName('type', AttributeType(univ.ObjectIdentifier('2.5.4.3')))
        commonname.setComponentByPosition(1, char.PrintableString(sCN))

        rdn = RelativeDistinguishedName()
        rdn.setComponentByPosition(0,commonname)

        rdnseq = RDNSequence()
        rdnseq.setComponentByPosition(0,rdn)

        self.SubjectSeq.setComponentByName('',rdnseq)


        # Email
##        idmail = univ.ObjectIdentifier('1.2.840.113549.1.9.1')
##        smail =  char.PrintableString(sEmail)
##        mail = univ.Sequence()
##        mail.setComponentByPosition(0, idmail)
##        mail.setComponentByPosition(1, smail)
##
##        mailsetof = univ.Set()
##        mailsetof.setComponentByPosition(0,mail)
##
##        self.SubjectSeq.setComponentByPosition(1,mailsetof)

        # rsaEncryption identifier:
        idrsaencryption = univ.ObjectIdentifier('1.2.840.113549.1.1.1')

        # AlgorithmIdentifier for rsaEncryption
        rsaalgid = AlgorithmIdentifier()
        rsaalgid.setComponentByName('algorithm', idrsaencryption)
        rsaalgid.setComponentByName('parameters', univ.Null())


        logging.debug("generate RSA")
        # Get a RSAPublicKey structure
        pkinfo = univ.Sequence()
        self.rsakey = generateRSAKey(1024,["python"])

        pkinfo.setComponentByPosition(0, univ.Integer(self.rsakey.n))
        pkinfo.setComponentByPosition(1, univ.Integer(self.rsakey.e))

        # Encode the public key info as a bit string
        pklong = long(pyasn1.codec.der.encoder.encode(pkinfo).encode('hex'), 16)
        pkbitstring = univ.BitString("'00%s'B" % self.toBitString_(pklong))

        #SubjectPublicKeyInfo structure
        publickeyinfo = SubjectPublicKeyInfo()
        publickeyinfo.setComponentByName('algorithm', rsaalgid)
        publickeyinfo.setComponentByName('subjectPublicKey', pkbitstring)


        # AlgorithmIdentifier for RSAEncryption
        #hashwithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.4')
        hashwithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.5')
        #algid = univ.Sequence()
        algid = AlgorithmIdentifier()
        algid.setComponentByName('algorithm',hashwithRSAEncryption)
        algid.setComponentByName('parameters', univ.Null())


        # TBSCertificate
        tbsCertificate = TBSCertificate()

        tbsCertificate.setComponentByName('version', 2)
        tbsCertificate.setComponentByName('serialNumber', self.SerialNumber)
        tbsCertificate.setComponentByName('signature', algid)
        tbsCertificate.setComponentByName('issuer', self.SubjectSeq)
        tbsCertificate.setComponentByName('validity', validity)
        tbsCertificate.setComponentByName('subject', self.SubjectSeq)
        tbsCertificate.setComponentByName('subjectPublicKeyInfo', publickeyinfo)

        logging.debug("calc x509 hash")
         # Encode the tbsCertificate sequence into ASN.1
        signature_bytes = self.rsakey.hashAndSign(pyasn1.codec.der.encoder.encode(tbsCertificate))
        strsig = array.array.tostring(signature_bytes);
        sigbitstring = univ.BitString("'%s'B" % self.BytesToBin(strsig))

        self.x509.setComponentByName('tbsCertificate', tbsCertificate)
        self.x509.setComponentByName('signatureAlgorithm', algid)
        self.x509.setComponentByName('signatureValue', sigbitstring)

        logging.debug("generate END")


    def writeX509PEM(self,stream):
        logging.debug("write X509 into PEM")

        stream.write('-----BEGIN CERTIFICATE-----\n')

        pem = base64.standard_b64encode(pyasn1.codec.der.encoder.encode(self.x509))
        pemlen = len(pem)
        i=0
        n=64
        while i+n < pemlen:
            stream.write(pem[i:i+n])
            stream.write('\n')
            i = i + n
        stream.write(pem[i:pemlen-1])

        stream.write('=\n-----END CERTIFICATE-----\n')

        #return stream

    def writeRSAPrivateKeyPEM(self,stream):
        logging.debug("write RSA Private Key into PEM")

        pvkSeq = univ.Sequence()
        pvkSeq.setComponentByPosition(0,univ.Integer(0))
        pvkSeq.setComponentByPosition(1,univ.Integer(self.rsakey.n))
        pvkSeq.setComponentByPosition(2,univ.Integer(self.rsakey.e))
        pvkSeq.setComponentByPosition(3,univ.Integer(self.rsakey.d))
        pvkSeq.setComponentByPosition(4,univ.Integer(self.rsakey.p))
        pvkSeq.setComponentByPosition(5,univ.Integer(self.rsakey.q))
        pvkSeq.setComponentByPosition(6,univ.Integer(self.rsakey.dP))
        pvkSeq.setComponentByPosition(7,univ.Integer(self.rsakey.dQ))
        pvkSeq.setComponentByPosition(8,univ.Integer(self.rsakey.qInv))

        stream.write('-----BEGIN RSA PRIVATE KEY-----\n')

        pem = base64.standard_b64encode(pyasn1.codec.der.encoder.encode(pvkSeq))
        pemlen = len(pem)
        i=0
        n=64
        while i+n < pemlen:
            stream.write(pem[i:i+n])
            stream.write('\n')
            i = i + n
        stream.write(pem[i:pemlen-1])
        #stream.write(pem)
        stream.write('=\n-----END RSA PRIVATE KEY-----\n')

        #return stream

    def getRSAKey(self):
        """ Gets a data structure representing an RSA public+private key. """
        return self.rsakey

    def getX509(self):
        """ Gets a data structure representing an x509. """
        return self.x509

    def getIssuerInfo(self):
        """ Gets x509 Subject Info """
        return self.SubjectSeq

    def getSerialNumber(self):
        """ Gets x509 Serial Number """
        return self.SerialNumber

