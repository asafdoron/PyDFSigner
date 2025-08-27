
"""  Parse x509 certificate  """



import string, base64
from io import BytesIO

from x509 import *

stSpam, stHam, stDump = 0, 1, 2

class x509Parser(object):
    def __init__(self,x509PemStream):
        self.x509PemStream = x509PemStream
        self.x509 = None
        self.tbsCertificate = None


    def readPemFromFile(self):
        state = stSpam
        self.x509PemStream.seek(0,0)
        while True:
            certLine = self.x509PemStream.readline()
            if not certLine:
                break
            certLine = certLine.strip()
            if state == stSpam:
                if certLine == '-----BEGIN CERTIFICATE-----':
                    certLines = []
                    state = stHam
                    continue
            if state == stHam:
                if certLine == '-----END CERTIFICATE-----':
                    state = stDump
                else:
                    certLines.append(certLine)
            if state == stDump:
                substrate = ''
                for certLine in certLines:
                    substrate = substrate + base64.decodebytes(certLine.encode())
                return substrate

    def Parse(self):
        certType = Certificate()

        certCnt = 0

        substrate = self.readPemFromFile()
        if not substrate:
            return

        self.x509 = decoder.decode(substrate, asn1Spec=certType)[0]
        self.tbsCertificate = self.x509.getComponentByName('tbsCertificate')


    def getX509(self):
        """ Gets a data structure representing an x509. """
        return self.x509

    def getIssuerInfo(self):
        """ Gets x509 Subject Info """
        issuerInfo = self.tbsCertificate.getComponentByName('issuer')
        return issuerInfo

    def getSerialNumber(self):
        """ Gets x509 Serial Number """
        serialNumber = self.tbsCertificate.getComponentByName('serialNumber')
        return serialNumber



