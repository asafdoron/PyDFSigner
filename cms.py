
"""  Create a signed data PKCS7  """

import random
import math
from datetime import datetime,timedelta
import string, base64
import pyasn1.codec.der.encoder
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
import hashlib
#from Crypto import Random
from tlslite.api import *
import array
from io import BytesIO

from x509Generator import x509Generator
from x509Parser import x509Parser
from pkcs7 import *


dataId = univ.ObjectIdentifier('1.2.840.113549.1.7.1')
signedDataId = univ.ObjectIdentifier('1.2.840.113549.1.7.2')
sha1withRSAEncryptionId = univ.ObjectIdentifier('1.2.840.113549.1.1.5')
rsaEncryptionId = univ.ObjectIdentifier('1.2.840.113549.1.1.1')
sha1Id = univ.ObjectIdentifier('1.3.14.3.2.26')


class CMS(object):
    def __init__(self):
        self.x509 = None
        self.rsakey = None
        self.issuerInfo = None
        self.serialNumber = None
        self.digest = None

    def createPKCS7(self,digest,x509PemStream,rsaPvkPemStream):
        self.digest = digest

        xp = x509Parser(x509PemStream)
        xp.Parse()

        rsaPvkPemStream.seek(0,0)
        s = ''
        for line in rsaPvkPemStream:
            s = s + line

        self.x509 = xp.getX509()
        self.issuerInfo = xp.getIssuerInfo()
        self.serialNumber = xp.getSerialNumber()

        self.rsakey = parsePEMKey(s,True,False,None,["python"])
        rsaPvkPemStream.close()

        return self._create()

    def _create(self):

        p7 = univ.Sequence()
        p7.setComponentByPosition(0,signedDataId)
        signedData = SignedData()

        # Version
        signedData.setComponentByName('version', 1)

        # DigestAlgorithmIdentifier
        # sha1withRSAEncryption
        digestAlgorithm = DigestAlgorithmIdentifier()
        #digestAlgorithm.setComponentByPosition(0, sha1withRSAEncryptionId)
        digestAlgorithm.setComponentByPosition(0, sha1Id)
        digestAlgorithm.setComponentByPosition(1, univ.Null())

        digestAlgorithmIdentifiers = DigestAlgorithmIdentifiers()
        digestAlgorithmIdentifiers.setComponentByPosition(0,digestAlgorithm)
        signedData.setComponentByName('digestAlgorithms', digestAlgorithmIdentifiers)

        # Content Info
        contentInfo = ContentInfo()
        contentInfo.setComponentByName('contentType',dataId)
        content = univ.Any().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        contentInfo.setComponentByName('content',self.digest)

        signedData.setComponentByName('contentInfo', contentInfo)

        # ExtendedCertificatesAndCertificates
        cert = ExtendedCertificateOrCertificate()
        cert.setComponentByName('certificate',self.x509)
        excerts = ExtendedCertificatesAndCertificates().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        excerts.setComponentByPosition(0,cert)
        signedData.setComponentByName('certificates', excerts)

        # SignerInfo
        signerInfo = SignerInfo()
        signerInfo.setComponentByName('version',1)

        issuerAndSN = IssuerAndSerialNumber()
        issuerAndSN.setComponentByName('issuer',self.issuerInfo)
        issuerAndSN.setComponentByName('serialNumber',self.serialNumber)

        signerInfo.setComponentByName('issuerAndSerialNumber',issuerAndSN)

        signerInfo.setComponentByName('digestAlgorithm', digestAlgorithm)

        # AlgorithmIdentifier for rsaEncryption
        # rsaEncryption identifier:
        digestEncryptionAlgorithm = DigestEncryptionAlgorithmIdentifier()
        digestEncryptionAlgorithm.setComponentByName('algorithm', rsaEncryptionId)
        digestEncryptionAlgorithm.setComponentByName('parameters', univ.Null())

        signerInfo.setComponentByName('digestEncryptionAlgorithm', digestEncryptionAlgorithm)

        #encryptedDigest
        encryptedDigest = EncryptedDigest()

        """ Calculate sha1 PKCS1 signature """
        data = array.array('B', self.digest)
        signature_bytes = self.rsakey.hashAndSign(data)

        strsig = signature_bytes.tobytes();
        encryptedDigest = univ.OctetString(strsig)

        signerInfo.setComponentByName('encryptedDigest', encryptedDigest)

        signerInfos = SignerInfos()
        signerInfos.setComponentByPosition(0,signerInfo)

        signedData.setComponentByName('signerInfos', signerInfos)

        signedDataSeq = univ.Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        signedDataSeq.setComponentByPosition(0,signedData)

        p7.setComponentByPosition(1,signedDataSeq)

        # encode ASN.1 PKCS7
        strp7 = pyasn1.codec.der.encoder.encode(p7)

        return strp7.hex()

