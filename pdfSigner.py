
"""  Sign a PDF file  """


#from random import randint
from datetime import datetime,timedelta
from pyPdf import PdfFileWriter, PdfFileReader
from pyPdf.generic import *
import hashlib
from cms import *
from StringIO import StringIO
    
import logging
#logging.basicConfig(level=logging.DEBUG)

class PdfSigner(object):
    def __init__(self,pdfStream,x509PemStream,rsaPvkPemStream):
        self._pdfStream = pdfStream
        self._x509PemStream = x509PemStream
        self._rsaPvkPemStream = rsaPvkPemStream
        self._outputpdf = StringIO()
        self._newobjectscount = 0
        self._startxref = 0
        self._xref_location = 0
        self._newobjects_collections = {}
        self._newxref = {}
        self._xrefcount = {}
        self._reader = None
        self._trailer = None
        self._catalog = None
        self._objectscount = None
        self._PageParentRef = 0
        self._VObjIdnum = 0
        self._SigObjIdnum = 0
        self._SigDictObj = DictionaryObject()
        self._ByteRange1 = 0
        self._ByteRange2 = 0
        self._ByteRange3 = 0
        self.PKCS7_SIZE = 4098

        self._rebuildPDF()

    def _getObjectsCount(self):
        retval = self._trailer["/Size"]
        return retval;

    def _isSigned(self):
        _bIsSigned = False
        if self._catalog.has_key("/AcroForm"):
            acroform = self._catalog["/AcroForm"]
            if acroform.has_key("/SigFlags"):
                n = acroform["/SigFlags"]
                if n == 3:
                    _bIsSigned = True
        return _bIsSigned



    def _rebuildPDF(self):
        self._reader = PdfFileReader(self._pdfStream)
        self._trailer = self._reader.trailer
        self._catalog = self._trailer["/Root"]
        
        _bIsSigned = self._isSigned()

        if not _bIsSigned:
            output = PdfFileWriter()
            for page in self._reader.pages:
                output.addPage(page)
            output.write(self._outputpdf)
        else:
            self._reader.stream.seek(0,0)
            self._outputpdf.write(self._reader.stream.read())

        self._reader = PdfFileReader(self._outputpdf)
        self._trailer = self._reader.trailer
        self._catalog = self._trailer["/Root"]
        self._objectscount = self._trailer["/Size"]



    def _addPageAnnots(self, nPageNumber):
        logging.debug("AddPageAnnots")

        # Get Page Parent
        page = self._reader.getPage(nPageNumber)
        pageparent = page["/Parent"]
        kids = pageparent["/Kids"]
        pageIndirect = kids[nPageNumber]
        self._PageParentRef = pageIndirect.idnum

        if page.has_key("/Annots"):
            annots = page["/Annots"]
            annots.append(IndirectObject(self._SigObjIdnum, 0, self))
        else:
            annots = ArrayObject()
            annots.append(IndirectObject(self._SigObjIdnum, 0, self))
            page[NameObject("/Annots")] = annots

        self._newobjects_collections[self._PageParentRef] = page


    def _addAcroFormRef(self):
        # found AcroForm
        if self._catalog.has_key("/AcroForm"):
            acroform = self._catalog["/AcroForm"]
            acroform[NameObject("/SigFlags")] = NumberObject(3)
            acrofields = acroform["/Fields"]
            self._newobjectscount += 0
            self._SigObjIdnum = self._objectscount + self._newobjectscount
            acrofields.append(IndirectObject(self._SigObjIdnum, 0, self))
            #acroform.update({NameObject("/Fields"): acrofields})
            acroformRef = self._catalog.raw_get("/AcroForm")

            # check if AcroForm is a standalone object
            if isinstance(acroformRef,IndirectObject):
                self._newobjects_collections[acroformRef.idnum] = acroform
            else:
                catalogobj = self._trailer.raw_get("/Root")
                self._newobjects_collections[catalogobj.idnum] = self._catalog

        else: # no AcroForm
            self._newobjectscount += 0
            catalogobj = self._trailer.raw_get("/Root")
            self._catalog.update({NameObject("/AcroForm"): IndirectObject(self._objectscount + self._newobjectscount, 0, self)})
            self._newobjects_collections[catalogobj.idnum] = self._catalog
            self._addNewAcroFormObj()

    def _addNewAcroFormObj(self):
        logging.debug("AddNewAcroFormObj")
        
        fieldsArray = ArrayObject()
        objcount = self._newobjectscount
        self._newobjectscount += 1
        self._SigObjIdnum = self._objectscount + self._newobjectscount
        fieldsArray.append(IndirectObject(self._SigObjIdnum, 0, self))

        acroform = DictionaryObject()
        acroform[NameObject("/Fields")] = fieldsArray
        acroform[NameObject("/SigFlags")] = NumberObject(3)

        self._newobjects_collections[self._objectscount + objcount] = acroform

    def _addSigFieldObj(self):
        logging.debug("AddDigSigFieldObj")
        
        self._newobjectscount += 1

        SigFieldObj = DictionaryObject()
        SigFieldObj[NameObject("/Type")] = NameObject("/Annot")
        SigFieldObj[NameObject("/Subtype")] = NameObject("/Widget")
        SigFieldObj[NameObject("/FT")] = NameObject("/Sig")
        SigFieldObj[NameObject("/Ff")] = NumberObject(1)
        SigFieldObj[NameObject("/F")] = NumberObject(132)
        SigName = u"Signature" + str(self._objectscount)
        SigFieldObj[NameObject("/T")] = createStringObject(SigName)
        SigFieldObj[NameObject("/V")] = IndirectObject(self._objectscount + self._newobjectscount, 0, self)
        SigFieldObj[NameObject("/P")] = IndirectObject(self._PageParentRef, 0, self)

        rect = ArrayObject()
        rect.append(NumberObject(0))
        rect.append(NumberObject(0))
        rect.append(NumberObject(0))
        rect.append(NumberObject(0))

        SigFieldObj[NameObject("/Rect")] = rect
        
        self._newobjects_collections[self._SigObjIdnum] = SigFieldObj

    def _addSigDictObj(self):
        logging.debug("AddDigSigDictObj")

        brArray = ArrayObject()
        brArray.append(NumberObject(0))
        brArray.append(NumberObject(1000))
        brArray.append(NumberObject(1000))
        brArray.append(NumberObject(1000))

        #sByteRange = ' ' * 30
        #sByteRange += "/ByteRange"
        self._SigDictObj[NameObject("/ByteRange")] = brArray
        self._SigDictObj[NameObject("/Type")] = NameObject("/Sig")
        self._SigDictObj[NameObject("/Name")] = createStringObject(u"asaf")
        self._SigDictObj[NameObject("/Filter")] = NameObject("/Asaf.Doron")
        self._SigDictObj[NameObject("/SubFilter")] = NameObject("/adbe.pkcs7.sha1")
        # get the date
        now = datetime.utcnow()
        strnow = now.strftime('D:%Y%m%d%H%M%S')
        self._SigDictObj[NameObject("/M")] = createStringObject(strnow)

        sContents = '0' * 4096
        self._SigDictObj[NameObject("/Contents")] = NameObject("<" + sContents + ">")

        self._VObjIdnum = self._objectscount + self._newobjectscount
        self._newobjects_collections[self._VObjIdnum] = self._SigDictObj


    #def _addSigAPObj(self):
         #logging.debug("AddSigAPObj")

         #SigAPObj = DictionaryObject()



    def _buildNewTrailer(self):
        logging.debug("BuildNewTrailer")
        
        self._trailer.update({
                NameObject("/Size"): NumberObject(self._objectscount + self._newobjectscount + 1),
                NameObject("/Prev"): NumberObject(self._startxref)
                })


    def _getStartXref(self):
        logging.debug("GetStartXref")

        stream = self._outputpdf
        # start at the end:
        stream.seek(-1, 2)
        line = ''
        while not line:
            line = self._reader.readNextEndLine(stream)

        # find startxref entry - the location of the xref table
        line = self._reader.readNextEndLine(stream)
        self._startxref = int(line)
       

    def _writeXref(self):
        logging.debug("WriteXref")

        stream = self._outputpdf
        self._xref_location = stream.tell()
        stream.write("xref\n")

        keyfirst = self._xrefcount.keys()[0]
        val = self._xrefcount[keyfirst]

        if keyfirst == 1:
                stream.write("0 %s\n" % (val + 1))
        else:
                stream.write("0 1\n")

        stream.write("%010d %05d f \n" % (0, 65535))

        for key in sorted(self._xrefcount.iterkeys()):
            val = self._xrefcount[key]

            if key != 1:
                stream.write("%s %s\n" % (key,val))

            for i in range(0, val):
                 offset = self._newxref[key + i]
                 stream.write("%010d %05d n \n" % (offset, 0))

    def _preSign(self):
        logging.debug("PreSign")
        

        self._addAcroFormRef()
        #self.AddAcroFormObj()
        self._addPageAnnots(0)
        self._addSigFieldObj()
        self._addSigDictObj()

        self._getStartXref()

        stream = self._reader.stream
        stream.seek(0,2)

        colkeys = sorted(self._newobjects_collections.keys())
        keytmp = colkeys[0]
        keyprev = colkeys[0]
        nxref = 1
        idx = 0
        # write the new objects
        for key in sorted(self._newobjects_collections.iterkeys()):
            #...do whatever with dict[key]...
            objdict = self._newobjects_collections[key]
            self._newxref[key] = stream.tell()
            stream.write(str(key) + " 0 obj\n")
            objdict.writeToStream(stream, None)
            if key == self._VObjIdnum:
                #scomment = '%' * 30
                scomment = ' ' * 30
                scomment += "\n"
                stream.write(scomment)
            stream.write("\nendobj\n")

            #build xref counter
            if idx > 0:
                if key == keyprev + 1:
                    nxref += 1
                else:
                    self._xrefcount[keytmp] = nxref
                    nxref = 1
                    keytmp = key

            idx+=1
            keyprev = key

        if nxref > 1:
            self._xrefcount[keytmp] = nxref

        # write xref
        self._writeXref()

        # write trailer
        self._buildNewTrailer()
        stream.write("trailer\n")
        self._trailer.writeToStream(stream, None)

        # eof
        stream.write("\nstartxref\n%s\n%%%%EOF\n" % (self._xref_location))


    def _calcByteRange(self):
        logging.debug("CalcByteRange")

        stream = self._outputpdf
        eof = stream.tell()

        VObjXref = self._newxref[self._VObjIdnum]
        stream.seek(VObjXref, 0)

        i = 0 # count of '<'
        j = 0 # how many chars we read

        while True:
            tok = stream.read(1)
            j+=1
            if tok == '<':
                i+=1
            if i == 3:
                break

        self._ByteRange1 = VObjXref + j - 1
        self._ByteRange2 = self._ByteRange1 + self.PKCS7_SIZE
        self._ByteRange3 = eof - self._ByteRange2

        brArray = ArrayObject()
        brArray.append(NumberObject(0))
        brArray.append(NumberObject(self._ByteRange1))
        brArray.append(NumberObject(self._ByteRange2))
        brArray.append(NumberObject(self._ByteRange3))

        len1 = len("1000 1000 1000")
        len2 = len(str(self._ByteRange1) + str(self._ByteRange2) + str(self._ByteRange3)) + 2

        self._SigDictObj.update({NameObject("/ByteRange"):brArray})

        stream.seek(VObjXref, 0)
        stream.write(str(self._VObjIdnum) + " 0 obj\n")
        self._SigDictObj.writeToStream(stream, None)

        len3 = 30 - len2 + len1
        scomment = '%' * len3
        scomment += "\n"
        stream.write(scomment)


    def _calcSha1(self,block_size):
        logging.debug("calc_sha1")

        stream = StringIO()
        stream1 = self._outputpdf
        stream1.seek(0,0)
        stream.write(stream1.read(self._ByteRange1))
        stream1.seek(self._ByteRange2,0)
        stream.write(stream1.read(self._ByteRange3 + 1))
        stream.seek(0,0)

        sha1 = hashlib.sha1()
        while True:
            data = stream.read(block_size)
            if not data:
                break
            sha1.update(data)

        digest = sha1.digest()

        return digest

    #def _closePDFFile(self):
        #self._outputpdf.close()

    def _insertPks7(self,digest):
        logging.debug("InsertPks7")

        p7 = CMS()
        strp7 = p7.createPKCS7(digest,self._x509PemStream,self._rsaPvkPemStream)
        self._outputpdf.seek(self._ByteRange1+1,0)
        self._outputpdf.write(strp7)

    def Sign(self):
        logging.debug("Sign")

        self._preSign()
        self._calcByteRange()
        digest = self._calcSha1(8192)
        self._insertPks7(digest)

        logging.debug("Sign END")
        
        return self._outputpdf

