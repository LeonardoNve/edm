#!/usr/bin/env python
# -*- coding: utf-8 -*-
# wget -e http_proxy=127.0.0.1:8000 --no-cache http://ilalocal1526.net/workorders.docx
# www.loc.gov/catdir/cpso/romanization/arabic.docx


import sys, struct, zlib, re, os
import zipfile, zlib
import string, random
import struct
import tempfile
import json

OOXMLContentTypes        = [
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.openxmlformats-officedocument.presentationml.slideshow'
]

genericOOXMLContentTypes = ['application/vnd.openxmlformats']
extensiones = ['.docx', '.xlsx', '.pptx', '.ppsx']

MIN_OOXML_SIZE = 1000

def OOXMLCheck(headers, uri):
    if "content-length" in headers:
        if int(headers["content-length"]) < MIN_OOXML_SIZE :
            return False
    else:
        return False

    if "content-type" in headers:
        contenttype = headers["content-type"]
    else:
        return False

    if contenttype in OOXMLContentTypes:
        return True

    if contenttype in genericOOXMLContentTypes:
        for extension in extensiones:
            if extension in uri:
                return True

        if "content-disposition" in headers:
            for extension in extensiones:
                if extension in headers['content-disposition']:
                    return True

    return False

class BloqueLFH:
    '''
        Almacenamiento y tratamiendo de datos de los bloques Local File Header y File Data.
    '''
    ESTRUCTURA_CABECERA = "<4s2B4HL2L2H"
    TAMANO_CABECERA 	= None
    FIRMA 				= "PK\003\004"
    _CIDX_FIRMA			= 0
    _CIDX_FLAGS			= 3
    _CIDX_COMPRESION	= 4
    _CIDX_CRC			= 7
    _CIDX_COMPRIMIDO 	= 8
    _CIDX_DESCOMPRIMIDO = 9
    _CIDX_NOMBRE_LENGTH = 10
    _CIDX_EXTRA_LENGTH 	= 11

    def __init__(self):
        self.TAMANO_CABECERA = struct.calcsize(self.ESTRUCTURA_CABECERA)
        self.cabecera  = None
        self.sobrante  = ""
        self.contenido = None
        self.nombre    = None
        self.extra     = None

    def datosBasicos(self):
        return { self.nombre : [
            self.cabecera[self._CIDX_COMPRIMIDO],
            self.cabecera[self._CIDX_DESCOMPRIMIDO],
            self.cabecera[self._CIDX_CRC]
            ]
        }

    def inicializa(self, datos):
        try:
            # cabecera
            aux = datos[:self.TAMANO_CABECERA]
            self.cabecera = struct.unpack(self.ESTRUCTURA_CABECERA, aux)
            # campos de longitud variable en cabecera
            self.nombre = datos[ self.TAMANO_CABECERA : self.TAMANO_CABECERA + self.cabecera[self._CIDX_NOMBRE_LENGTH] ]
            self.extra  = datos[ self.TAMANO_CABECERA + self.cabecera[self._CIDX_NOMBRE_LENGTH] : self.TAMANO_CABECERA + self.cabecera[self._CIDX_NOMBRE_LENGTH] + self.cabecera[self._CIDX_EXTRA_LENGTH]]
            # stream de contenido
            inicio_datos = self.TAMANO_CABECERA + self.cabecera[self._CIDX_NOMBRE_LENGTH] + self.cabecera[self._CIDX_EXTRA_LENGTH]
            size_datos = self.cabecera[self._CIDX_COMPRIMIDO]
            if len(datos) < inicio_datos + size_datos:
                self.sobrante = datos
                return -1 	## bloque incompleto
            elif len(datos) > inicio_datos + size_datos:
                self.contenido = datos[inicio_datos : inicio_datos + size_datos]
                self.sobrante  = datos[inicio_datos + size_datos : ]
                return 1 	## datos sobrantes en bloque
            else:
                self.contenido = datos[inicio_datos : ]
                return 0 	## bloque exacto
        except Exception, e:
            self.sobrante = datos
            return -1 		## unpack error, bloque incompleto

    def serializa(self):
        return struct.pack(self.ESTRUCTURA_CABECERA, *self.cabecera) + self.nombre + self.extra + self.contenido

    def extraeStreamDescomprimido(self):
        return zlib.decompress(self.contenido, -15)

    def actualizaGenerico(self, elQue, aPartirDeDonde, conNombre, condicional = False):
        # descomprimir
        try:
            original = self.extraeStreamDescomprimido()
        except Exception, e:
            print "!! Descompression exception: ",e
            return 

        try:
            modificado = original.replace(aPartirDeDonde, elQue, 1)
        except Exception, e:
            print "!! Replace exception: ",e
            return

        try:
            # Compresion temporal en fichero .zip
            tdir = tempfile.gettempdir()
            tzip = os.path.join(os.path.sep, tdir, 'ups.zip')
            fz = zipfile.ZipFile(tzip,'w', zipfile.ZIP_DEFLATED)
            fz.writestr(conNombre, modificado)
            fz.close()
            fh = open(tzip, 'rb')
            fc = fh.read()
            fh.close()
            os.remove(tzip)
            # Actualizacion objeto bloque
            fc = fc[ : fc.find('PK\001\001') ]
            self.inicializa(fc)
        except Exception, e:
            print "!! Compression exception: ",e

    def insertaEmbedido(self, injectObjects):
        try:
            a = injectObjects
            b = []
            for c in a:
                # leemos binario OLE
                with open(c[0], 'rb') as fhole:
                    fcole = fhole.read()
                tdir = tempfile.gettempdir()
                tzip = os.path.join(os.path.sep, tdir, 'ups.zip')
                # lo comprimimos en fichero temporal
                with zipfile.ZipFile(tzip,'w', zipfile.ZIP_DEFLATED) as fz:
                    fz.writestr(c[1], fcole)
                    fz.close()
                # leemos su contenido y lo borramos.
                with open(tzip, 'rb') as fh:
                    fc = fh.read()
                    fh.close()
                os.remove(tzip)
                #
                zfh =  fc[ : fc.find('PK\001\002') ]
                objFH = BloqueLFH()
                objFH.inicializa(zfh)
                zfd =  fc[ fc.find('PK\001\002') : ]
                zfd = zfd[ : zfd.find('PK\005\006') ]
                objCD = BloqueCDFH()
                objCD.inicializa(zfd)
                b.append( (objFH, objCD) )
            return b
        except Exception, e:
            print '> Inserting exception: ',e
            return None

class BloqueCDFH:
    '''
        Almacenamiento y tratamiento de datos de los bloques 'Central Directory Record'
    '''
    ESTRUCTURA_CABECERA 	= "<4s4B4HL2L5H2L"
    TAMANO_CABECERA 		= None
    FIRMA 					= "PK\001\002"
    _CIDX_FIRMA				= 0
    _CIDX_FLAGS				= 5
    _CIDX_COMPRESION		= 6
    _CIDX_CRC				= 9
    _CIDX_COMPRIMIDO 		= 10
    _CIDX_DESCOMPRIMIDO 	= 11
    _CIDX_NOMBRE_LENGTH 	= 12
    _CIDX_EXTRA_LENGTH 		= 13
    _CIDX_COMMENT_LENGTH	= 14
    _CIDX_LH_OFFSET 		= 18

    def __init__(self):
        self.TAMANO_CABECERA = struct.calcsize(self.ESTRUCTURA_CABECERA)
        self.cabecera  = None
        self.sobrante  = ""
        self.nombre = None
        self.extra  = None

    def inicializa(self, datos):
        try:
            # cabecera
            aux = datos[:self.TAMANO_CABECERA]
            self.cabecera = struct.unpack(self.ESTRUCTURA_CABECERA, aux)
            # campos de longitud variable en cabecera
            nPos = self.TAMANO_CABECERA
            self.nombre = datos[ nPos : nPos + self.cabecera[self._CIDX_NOMBRE_LENGTH] ]
            ePos = self.TAMANO_CABECERA + self.cabecera[self._CIDX_NOMBRE_LENGTH]
            self.extra  = datos[ ePos : ePos + self.cabecera[self._CIDX_EXTRA_LENGTH]]
            cPos = self.TAMANO_CABECERA + self.cabecera[self._CIDX_NOMBRE_LENGTH] + self.cabecera[self._CIDX_EXTRA_LENGTH]

            if len(datos) < cPos:
                self.sobrante = datos
                return -1 	## bloque incompleto
            elif len(datos) > cPos:
                self.sobrante  = datos[ cPos : ]
                return 1 	## datos sobrantes en bloque
            else:
                return 0 	## bloque exacto
        except Exception, e:
            self.sobrante = datos
            return -1 		## unpack error, bloque incompleto

    def actualiza(self, datos):
        cbc = list(self.cabecera)
        cbc[self._CIDX_COMPRIMIDO] = datos[0]
        cbc[self._CIDX_DESCOMPRIMIDO] = datos[1]
        cbc[self._CIDX_CRC] = datos[2]
        cbc[self._CIDX_LH_OFFSET] = datos[3]
        self.cabecera = tuple(cbc)

    def serializa(self):
        return struct.pack(self.ESTRUCTURA_CABECERA, *self.cabecera) + self.nombre + self.extra

class BloqueEOCDR:
    '''
        Almacenamiento y tratamiento del End Of Central Directory Record
    '''
    ESTRUCTURA_CABECERA = "<4s4H2LH"
    TAMANO_CABECERA 	= None
    FIRMA 				= "PK\005\006"
    _CIDX_FIRMA			= 0
    _CIDX_EDISK 		= 3
    _CIDX_ETOTAL 		= 4
    _CIDX_CDSIZE 		= 5
    _CIDX_CD_OFFSET     = 6
    _CIDX_COMENT_LENGTH = 7

    def __init__(self):
        self.TAMANO_CABECERA = struct.calcsize(self.ESTRUCTURA_CABECERA)
        self.cabecera  = None
        self.sobrante  = ""
        self.comentarios  = None
        self.nombre = "EOCDR"

    def inicializa(self, datos):
        try:
            # cabecera
            aux = datos[:self.TAMANO_CABECERA]
            self.cabecera = struct.unpack(self.ESTRUCTURA_CABECERA, aux)
            # campos de longitud variable en cabecera
            self.comentarios  = datos[ self.TAMANO_CABECERA : self.TAMANO_CABECERA + self.cabecera[self._CIDX_COMENT_LENGTH] ]

            size_total = self.TAMANO_CABECERA + self.cabecera[self._CIDX_COMENT_LENGTH]
            if len(datos) < size_total:
                self.sobrante = datos
                return -1 	## bloque incompleto
            elif len(datos) > size_total:
                self.sobrante  = datos[ size_total : ]
                return 1 	## datos sobrantes en bloque
            else:
                return 0 	## bloque exacto
        except Exception, e:
            self.sobrante = datos
            return -1 		## unpack error, bloque incompleto

    def serializa(self):
        return struct.pack(self.ESTRUCTURA_CABECERA, *self.cabecera) + self.comentarios

    def actualizaDesplazamientos(self,off, total_entradas, size_CD):
        cbc = list(self.cabecera)
        cbc[self._CIDX_CD_OFFSET] = off
        cbc[self._CIDX_EDISK] 	  = total_entradas
        cbc[self._CIDX_ETOTAL]    = total_entradas
        cbc[self._CIDX_CDSIZE] 	  = size_CD
        self.cabecera = tuple(cbc)

class DOCXHandler:

    BLOQUE_INCOMPLETO 	= -1
    BLOQUE_COMPLETO  	= 0
    BLOQUE_MULTIPLE 	= 1
    TIPO_BLOQUE_LFH 	= 0
    TIPO_BLOQUE_CDFH 	= 1
    TIPO_BLOQUE_EOCDR 	= 2
    BLOQUE_VACIO 		= 0

    nuevoComprimido = nuevoDescomprimido = nuevo_crc32 = offsetDiff = 0

    configuration = None
    injectObjects = None

    tipo = None

    def __init__(self, ooxml_config, headers, uri):
        self.por_tratar = ""
        self.TipoDatosActuales = 0
        self.DatosBloques = {
            0: ( BloqueLFH(),   'PK\003\004'),
            1: ( BloqueCDFH(),  'PK\001\002'),
            2: ( BloqueEOCDR(), 'PK\005\006')
        }

        self.offset_LFH  = 0
        self.size_CD     = 0
        self.referencias = {}
        self.objetos     = None

        self.configuration = json.loads(open(ooxml_config).read())


        self.tipo = ".docx"

        for extension in extensiones:
            if extension in uri:
                self.tipo = extension

        if "content-disposition" in headers:
            for extension in extensiones:
                if extension in headers['content-disposition']:
                    return True

        self.injectObjects = []
        if self.tipo in self.configuration:
            if 'add' in self.configuration[self.tipo]:
                self.injectObjects = self.configuration[self.tipo]["add"]

        print "> OOXML detected Handling response for Content-Type %s" % headers["content-type"]



        #print "> DOCX detected Handling response for Content-Type %s" % response.getheader('Content-Type')

    def Bind(self, data, datalen, contentlength = 0, downloaded_name='temporal.docx'):
        if not self.tipo in self.configuration:
            return data, contentlength, 0

        return self.BlockHandler(data, datalen, contentlength, downloaded_name)

    def BlockHandler(self, data, datalen, contentlength = 0, downloaded_name='temporal.docx'):

        self.por_tratar += data

        TodoAnalizado 	= False
        aEnviar = ""
        while not TodoAnalizado:
            try:
                objPK, firmaActual = self.DatosBloques[self.TipoDatosActuales]
                bloques = self.por_tratar.split(firmaActual)

                if len(bloques) == self.BLOQUE_VACIO:
                    break

                for bloque in bloques:
                    if len(bloque) > self.BLOQUE_VACIO:
                        estado = objPK.inicializa(objPK.FIRMA + bloque)
                        self.por_tratar = objPK.sobrante

                        if estado == self.BLOQUE_INCOMPLETO:
                            TodoAnalizado = True
                            break

                        if self.TipoDatosActuales == self.TIPO_BLOQUE_LFH:

                            for fichero in self.configuration[self.tipo]["mod"]:
                                if fichero["name"] == objPK.nombre:
                                    print "> Updating file ",objPK.nombre
                                    objPK.actualizaGenerico(fichero["new"].encode("utf-8"), fichero["old"].encode("utf-8"), objPK.nombre)


                            dBasicos = objPK.datosBasicos()
                            dBasicos[dBasicos.keys()[0]].append(self.offset_LFH)
                            self.referencias.update(dBasicos)

                            aEnviar += objPK.serializa()
                            self.offset_LFH += len(objPK.serializa())

                            if estado == self.BLOQUE_MULTIPLE:
                                if len(self.injectObjects) > 0:
                                    print "> INSERTING files"

                                self.objetos = objPK.insertaEmbedido(self.injectObjects)

                                if self.objetos != None:
                                    for b in self.objetos:
                                        dBasicos = b[0].datosBasicos()
                                        dBasicos[dBasicos.keys()[0]].append(self.offset_LFH)
                                        self.referencias.update(dBasicos)
                                        aEnviar += b[0].serializa()
                                        self.offset_LFH += len(b[0].serializa())


                        elif self.TipoDatosActuales == self.TIPO_BLOQUE_CDFH:
                            objPK.actualiza(self.referencias[objPK.nombre])
                            aEnviar += objPK.serializa()
                            self.size_CD += len(objPK.serializa())
                            if estado == self.BLOQUE_MULTIPLE:
                                if self.objetos != None:
                                    for b in self.objetos:
                                        b[1].actualiza(self.referencias[b[1].nombre])
                                        aEnviar += b[1].serializa()
                                        self.size_CD += len(b[1].serializa())

                        elif self.TipoDatosActuales == self.TIPO_BLOQUE_EOCDR:
                            # actualizar offset del CD
                            objPK.actualizaDesplazamientos(self.offset_LFH, len(self.referencias), self.size_CD)
                            TodoAnalizado = True
                            aEnviar += objPK.serializa()
                            print "> WORK Finished"
                            break

                        if estado == self.BLOQUE_MULTIPLE:
                            self.TipoDatosActuales += 1

            except Exception, e:
                pass

        data = aEnviar
        return data, 0, 0

    def Padding(self):
        return None