#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

import DOCXHandler

class FilterHandler:

	POS_PART  	= 0x00
	POS_EXPR 	= 0x01
	POS_HDNL 	= 0x02

	AT_REQUEST 	= 0x01
	AT_RESPONSE	= 0x02

	URL_PART	= 0x03
	HEADER_PART	= 0x04
	BODY_PART	= 0x05

	LOOK_AT		  = [ AT_REQUEST, AT_RESPONSE  			]
	IDENTITY_PART = [ URL_PART, HEADER_PART, BODY_PART 	]

	"""
		Pattern Example:
		{ 0x01 : [ 0x03, ['upload.php','download.php'], 'FOOBARHandlerClass' ]} Trigger Inspection with class FOOBARHandlerClass if upload.php or download.php patterns are present in URL of Request data.
	"""
	Filters_Patterns = [
		# Filter for DOCX Handler
		{ 0x02 : [ 0x04, ['Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document'], 'DOCXHandler' ]},
		# Filter for PE Handler
		{ 0x02 : [ 0x04, ['Content-Type: application/octet-stream', 'Content-Type: application/x-msdownload', 'Content-Type: application/exe', 'Content-Type: application/x-exe', 'Content-Type: application/dos-exe', 'Content-Type: vms/exe', 'Content-Type: application/x-winexe', 'Content-Type: application/msdos-windows', 'Content-Type: application/x-msdos-program'], 'PEHandler' ]}
	]


	def must_handle(self, request, response):
		for pattern_decision in self.Filters_Patterns:
			at_key   = pattern_decision.keys()[0]
			part_key = pattern_decision[at_key][self.POS_PART]
			expr_key = pattern_decision[at_key][self.POS_EXPR]
			if at_key not in self.LOOK_AT: continue 			# AT_REQUEST or AT_RESPONSE
			if part_key not in self.IDENTITY_PART: continue 	# HEADER_PART or URL_PART or BODY_PART
			try: 												# Valid Regular Expression
				for pat in expr_key:
					re.compile( pat )
			except re.error:
				continue

			if at_key == self.AT_REQUEST:
				target_object = request
			elif at_key == self.AT_RESPONSE:
				target_object = response
			else:
				continue

			if part_key == self.URL_PART:
				target_data = str(target_object.path)
			elif part_key == self.HEADER_PART:
				target_data = str(target_object.headers)
			elif part_key == self.BODY_PART:
				if at_key == self.AT_RESPONSE:
					target_data = str(target_object.data)
				else:
					target_data = str(target_object.payload)
			else:
				continue

			for pat in expr_key:
				if re.search(pat, target_data) != None:
					handler_name = pattern_decision[at_key][self.POS_HDNL]
					if handler_name == 'DOCXHandler':
						return DOCXHandler.DOCXHandler()
					elif handler_name == 'foobar':
						pass
		return None
