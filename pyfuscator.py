########################################################################################################################
# pyfuscator.py																										   #
# Version: 1.1																										   #
# Author: Sebastian Bitter <sebastian.bitter@gmx.net>																   #
# License: GPL V3																									   #
# 																													   #
# pyfucator is an obfuscator for python scripts. 																	   #
# It is capable of renaming function names, Encrypting the source with XOR, compressing the source with gzip,	       #
# encoding the source with base64 and finally compiling a python binary file (.pyc).  							       #
# All features except for base64 encoding are optional.																   #
# Depending on the chosen feauters pyfuscator may add some functions and imports to the outputfile. 				   #
########################################################################################################################

import sys
import getopt
import re
import base64
import random
import string
import py_compile
import importlib
import os.path
import StringIO
import gzip
from inspect import getmembers, isfunction
from itertools import izip, cycle


# Displays the banner
def showbanner():
	print "\t              __                     _             "
	print "\t             / _|                   | |            "
	print "\t _ __  _   _| |_ _   _ ___  ___ __ _| |_ ___  _ __ "
	print "\t| '_ \| | | |  _| | | / __|/ __/ _` | __/ _ \| '__|"
	print "\t| |_) | |_| | | | |_| \__ \ (_| (_| | || (_) | |   "
	print "\t| .__/ \__, |_|  \__,_|___/\___\__,_|\__\___/|_|   "
	print "\t| |     __/ |     Obfuscater for python scripts    "
	print "\t|_|    |___/      Version: 1.1                     "


# Displays help (-h)
def showhelp():
	print '\r\n\tPyfuscator obfuscates python scripts by renaming functions, XORing source code'
	print '\tand encoding it with base64. Additionally pyfuscator can create binary files.'
	print '\tThe output files are fully functional and can be used like any other python script.'
	print '\r\n\t-i, --inputfile\t\tInput file, needs to be in one directory with pyfuscator (required)'
	print '\t-o, --outputfile\tPath to output file (required)'
	print '\t-x\t\t\tXORs the source before encoding (optional)'
	print '\t\t\t\t  By default a random 64 byte key is used'
	print '\t-k, --key\t\tDefines a custom key. Can only be used with the -x switch (optional)'
	print '\t-c\t\t\tCompile to byte code (optional)'
	print '\t-f\t\t\tRename function names (optional)'
	print '\t-z\t\t\tCompress input with gzip (optional)'
	print '\t-v\t\t\tVerbose'
	print '\t-h\t\t\tShows this help screen\r\n'


# Function renames all function names with a random 64 byte name except the main function
def renamefunctionnames(scriptname, script):
	functionnames = []
	i = importlib.import_module(scriptname)
	functions_list = [o for o in getmembers(i) if isfunction(o[1])]
	for i in range(len(functions_list)):
		test = str(functions_list[i])
		test = str(re.findall(r'\'([^"]*)\'', test))
		if test[2:-2] != 'main':
			functionnames.append(test[2:-2])
	for i in range(len(functionnames)):
		rankey = randomkey(64)
		script = script.replace(functionnames[i], rankey)
		print '[OK] Functionname %s was replaced with %s' % (functionnames[i], rankey)

	print '[OK] All Functionnames and calls were replaced with 64 byte random names'

	# The file <inputfile.pyc> is generated automatically, following lines will remove it
	path = scriptname + '.pyc'
	if os.path.isfile(path):
		os.remove(path)
		print '[OK] Temporary file %s was removed' % path
	return script


# Returns a gzip compressed string
def gz(data):
	out = StringIO.StringIO()
	with gzip.GzipFile(fileobj=out, mode="w") as f:
		f.write(data)
		f.close()
	return out.getvalue()


# Returns a random key of userdefined length
def randomkey(length):
	return ''.join(random.choice(string.lowercase) for i in range(length))


# Returns with key XORed data
def xorcrypt(data, key, compress):
	xored = ''.join(chr(ord(x) ^ ord(y)) for (x, y) in izip(data, cycle(key)))
	if compress == 0:
		return "from itertools import izip,cycle;import base64\na=\"\"\""+base64.encodestring(xored).strip()+"\"\"\"\na=base64.decodestring(a)\nb=''.join(chr(ord(x)^ord(y))for(x,y)in izip(a,cycle('"+key+"')))\nexec(b)"
	else:
		randomname = randomkey(64)
		return "from itertools import izip,cycle;import base64,StringIO,gzip; \ndef " + randomname + "(data):\n\tinfile=StringIO.StringIO()\n\tinfile.write(data)\n\twith gzip.GzipFile(fileobj=infile, mode=\"r\") as f:\n\t\tf.rewind()\n\t\treturn f.read()\na=\"\"\""+base64.encodestring(xored).strip()+"\"\"\"\na=base64.decodestring(a)\nb=''.join(chr(ord(x)^ord(y))for(x,y)in izip(a,cycle('"+key+"')))\nexec("+randomname+"(b))"


# Returns base64 encoded data
def b64(data, compress):
	if compress == 0:
		return "import base64\na=\"\"\"" + base64.b64encode(data) + "\"\"\"\nexec(base64.b64decode(a))"
	else:
		randomname = randomkey(64)
		return "import base64,gzip,StringIO\ndef " + randomname + "(data):\n\tinfile=StringIO.StringIO()\n\tinfile.write(data)\n\twith gzip.GzipFile(fileobj=infile, mode=\"r\") as f:\n\t\tf.rewind()\n\t\treturn f.read()\na=\"\"\"" + base64.b64encode(data) + "\"\"\"\nexec("+randomname+"(base64.b64decode(a)))"


# Writes data to a file
def writeoutputfile(filename, data):
	f = open(filename, 'w')
	try:
		f.write(data)
		f.close()
		return True
	except:
		return False


# Reads a given file and returns it as string
def readfile(filename):
	f = open(filename, 'r')
	data = f.read()
	f.close()
	return data


# Depending on the parameters different obfuscation techniques are applied
def obfuscate(filename, data, crypt, key, renamefunctions, compress):
	# Renames functionnames
	if renamefunctions == 1:
		data = renamefunctionnames(filename, data)
	# Compresses the input script with gzip
	if compress == 1:
		data = gz(data)
		print '[OK] Source was gzip compressed'
	# Encrypts the input script with XOR
	if crypt == 1:
		# If no key was passed in a random key is generated
		if key == '':
			key = randomkey(64)
			data = xorcrypt(data, key, compress)
			print '[OK] Source was XOR encrypted with 64 bytes key'
	else:
		data = b64(data, compress)
		print '[OK] Source was base64 encoded'
	return data


def main(argv):
	inputfile = ''
	outputfile = ''
	key = ''
	verbose = 0
	encrypt = 0
	bytecode = 0
	renamefunctions = 0
	compress = 0
	try:
		opts, args = getopt.getopt(argv, "hvzfcxi:o:k:", ["inputfile=", "outputfile=", "key="])
	except getopt.GetoptError:
		showbanner()
		print '\r\nUsage: python %s -i <inputfile.py> -o <outputfile.py> [-v -x -k <key> -c -h -f -z]\r\n' % sys.argv[0]
		sys.exit()
	for opt, arg in opts:
		if opt == '-h':
			showbanner()
			showhelp()
			sys.exit()
		elif opt == '-v':
			verbose = 1
		elif opt == '-x':
			encrypt = 1
		elif opt == '-c':
			bytecode = 1
		elif opt == '-z':
			compress = 1
		elif opt == '-f':
			renamefunctions = 1
		elif opt in ("-k", "--key"):
			key = arg
		elif opt in ("-i", "--inputfile"):
			inputfile = arg
		elif opt in ("-o", "--outputfile"):
			outputfile = arg

	# Checks if input- and outputfile is defined
	if inputfile != '' and outputfile != '':
		print '\r\n'

		# Checks if the file if the input file is in the same directory with pyfuscator
		if inputfile.find('/') == -1 or inputfile.find('\\') == -1:

			# if encryption was not enabled but a key was defined a warning message is shown
			if encrypt == 0 and key != '':
				print '[WARNING] An encryption key was defined but encryption (-x) was not enabled'

			# Checks if the input file exists; Displays an error message if file not found
			if os.path.isfile(inputfile):
				inputdata = readfile(inputfile)
				print '[OK] Input from file %s was read' % inputfile

				# if verbosity was enabled the input is printed out
				if verbose == 1:
					print inputdata

				outputdata = obfuscate(inputfile[:-3], inputdata, encrypt, key, renamefunctions, compress)

				# if verbosity was enabled the output is printed out
				if verbose == 1:
					print outputdata

			else:
				print '[ERROR] Input file not found'
				sys.exit()

		# If file is not in one direcotry with pyfuscator an error message is displayed
		else:
			print '[ERROR] File needs to be in one directory with pyfuscator'
			sys.exit()
	
		# If writing to outputfile was successful a message is shown
		if writeoutputfile(outputfile, outputdata):
			print '[OK] Created file %s' % outputfile
	
		# If writing to outputfile was not successful an error message is shown
		else:
			print '[ERROR] Could not create file %s' % outputfile
			sys.exit()

		# Compilates a binary file
		if bytecode == 1:
			py_compile.compile(outputfile)
			print '[OK] Created file %sc' % outputfile

	# If no input- or outputfile is defined a usage hint is shown
	else:
		showbanner()
		print '\r\nUsage: python %s -i <inputfile.py> -o <outputfile.py> [-v -x -k <key> -c -h -f -z]\r\n' % sys.argv[0]
		sys.exit()
	print '\r\n'


if __name__ == "__main__":
	main(sys.argv[1:])
