import sys
import getopt
import re
import base64
import random
import string
import py_compile
import importlib
import os.path
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
	print "\t|_|    |___/      Version: 1.0                     "


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


# Returns a random key of userdefined length
def randomkey(length):
	return ''.join(random.choice(string.lowercase) for i in range(length))


# Returns with key XORed data
def xorcrypt(data, key):
	xored = ''.join(chr(ord(x) ^ ord(y)) for (x, y) in izip(data, cycle(key)))
	return "from itertools import izip,cycle;import base64;a=\"\"\""+base64.encodestring(xored).strip()+"\"\"\";a=base64.decodestring(a);b=''.join(chr(ord(x)^ord(y))for(x,y)in izip(a,cycle('"+key+"')));exec(b);"


# Returns base64 encoded data
def b64(data):
	return "a=\"\"\"" + base64.b64encode(data) + "\"\"\";import base64;exec(base64.b64decode(a));"


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


def obfuscate(filename, data, crypt, key, renamefunctions):
	if renamefunctions == 1:
		data = renamefunctionnames(filename, data)
	if crypt == 1:
		if key == '':
			key = randomkey(64)
			data = xorcrypt(data, key)
			print '[OK] Source was XOR encrypted with 64 bytes key'
	else:
		data = b64(data)
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
	try:
		opts, args = getopt.getopt(argv, "hvfcxi:o:k:", ["inputfile=", "outputfile=", "key="])
	except getopt.GetoptError:
		showbanner()
		print '\r\nUsage: python %s -i <inputfile.py> -o <outputfile.py> [-v -x -k <key> -c -h -f]\r\n' % sys.argv[0]
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

				outputdata = obfuscate(inputfile[:-3], inputdata, encrypt, key, renamefunctions)

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
		print '\r\nUsage: python %s -i <inputfile.py> -o <outputfile.py> [-v -x -k <key> -c -h -f]\r\n' % sys.argv[0]
		sys.exit()

	print '\r\n'


if __name__ == "__main__":
	main(sys.argv[1:])
