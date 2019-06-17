import winreg
import sys
import binascii
import textwrap

hives = [winreg.HKEY_CLASSES_ROOT, winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_USERS, winreg.HKEY_CURRENT_CONFIG]

#demonstration purposes
#hives = [winreg.HKEY_CLASSES_ROOT,winreg.HKEY_CURRENT_CONFIG]

def subkeys(key):
	# returns the subkeys held within the given key
    i = 0
    while True:
        try:
            subkey = winreg.EnumKey(key, i)
            yield subkey
            i+=1
        except WindowsError as e:
            break

def values(key):
	valdata = []
	suspiciousVals = {}
	count = 0
	
	#loops through all the values held within the given key and checks to see if it contains the MZ/PE signature
	while True:
		try:
			#returns a tuple with the name of the value, data for the value, and type of value it is
			name, data, type = winreg.EnumValue(key, count)
			if type in registryValTypesToAnalyze:
				suspicious = 0
				if analyzeValues(data) == 1:
					suspicious = 1
					suspiciousVals[name] = "Type: {}".format(type)
					valdata.append(data)
					print("\n{}\n{}".format(name, data))
					
					# just for demo purposes
					while 1:						
						contQ = input("Continue? Y/N\n")
						if contQ.upper() == "N":
							sys.exit(0)
						elif contQ.upper() == "Y":
							break
						else:
							continue
			count += 1
		except WindowsError:
			break
	return suspiciousVals, valdata

def analyzeValues(data):
	if data == None:
		return 0
		
	#checks the byte offset for the PE header based upon e_lfanew from DOS Header
	#e_lfanew is always at offset 0x3c or the 60th byte from offset 0
	registryVal = bytes.hex(data).upper()
	metadata = textwrap.wrap(registryVal,2)
	
	#The PE header pointer is in little endian and so should be converted to big endian to point to the right location within the list
	#put it in a try catch in case the binary data isn't long enough to be considered anything or if it's some other file type that has a dos mz header, etc... who knows?
	try:
		peHeaderHexByteOffset = "".join((metadata[60:64])[::-1])
		peHeaderDecimalByteOffset = int(peHeaderHexByteOffset, 16)
		supposedPEHeader = "".join(metadata[peHeaderDecimalByteOffset:peHeaderDecimalByteOffset+4])
		
		#checks the 3 conditions to assume PE file: 
		#1. Hex value for MZ is in the first word (first 2 bytes)
		#2. From above, checks the e_lfanew long value (4 bytes at the 60th byte offset) to see the location of where the PE signature is supposed to begin (it's a pointer to the location of PE)
		#3. Checks to see if the supposed offset at which PE header begins, contains the PE signature PE 0 0 aka 50 45 00 00
		if "4D5A" in registryVal[:4] and supposedPEHeader == "50450000" in registryVal:
			return 1
	except:
		pass
	return 0

def treeWalk(currentHive, hiveKey, keypath):
	#Similar to OS Walk, this function walks the entire tree recursively checking each key for subkeys and following those levels
	try:
		key = winreg.OpenKey(hiveKey, keypath)
		fullHivePath = "{}\{}".format(currentHive, keypath)
		print(fullHivePath)
		
		#appends the data received from the values function which checks to see if the binary data with in the registry values contain an MZ/PE signature
		suspiciousVals, valdata = values(key)
		if len(valdata) > 0:
			fullPathAndData[fullHivePath] = valdata
		if bool(suspiciousVals) == 1:
			suspiciousPathAndVals[fullHivePath] = suspiciousVals

		for subkeyname in subkeys(key):
			subkeypath = "%s\\%s" % (keypath, subkeyname)
			treeWalk(currentHive, hiveKey, subkeypath)
	except WindowsError:
		pass

# Types Figured Out By Trial And Error
# 0 = REG_NONE: 			Binary Values
# 1 = REG_SZ: 				String Values
# 2 = REG_EXPAND_SZ: 			String Values
# 3 = REG_BINARY: 			Binary Values
# 4 = REG_DWORD: 			32 bit integer
# 7 = REG_MULTI_SZ: 			String Values
# 8 = REG_RESOURCE_LIST: 		Binary Values
# 9 = REG_FULL_RESOURCE_DESCRIPTOR: 	Binary Values
# 11 = REG_QWORD: 			64 bit integer
# 5,6,10,12+ - either the registry types doesn't exist for this OS, or isn't in the registry as a value type

registryValTypesToAnalyze = [0,3,8,9]

# Structure of suspiciousPathAndVals:
# {Hive\Key\Path\...: {Value Name: [Suspicious Value, Value Type]}}
# Suspicious Value: 1 = True, 0 = False
# However, for the purposes of this particular project, we are only interested in suspicious values of 1, but the code can be altered to collect both value types in the values function

fullPathAndData = {}
suspiciousPathAndVals = {}

currentHive = None
for i in range(len(hives)):
	if hives[i] == winreg.HKEY_CLASSES_ROOT:
		currentHive = "HKCR"
	elif hives[i] == winreg.HKEY_CURRENT_USER:
		currentHive = "HKCU"
	elif hives[i] == winreg.HKEY_LOCAL_MACHINE:
		currentHive = "HKLM"
	elif hives[i] == winreg.HKEY_USERS:
		currentHive = "HKU"
	elif hives[i] == winreg.HKEY_CURRENT_CONFIG:
		currentHive = "HKCC"
		
	#Starts recursion at initial subkeys
	initialSubKeys = subkeys(winreg.OpenKey(hives[i], "")) #replace hivekey here
	for j in initialSubKeys:
		treeWalk(currentHive, hives[i], j) #replace hivekey here

print("\n")
for key,value in suspiciousPathAndVals.items():
	print(key, "=>", value)
	print(fullPathAndData[key])
	print()


