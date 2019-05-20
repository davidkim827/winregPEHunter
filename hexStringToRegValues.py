#This script takes the complete hex value input from Winhex or some hex dump to convert it into something that will be input into a registry file

hexStringInput = str(input())
hexStringComma = ','.join(hexStringInput[i:i+2] for i in range(0, len(hexStringInput),2))
with open("helpme.txt", 'w') as file:
	file.write(hexStringComma)
file.close()
print(hexStringComma)