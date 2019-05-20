hexStringInput = str(input())
hexStringComma = ','.join(hexStringInput[i:i+2] for i in range(0, len(hexStringInput),2))
with open("helpme.txt", 'w') as file:
	file.write(hexStringComma)
file.close()
print(hexStringComma)