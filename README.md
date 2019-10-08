# winregPEDetector

<b><i>Use of any code in this repo in any form for academic purposes is considered cheating, which is not only unfair to your classmates, but as well as yourself. Use at your own risk.</i></b>

Detects PE Files in the Window's Registry.

Based on extracting the binary data from the values under the various keys/subkeys, this fully python (standard library only) script walks through the Window's Registry and analyzes the binary data to determine whether the binary data represents a PE format file. The script then outputs the entire keypath, the value's name, and the value's data as it's final output, along with the value's data type (reg_binary, etc.)

This script also details some of the missing documentation in the python docs specifically under what type is what value (e.g. value type 0 = reg_none, 1 = reg_sz, etc.). It is missing some of the values under the value data types as all testing was performed in a fresh Windows 7 VM. Further improvements could include the possibility of removal of the malicious value, further analysis of the binary data as to what its function pertains to, the detection of other such malicious values, as well as multithreading this project, etc. 

Why is detection important? Poweliks could utilize these PE files to covertly create an instance of the PE file hidden, run, and then remove itself, as well as many other corner cases and scenarios. It is an instance of trojan that is not detectable by file signatures, as the Window's registry is not considered a traditional file in the file structure system.
