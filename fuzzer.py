from pwn import *
import sys
import json
import xml.etree.ElementTree as ET
############################
##### HELPER FUNCTIONS #####
############################

##### FORMAT CHECK #####

def isJSON(inputStr):
	try:
		json_obj = json.loads(inputStr)
	except:
		return False

	return True

def isXML(inputStr):
    try:
    	ET.fromstring(inputStr)
    except:
    	return False

    return True

# Checks if input is CSV
# Idea:
# - count the number of commas for each line
# - every line should have the same number of commas
def isCSV(lines):
    # Check that there is more than one line
    # and at least 1 comma
    # I might be wrong on these, for now it passes the binaries given
    if len(lines) > 1 and lines[0].count(",") > 0:
        num_comma = lines[0].count(",")
        for l in lines:
            if l.count(",") != num_comma:
                return False
        return True
    return False

#count lines in input string
#count commas in first line
#if format is CSV, total comma count will be equal to lines * first line comma count
def isCSV2(inputStr):
	line_count = inputStr.count('\n')
	lines = inputStr.split("\n")
	first_line_comma_count = lines[0].count(',')
	total_comma_count = inputStr.count(',')

	if((line_count+1) * first_line_comma_count == total_comma_count and line_count > 1):
		return True
	else:
		return False

############################
##### FUZZER FUNCTIONS #####
############################

##### PLAINTEXT #####

# Fuzz a program that accepts plaintext
def fuzzPlaintext(inputStr):
    # Fuzz - empty input
    exitCode = runProcess("")
    if exitCode != 0:
        return ("", exitCode)    
    # Fuzz - null terminator
    testStr = plaintextNullMutate("")
    exitCode = runProcess(testStr)
    if exitCode != 0:
        return (testStr, exitCode)
    # Fuzz - newline
    testStr = plaintextNewlineMutate("")
    exitCode = runProcess(testStr)
    if exitCode != 0:
        return (testStr, exitCode)
    # Fuzz - format string
    testStr = plaintextFormatMutate("")
    exitCode = runProcess(testStr)
    # Fuzz - all characters
    testStr = plaintextCharMutate("")
    exitCode = runProcess(testStr)
    if exitCode != 0:
        return (testStr, exitCode)
    # Fuzz - overflow
    testStr = ""
    while (True):
        testStr = plaintextPadding(testStr, 10)
        exitCode = runProcess(testStr)
        if exitCode != 0:
            return (testStr, exitCode)
        if len(testStr) > 1000:
            break

    # No vulnerability found
    return ("", 0)

# Mutate with character padding
def plaintextPadding(testStr, count):
    return testStr + "a"*count

# Mutate with null character
def plaintextNullMutate(testStr):
    return testStr + "\0"

# Mutate with newline character
def plaintextNewlineMutate(testStr):
    return testStr + "\n"

# Mutate with format string
def plaintextFormatMutate(testStr):
    return testStr + "%x"

# Mutate with all characters
def plaintextCharMutate(testStr):
    count = 0
    while count <= 127:
        testStr = testStr + chr(count)
        count += 1
    return testStr

# Runs a process, returns exit code
def runProcess(testStr):
    p = process("./"+sys.argv[1])
    while p.poll(block = False) == None:
        print("@@@ Sending: " + testStr)
        p.sendline(testStr)
        sleep(0.3)
    return p.poll(block = False)


######################
##### MAIN LOGIC #####
######################

# Usage: ./fuzzer program sampleinput.txt
if len(sys.argv) != 3:
    print("@@@ Usage: ./fuzzer program sampleinput.txt")
    sys.exit()

# Read sampleinput.txt
try:
    inputFile = open(sys.argv[2], 'r')
    inputStr = inputFile.read().strip()
    #TODO: lines almost always returns an empty list, will be using inputStr as the input for the isJSON, isXML, isCSV funcitons
    lines = inputFile.readlines()
except OSError:
    print('@@@ Could not open ' + sys.argv[2])
    print("@@@ Usage: ./fuzzer program sampleinput.txt")
    sys.exit()
# Determine format in sampleinput.txt
inputFormat = "plaintext"
if isJSON(inputStr):
    print("@@@ Format found: JSON")
    inputFormat = "json"
elif isXML(inputStr):
    print("@@@ Format found: XML")
    inputFormat = "xml"
elif isCSV(lines):
	print("@@@ Format found: CSV")
	inputFormat = "csv"
#TODO: choose between CSV checkers
elif isCSV2(inputStr):
	print("@@@ Format found: CSV")
	inputFormat = "csv"
else:
    print("@@@ Format found: plaintext")

# Run the binary in a process and feed input
# Keep repeating until segfault, mutating input each time
if inputFormat == "json":
    pass
elif inputFormat == "xml":
    pass
elif inputFormat == "csv":
    pass
else:
    (i, e) = fuzzPlaintext(inputStr)

print("\n@@@ RESULT")
if e == 0:
    print("@@@ No vulnerabilities found...yet")
elif e == -11:
    print("@@@ Faulting input: "+i+"\n@@@ Exit code: "+str(e)+"\n@@@ Found a segfault")

        
### 1. Read input.txt ###

# Use regex to find out what kind of input (easier to mutate)
# Might run the program a few times to confirm format

# - json
#   - curly braces at start and end, add more to refine regex if more complicated

# - xml
#   - xml prologue <?xml version="1.0" encoding="UTF-8"?>) is optional,
#   - if not there, might have to search for tags, might have code out there for that

# - csv
#   - basically commas everywhere, might be confused with text
#   - so we can try giving invalid csv input and see how it reacts

# - Plaintext (multiline)
#   - this is the "else", if the input doesn't fit the rest

### 2. Do a bunch of basic mutation ###

# - bit flips
# - empty input
# - overflow
# - a mixture of the above

### 3. Do format-specific manipulation/generation of input ###

# - change fields of input, possibly aided
