from pwn import *
import sys
import json
import xml.etree.ElementTree as ET
import threading
import enum
import re
import random
import copy


############################
##### HELPER FUNCTIONS #####
############################

##### FORMAT CHECK #####    
class ThreadManager:
    __instance = None
    @staticmethod 
    def getInstance():
        if ThreadManager.__instance == None:
            ThreadManager()
        return ThreadManager.__instance
    def __init__(self, count):
        if ThreadManager.__instance != None:
            raise Exception("This class is a singleton!")
        else:
            ThreadManager.__instance = self
            self.count = count
            self.stopFlag = False
    def startThreads(self, fuzzer):
        self.stopFlag = False
        for i in range(0,self.count):
            thread = threading.Thread(target = fuzzer.fuzz, args=(fuzzer.inputStr,lambda : self.stopFlag))
            thread.start()
            print(f"Starting thread {thread.ident}")

    def stopThreads(self):
        self.stopFlag = True
        
    def threadResult(self,result):
        # if self.stopFlag:
        #     thread = threading.current_thread()
        #     print(f"Stopping thread {thread.ident}")
        #     thread.join()
        (i, e) = result
        # print(i)
        print("\n@@@ RESULT")
        if e == 0:
            print("@@@ No vulnerabilities found...yet")
        elif e == -11:
            print("@@@ Faulting input: "+i+"\n@@@ Exit code: "+str(e)+"\n@@@ Found a segfault")
            self.stopThreads()

threadManager = ThreadManager(10)

class Fuzzer:
    def __init__(self, inputStr):
        self.inputStr = inputStr
    def isType(self):
        return True
    def fuzz(self,mutated,stop):
        return (0, "")
class JSONRules(enum.Enum):
   OVERFLOW = "A" * 1000
   BOUNDARY_MINUS = -1
   BOUNDARY_PLUS = 1
   BOUNDARY_ZERO = 0
   LARGE_POS_NUM = 999999999999999999999999999999999999999999999999999999
   LARGE_NEG_NUM = -999999999999999999999999999999999999999999999999999999
   FORMAT = "%p"
class JSONFuzzer(Fuzzer):
    def __init__(self, inputStr):
        super().__init__(inputStr)
        self.formatLimit = 1000
        self.rules = []
        for rule in JSONRules :
            self.rules.append(rule.value)
        self.perms = set()
        self.perms.add(inputStr)
        try:
            self.jsonObj = json.loads(self.inputStr)
        except:
            self.jsonObj = {}

    def isType(self):
        try:
            json.loads(self.inputStr)
        except:
            return False

        return True

    def fuzz(self, mutated, stop):
        if stop():
            ThreadManager.getInstance().threadResult((mutated,0))
            return
        # Acquire lock
        if mutated not in self.perms :
            self.perms.add(mutated)
            # Remove lock
            exitCode = runProcess(mutated)
            ThreadManager.getInstance().threadResult((mutated,exitCode))
            if exitCode != 0:
                return
            self.fuzz(self.mutate(),stop)

        else:
            self.fuzz(self.mutate(),stop)
        ThreadManager.getInstance().threadResult((mutated,0))
    
    def checkFormatStrNum(self,inputStr):
        res = re.search(r"\%(.*?)\$", inputStr).group()
        return res[1:len(res)-1]
    
    def getFormatStr(self, num):
        return f"AAAAAAAAAA%{num}$n"

    def mutate(self):
        temp = copy.deepcopy(self.jsonObj)
        for key in self.jsonObj:
            mutation = self.rules[random.randint(0,len(self.rules)-1)]
            if mutation == JSONRules.FORMAT.value:
                formatStr = self.getFormatStr(random.randint(1,self.formatLimit))
                temp[key] = formatStr
            else:
                temp[key] = mutation
        return json.dumps(temp)
        
class XMLFuzzer(Fuzzer):
    def __init__(self, inputStr):
        super().__init__(inputStr)
    def isType(self):
        try:
            ET.fromstring(self.inputStr)
        except:
            return False

        return True
     
class CSVFuzzer(Fuzzer):
    def __init__(self, inputStr):
        super().__init__(inputStr)
    
    # # Checks if input is CSV
    # # Idea:
    # # - count the number of commas for each line
    # # - every line should have the same number of commas
    # def isCSV(lines):
    #     # Check that there is more than one line
    #     # and at least 1 comma
    #     # I might be wrong on these, for now it passes the binaries given
    #     if len(lines) > 1 and lines[0].count(",") > 0:
    #         num_comma = lines[0].count(",")
    #         for l in lines:
    #             if l.count(",") != num_comma:
    #                 return False
    #         return True
    #     return False

    #count lines in input string
    #count commas in first line
    #if format is CSV, total comma count will be equal to lines * first line comma count
    def isType(self):
        line_count = self.inputStr.count('\n')
        lines = self.inputStr.split("\n")
        first_line_comma_count = lines[0].count(',')
        total_comma_count = self.inputStr.count(',')

        if((line_count+1) * first_line_comma_count == total_comma_count and line_count > 1):
            return True
        else:
            return False

class PlaintextFuzzer(Fuzzer):
    def __init__(self, inputStr):
        super().__init__(inputStr)
    
    # Mutate with character padding
    def plaintextPadding(self, testStr, count):
        return testStr + "a"*count

    # Mutate with null character
    def plaintextNullMutate(self, testStr):
        return testStr + "\0"

    # Mutate with newline character
    def plaintextNewlineMutate(self, testStr):
        return testStr + "\n"

    # Mutate with format string
    def plaintextFormatMutate(self, testStr):
        return testStr + "%x"

    # Mutate with all characters
    def plaintextCharMutate(self, testStr):
        count = 0
        while count <= 127:
            testStr = testStr + chr(count)
            count += 1
        return testStr
    def fuzz(self, mutated, stop):
        # Fuzz a program that accepts plaintext
        # Fuzz - empty input
        if stop():
            ThreadManager.getInstance().threadResult((mutated,0))
            return
        exitCode = runProcess("")
        ThreadManager.getInstance().threadResult(("",exitCode))
        if exitCode != 0:
            return
        # Fuzz - null terminator
        testStr = self.plaintextNullMutate("")
        exitCode = runProcess(testStr)
        ThreadManager.getInstance().threadResult((testStr,exitCode))
        if exitCode != 0:
            return
        # Fuzz - newline
        testStr = self.plaintextNewlineMutate("")
        exitCode = runProcess(testStr)
        ThreadManager.getInstance().threadResult((testStr,exitCode))
        if exitCode != 0:
            return
        # Fuzz - format string
        testStr = self.plaintextFormatMutate("")
        exitCode = runProcess(testStr)
        # Fuzz - all characters
        testStr = self.plaintextCharMutate("")
        exitCode = runProcess(testStr)
        ThreadManager.getInstance().threadResult((testStr,exitCode))
        if exitCode != 0:
            return
        # Fuzz - overflow
        testStr = ""
        while (True):
            testStr = self.plaintextPadding(testStr, 10)
            exitCode = runProcess(testStr)
            ThreadManager.getInstance().threadResult((testStr,exitCode))
            if exitCode != 0:
                return
            if len(testStr) > 1000:
                break

        # No vulnerability found
        return ThreadManager.getInstance().threadResult(("",0))


# Runs a process, returns exit code
def runProcess(testStr):
    p = process("./"+sys.argv[1])
    # print("@@@ Sending: " + testStr)
    p.sendline(testStr)
    p.shutdown()
    return p.poll(block = True)


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

fuzzer = None
if JSONFuzzer(inputStr).isType() :
    fuzzer = JSONFuzzer(inputStr)
elif XMLFuzzer(inputStr).isType() :
    fuzzer = XMLFuzzer(inputStr)
elif CSVFuzzer(inputStr).isType() :
    fuzzer = CSVFuzzer(inputStr)
else:
    fuzzer = PlaintextFuzzer(inputStr)
ThreadManager.getInstance().startThreads(fuzzer)

        
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
