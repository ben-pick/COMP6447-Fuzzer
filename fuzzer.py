#!/usr/bin/python3
from pwn import *
import sys
import json
import csv
import xml.etree.ElementTree as ET
import threading
import enum
import re
import random
import copy


############################
##### HELPER FUNCTIONS #####
############################

# All threads are managed here. Singleton instantiation, one instance only (thread safe). 
class ThreadManager:
    __instance = None
    # Gets the only instance of the ThreadManager.
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
            self.stopSem = threading.Semaphore(1)
            self.addSem = threading.Semaphore(1)
    # Starts n number of threads (which is specified on instantiation), with the fuzzer you want to fuzz with
    def startThreads(self, fuzzer):
        self.stopFlag = False
        for i in range(0,self.count):
            thread = threading.Thread(target = fuzzer.fuzz, args=(fuzzer.inputStr,lambda : self.stopFlag))
            thread.start()
            print(f"Starting thread {thread.ident}")

    # Whenever a process exits with an exit code, send it to this function. Will stop all threads if we find a vuln.
    # e.g. ThreadManager.getInstance().threadResult(exitCode, inputStr)
    def threadResult(self,result):
        (i, e) = result
        self.stopSem.acquire()
        if not self.stopFlag:
            if e == 0:
                print("\n@@@ RESULT")
                print("@@@ No vulnerabilities found...yet")
            elif e == -11:
                # Save output here
                print("\n@@@ RESULT")
                print("@@@ Faulting input: "+i+"\n@@@ Exit code: "+str(e)+"\n@@@ Found a segfault")
                f = open("bad.txt","w+")
                f.write(i)
                f.close()
                self.stopFlag = True
                self.stopSem.release()
        self.stopSem.release()

threadManager = ThreadManager(len(os.sched_getaffinity(0)))
print(len(os.sched_getaffinity(0)))

# All specific fuzzers inherit from this
class Fuzzer:
    def __init__(self, inputStr):
        self.inputStr = inputStr
    # Returns if the inputStr can be parsed as its type
    def isType(self):
        return True
    # Where are the processing occurs, should only return when we get a seg fault, otherwise keep running indefinitely
    # Mutated parameter is for recursion if you wish to mutate by recursion
    # Stop is a lambda function that changes when ThreadManager.stopFlag changes, i.e. when we want all other threads to stop
    # Check for stop at the start of your fuzz function, and return if you do
    # Report to threadManager by ThreadManager.getInstance().threadResult whenever runProcess finishes
    def fuzz(self,mutated,stop):
        return (0, "")
# Arbitrary enum, you dont have to use in other fuzzer classes
# All the different permutations for the JSON fuzzer
class JSONRules(enum.Enum):
   OVERFLOW = "A" * 100000
   BOUNDARY_MINUS = -1
   BOUNDARY_PLUS = 1
   BOUNDARY_ZERO = 0
   LARGE_POS_NUM = 999999999999999999999999999999999999999999999999999999
   LARGE_NEG_NUM = -999999999999999999999999999999999999999999999999999999
   ONE_BYTE = 128
   TWO_BYTE = 32768
   FOUR_BYTE = 2147483648
   EIGHT_BYTE = 9223372036854775808  
   FORMAT = "%p"
class JSONFuzzer(Fuzzer):
    def __init__(self, inputStr):
        super().__init__(inputStr)
        # Limit on how many format strings we should check based i.e. go up to %1000$n
        # Hopefully will overwrite some value and make it invalid
        self.formatLimit = 1000
        self.rules = []
        self.infiniteMutation = False
        self.bigMutation = False
        for rule in JSONRules :
            self.rules.append(rule.value)
        self.bytesToAdd = ["\0", "%s", "A", "\n"]
        self.badBytes = self.getBadBytes()
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
        m = self.inputStr
        while True:
            if stop():
                ThreadManager.getInstance().threadResult((mutated,0))
                return
            exitCode = runProcess(m)
            ThreadManager.getInstance().threadResult((m,exitCode))
            if exitCode != 0:
                return
            if self.infiniteMutation:
                m = self.mutateInfinitely()
            else:
                m = self.mutate()
    
    def checkFormatStrNum(self,inputStr):
        res = re.search(r"\%(.*?)\$", inputStr).group()
        return res[1:len(res)-1]
    
    def getFormatStr(self, num):
        return "%s" * num

    def getBadBytes(self):
        l = []
        count = 0
        while count <= 127:
            if count < 48 or count > 122:
                l.append(chr(count))
            count += 1
        l = l + ["a", "\0", "\n", "%s"]
        return l
    def mutateInfinitely(self):
        # We don't need semaphore, we arent holding any state
        temp = copy.deepcopy(self.jsonObj)
        randomKey = random.choice([i for i in temp])
        if isinstance(temp[randomKey], int):
            temp[randomKey] = random.randint(-2147483648, 2147483648)
        if isinstance(temp[randomKey], str):
            temp[randomKey] = self.strMutate(temp[randomKey])
        if isinstance(temp[randomKey],list):
            randomIndex = random.randint(0,len(temp[randomKey])-1)
            randomElem = temp[randomKey][randomIndex]
            if isinstance(randomElem,str):
                temp[randomKey][randomIndex] = self.strMutate(randomElem)
            elif isinstance(randomElem, int):
                temp[randomKey][ranomIndex] = random.randint(-2147483648, 2147483648)
        return json.dumps(temp)

    def strMutate(self,string):
        strList = list(string)
        mutationSize = random.randint(1,len(string)+5)
        mutationSpots = []
        while len(mutationSpots) < mutationSize:
            randomSpot = random.randint(0,len(string)+5)
            if randomSpot not in mutationSpots:
                mutationSpots.append(randomSpot)
        for i in mutationSpots:
            if i >= len(strList):
                strList.append(self.badBytes[random.randint(0,len(self.badBytes)-1)])
            else:
                strList[i] = self.badBytes[random.randint(0,len(self.badBytes)-1)]
        return "".join(strList)

    def mutate(self):
        if len(self.rules) != 0 :
            # Do all of the boundary checks here to pick up errors quick
            ThreadManager.getInstance().addSem.acquire()
            temp = copy.deepcopy(self.jsonObj)
            mutation = self.rules[0]
            for key in temp:
                temp[key] = mutation
            self.rules.remove(mutation)
            ThreadManager.getInstance().addSem.release()
            return json.dumps(temp)
        else :
            # Mutate - only does ints and strings right now
            # For strings, just add bad bytes to string
            # For ints, multiply by -2
            # When all entries reach a large length, add a 1000 more
            byte = self.bytesToAdd[random.randint(0,len(self.bytesToAdd)-1)]
            ThreadManager.getInstance().addSem.acquire()
            continueFlag = True
            for key in self.jsonObj:
                if isinstance(self.jsonObj[key], str):
                    if len(self.jsonObj[key]) < 200:
                        if continueFlag:
                            continueFlag = False
                    self.jsonObj[key] = self.jsonObj[key] + byte
                if isinstance(self.jsonObj[key], int):
                    if self.jsonObj[key] == 0:
                        self.jsonObj[key] = 1
                    if len(str(self.jsonObj[key])) < 20:
                        if continueFlag:
                            continueFlag = False
                    self.jsonObj[key] = self.jsonObj[key]*-2
                if isinstance(self.jsonObj[key], list):
                    for i in range(0,len(self.jsonObj[key])):
                        if isinstance(self.jsonObj[key][i],str):
                            if len(self.jsonObj[key][i]) < 200:
                                if continueFlag:
                                    continueFlag = False
                                self.jsonObj[key][i] = self.jsonObj[key][i] + byte
                        if isinstance(self.jsonObj[key][i],int):
                            if self.jsonObj[key][i] == 0:
                                self.jsonObj[key][i] = 1
                            if len(str(self.jsonObj[key][i])) < 20:
                                if continueFlag:
                                    continueFlag = False
                                self.jsonObj[key][i] = self.jsonObj[key][i]*-2

                    if len(self.jsonObj[key])<1000:
                        toAdd = 100 - len(self.jsonObj[key])
                        for i in range(0, toAdd//2):
                            self.jsonObj[key].append("A")
                        for i in range(toAdd//2, 1000):
                            self.jsonObj[key].append(random.randint(-10,10))

            if continueFlag and not self.bigMutation:
                self.bigMutation = True
                for i in range(0, 50):
                    self.jsonObj[f"add{i}"] = "A"
                for i in range(50, 100):
                    self.jsonObj[f"add{i}"] = random.randint(-10,10)
            elif continueFlag and self.bigMutation:
                self.infiniteMutation = True
                self.jsonObj = json.loads(self.inputStr)
            ThreadManager.getInstance().addSem.release()
            return json.dumps(self.jsonObj)

        
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
        self.lines = self.inputStr.split("\n")
        self.commasPerLine = self.lines[0].count(",")
        self.valuesPerLine = self.commasPerLine + 1
        self.rules = ["overflow_lines", "overflow_values", "minus", "plus", "zero", 
                        "large_minus", "large_plus", "null_term", "format_string", "new_line", "ascii"]
    
    def isType(self):
        line_count = self.inputStr.count('\n')
        lines = self.inputStr.split("\n")
        first_line_comma_count = lines[0].count(',')
        total_comma_count = self.inputStr.count(',')

        if((line_count+1) * first_line_comma_count == total_comma_count and line_count > 1):
            return True
        else:
            return False
    
    # Padding of desired length
    def csvPadding(self, inputStr, count):
        return inputStr + "A" * count

    # forms a basic line with single A's
    def craftLine(self):
        CSVline = '\n'
        for i in range(0, self.commasPerLine):
            CSVline += 'A,'
        CSVline += 'A'
        return CSVline

    def appendOverflow(self, inputStr):
        for i in range(1000):
            inputStr = inputStr + self.craftLine()
        return inputStr

    # forms a valid line of 100 A's in each valu
    def craftLongLine(self):
        CSVline = '\n'
        for i in range(0, self.commasPerLine):
            CSVline += 'A'*100 + ','
        CSVline += 'A'*100
        return CSVline
    
    def appendLongOverflow(self, inputStr):
        inputStr = inputStr + self.craftLongLine()
        return inputStr

    def appendNegative(self, inputStr):
        newLine = '\n'
        for i in range(0, self.commasPerLine):
            newLine += '-1' + ','
        newLine += '-1'
        inputStr = inputStr + newLine
        return inputStr
        
    def appendPositive(self, inputStr):
        newLine = '\n'
        for i in range(0, self.commasPerLine):
            newLine += '1' + ','
        newLine += '1'
        inputStr = inputStr + newLine
        return inputStr

    # append a line of 0's
    def appendZero(self, inputStr):
        newLine = '\n'
        for i in range(0, self.commasPerLine):
            newLine += '0,'
        newLine += '0'
        inputStr = inputStr + newLine
        return inputStr   

    # Append a line with large positive values
    def largePositive(self, inputStr):
        newLine = '\n'
        for i in range(0, self.commasPerLine):
            newLine += '999999999999999999999999999999999999999999999999999999' + ','
        newLine += '999999999999999999999999999999999999999999999999999999'
        inputStr = inputStr + newLine
        return inputStr

    # Append a line with large negative values
    def largeNegative(self, inputStr):
        newLine = '\n'
        for i in range(0, self.commasPerLine):
            newLine += '-999999999999999999999999999999999999999999999999999999' + ','
        newLine += '-999999999999999999999999999999999999999999999999999999'
        inputStr = inputStr + newLine
        return inputStr
    
    def nullTerminator(self, inputStr):
        return inputStr+'\0'

    def appendFormatString(self, inputStr):
        return inputStr+'%s'

    def appendNewLine(self, inputStr):
        return inputStr+'\n'

    # Returns a line of ch
    def mutateLine(self, inputStr, ch):
        changedLine = ''
        for i in range(0, self.commasPerLine):
            changedLine += str(ch) + ','
        changedLine += str(ch)
        return changedLine
    
    # will append a valid csv line of ascii val e.g. if val=50 -> line = 2,2,2
    def appendAsciiLine(self, inputStr, val):
        newLine = '\n'
        for i in range(0, self.commasPerLine):
            newLine += chr(val) + ','
        newLine += chr(val)
        inputStr = inputStr + newLine
        return inputStr

    def appendAscii(self, inputStr, val):
        return inputStr + "\n" + chr(val)
        #return chr(val)
    
    def fuzz(self, mutated, stop):
        # Fuzz a program with csv file format
        if stop():
            ThreadManager.getInstance().threadResult((mutated,0))
            return
        exitCode = runProcess("")
        ThreadManager.getInstance().threadResult(("",exitCode))
        if exitCode != 0:
            return
        
        # Fuzzing for initial appending cases first
        payload = self.inputStr
        cases = copy.deepcopy(self.rules)
        while(cases != []):
            case = cases.pop(0)
            if(case == "overflow_lines"):
                payload = self.appendOverflow(payload)
            elif(case == "overflow_values"):
                payload = self.appendLongOverflow(payload)
            elif(case == "minus"):
                payload = self.appendNegative(payload)
            elif(case == "plus"):
                payload = self.appendPositive(payload)
            elif(case == "zero"):
                payload = self.appendZero(payload)
            elif(case == "large_minus"):
                payload = self.largeNegative(payload)
            elif(case == "large_plus"):
                payload = self.largePositive(payload)
            elif(case == "null_term"):
                payload = self.nullTerminator(payload)
            elif(case == "format_string"):
                payload = self.appendFormatString(payload)
            elif(case == "new_line"):
                payload = self.appendNewLine(payload)
            elif(case == "ascii"):
                for i in range(0, 127):
                    payload = self.inputStr
                    payload = self.appendAsciiLine(payload, i)
                    exitCode = runProcess(payload)
                    ThreadManager.getInstance().threadResult((payload,exitCode))
                    if exitCode != 0:
                        return
                    payload = self.inputStr
                    payload = self.appendAscii(payload, i)
                    exitCode = runProcess(payload)
                    ThreadManager.getInstance().threadResult((payload,exitCode))
                    if exitCode != 0:
                        return
                pass
            else:
                pass
            exitCode = runProcess(payload)
            ThreadManager.getInstance().threadResult((payload,exitCode))
            if exitCode != 0:
                return

        
        linesCopy = self.lines
        cases2 = copy.deepcopy(self.rules)
        self.lineByLineFuzz(mutated, stop, 0, linesCopy, cases2)
        self.replacementFuzz(mutated, stop)  

        return ThreadManager.getInstance().threadResult(("",0))

    def lineByLineFuzz(self, mutated, stop, currLine, payload, cases):
        if(currLine == len(self.lines)):
            return
        
        if stop():
            ThreadManager.getInstance().threadResult((mutated,0))
            return

        payload[currLine] = self.lines[currLine]
        cases = copy.deepcopy(self.rules)
        while(cases != []):
            case = cases.pop(0)
            if(case == "overflow_lines"):
                continue
            elif(case == "overflow_values"):
                payload[currLine] = self.mutateLine(payload[currLine], "A"*100)
            elif(case == "minus"):
                payload[currLine] = self.mutateLine(payload[currLine], -1)
            elif(case == "plus"):
                payload[currLine] = self.mutateLine(payload[currLine], 1)
            elif(case == "zero"):
                payload[currLine] = self.mutateLine(payload[currLine], 0)
            elif(case == "large_minus"):
                payload[currLine] = self.mutateLine(payload[currLine], -999999999999999999999999999999999999999999999999999999)
            elif(case == "large_plus"):
                payload[currLine] = self.mutateLine(payload[currLine], 999999999999999999999999999999999999999999999999999999)
            elif(case == "null_term"):
                payload[currLine] = self.mutateLine(payload[currLine], "\0")
            elif(case == "format_string"):
                payload[currLine] = self.mutateLine(payload[currLine], "%x")
            elif(case == "new_line"):
                payload[currLine] = self.mutateLine(payload[currLine], "\n")
            else:
                pass
            final = "\n".join(payload)
            exitCode = runProcess(final)
            ThreadManager.getInstance().threadResult((payload,exitCode))
            if exitCode != 0:
                return
        self.lineByLineFuzz(mutated, stop, currLine+1, payload, cases)

        return ThreadManager.getInstance().threadResult(("",0))

    def replacementFuzz(self, mutated, stop):
        if stop():
            ThreadManager.getInstance().threadResult((mutated,0))
            return

        payload = self.inputStr
        cases = copy.deepcopy(self.rules)
        while(cases != []):
            case = cases.pop(0)
            if(case == "overflow_lines"):
                payload = "A"*10000
            elif(case == "overflow_values"):
                pass
            elif(case == "minus"):
                payload = "-1"
            elif(case == "plus"):
                payload = "1"
            elif(case == "zero"):
                payload = "0"
            elif(case == "large_minus"):
                payload = "-999999999999999999999999999999999999999999999999999999"
            elif(case == "large_plus"):
                payload = "999999999999999999999999999999999999999999999999999999"
            elif(case == "null_term"):
                payload = "\0"
            elif(case == "format_string"):
                payload = "%x"
            elif(case == "new_line"):
                payload = "\n"
            elif(case == "ascii"):
                for i in range(0, 127):
                    payload = chr(i)
                    exitCode = runProcess(payload)
                    ThreadManager.getInstance().threadResult((payload,exitCode))
                    if exitCode != 0:
                        return
                pass
            else:
                pass
            exitCode = runProcess(payload)
            ThreadManager.getInstance().threadResult((payload,exitCode))
            if exitCode != 0:
                return

class PlaintextFuzzer(Fuzzer):
    def __init__(self, inputStr):
        super().__init__(inputStr)
        # A list version of the sample input, separated by newline
        self.lines = []
        # Number of lines in the sample input
        self.numLines = 0
        # Variants of mutation to execute
        self.variants = ["nothing", "overflow", "null", "newline", "format", "ascii", "largeNeg", "largePos", "zero"]
        # A list of possibly bad bytes
        self.badBytes = self.getBadBytes()

    ########################
    # Variants of mutation #
    ########################

    # Append character padding to overflow
    def mutateOverflow(self, testStr, count):
        return testStr + "a"*count

    # Append null character
    def mutateNull(self, testStr, count):
        return testStr + "\0"*count

    # Append newline character
    def mutateNewline(self, testStr, count):
        return testStr + "\n"*count

    # Append format string
    def mutateFormat(self, testStr, count):
        return testStr + "%x"*count

    # Append all ascii characters
    def mutateAscii(self, testStr):
        count = 0
        while count <= 127:
            testStr = testStr + chr(count)
            count += 1
        return testStr

    # Mutate into large positive
    def mutateLargeNeg(self, testStr):
        return "-99999999"
    
    # Mutate into large positive
    def mutateLargePos(self, testStr):
        return "99999999"

    # Mutate into zero
    def mutateZero(self, testStr):
        return "0"

    # Mutate a random char in a list of strings
    def randomCharMutate(self, currLines):
        pickLine = random.randint(0, len(currLines)-1)
        pickChar = random.randint(0, len(currLines[pickLine])-1)
        pickRandomChar = self.badBytes[random.randint(0, len(self.badBytes)-1)]
        currLines[pickLine] = currLines[pickLine][:pickChar] + pickRandomChar + currLines[pickLine][pickChar+1:]
        return currLines

    ####################
    # Helper functions #
    ####################

    # Produce and return a list containing ascii characters (minus the alphabet)
    # and some more potentially troublesome bytes
    def getBadBytes(self):
        l = []
        count = 0
        while count <= 127:
            if count < 48 or count > 122:
                l.append(chr(count))
            count += 1
        l = l + ["a", "\0", "\n", "%x", "-99999999", "99999999", "0"]
        return l

    #################
    # Fuzzing logic #
    #################

    # Does two rounds of fuzzing
    # 1. Appending or changing characters exhaustively using a finite list of well-known edge cases
    # 2. Mutating one random character each time, resetting the string in between
    def fuzz(self, mutated, stop):
        # ThreadManager.getInstance().addSem.acquire()
        # ThreadManager.getInstance().addSem.release()
        # Prepare list of input lines
        testStr = self.inputStr
        self.lines = testStr.split("\n")
        currLines = self.lines.copy()
        # Prepare list of variants
        currVariants = self.variants.copy()
        # Get total number of lines
        self.numLines = len(self.lines)
        # Begin recursive fuzz
        print("@@@@@ Original testStr: "+testStr+"\n@@@@@ Number of lines: "+str(self.numLines))
        self.basicFuzz(mutated, stop, 0, currLines, currVariants)
        # Random character mutation
        print("@@@@@ Starting endless mutation")
        m = self.inputStr
        while True:
            if stop():
                ThreadManager.getInstance().threadResult((mutated,0))
                return
            print("@@@ Testing: "+m)
            exitCode = runProcess(m)
            ThreadManager.getInstance().threadResult((m,exitCode))
            if exitCode == -11:
                return
            m = "\n".join(self.randomCharMutate(self.lines.copy()))

    # We fuzz via recursion (essentially depth-first logic)
    # For every type of mutation in first input line, do every type of mutation for next line and so on...
    def basicFuzz(self, mutated, stop, currLine, currLines, currVariants):
        # Base case: no more input lines
        if currLine == self.numLines:
            return
        # Stop threads when required
        if stop():
            ThreadManager.getInstance().threadResult((mutated,0))
            return
        # If there are more variants of mutation to test, pop and mutate
        while currVariants != []:
            # Reset the current element
            currLines[currLine] = self.lines[currLine]
            variant = currVariants.pop(0)
            if variant == "nothing":
                pass
            elif variant == "overflow":
                currLines[currLine] = self.mutateOverflow(currLines[currLine], 10)
                # print("@@@ Overflow mutating for index "+str(currLine)+"\n")
            elif variant == "null":
                currLines[currLine] = self.mutateNull(currLines[currLine], 1)
            elif variant == "newline":
                currLines[currLine] = self.mutateNewline(currLines[currLine], 1)
            elif variant == "format":
                currLines[currLine] = self.mutateFormat(currLines[currLine], 1)
            elif variant == "ascii":
                currLines[currLine] = self.mutateAscii(currLines[currLine])
            elif variant == "largeNeg":
                currLines[currLine] = self.mutateLargeNeg(currLines[currLine])
            elif variant == "largePos":
                currLines[currLine] = self.mutateLargePos(currLines[currLine])
            elif variant == "zero":
                currLines[currLine] = self.mutateZero(currLines[currLine])
            else:
                pass
            # Recurse through the other lines
            self.basicFuzz(mutated, stop, currLine+1, currLines, ["nothing", "overflow", "null", "newline", "format", "ascii", "largeNeg", "largePos", "zero"])
            # Join the lines back into a string and fuzz
            testStr = "\n".join(currLines)
            print("@@@ In beginFuzz: testStr = "+testStr)
            exitCode = runProcess(testStr)
            ThreadManager.getInstance().threadResult((testStr,exitCode))
            # If vulnerability found, return
            if exitCode == -11:
                return

        # No vulnerability found
        return ThreadManager.getInstance().threadResult(("",0))


# Runs a process, returns exit code
def runProcess(testStr):
    p = process("./"+sys.argv[1])
    # print("@@@ Sending: " + testStr)
    # print(len(testStr))
    p.sendline(testStr)
    p.shutdown()
    ret = p.poll(block = True)
    p.stderr.close()
    p.stdout.close()
    return ret


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
    inputFile.close()
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
