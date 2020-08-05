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
import os

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
            self.codeFlows = dict()
            self.codeFlowCount = 0
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

    def threadResultWithLtrace(self,result,ltrace):
        (i, e) = result
        if ltrace is not None:
            (parsedLtrace,originalLtraceList) = ltraceParser(ltrace)
            # calls = tuple(i for i in parsedLtrace)
            # need to convert to a tuple, lists cannot be hashed
            calls = tuple(i[0] for i in parsedLtrace)
            # print(calls)
            self.stopSem.acquire()
            if self.codeFlows.get(calls) is None:
                self.codeFlows[calls] = (1,i,originalLtraceList)
                self.codeFlowCount +=1
            else:
                (count, testStr, originalLtraceList) = self.codeFlows[calls]
                self.codeFlows[calls] = (count+1,i,originalLtraceList)
                self.codeFlowCount +=1
        else:
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
                reportDetails = ""
                count =1
                cwd = os.getcwd()
                traceReportFile = os.path.join(cwd,"trace", "trace.txt")
                for key in self.codeFlows:
                    codePath = ""
                    sampleInputFile = os.path.join(cwd,"trace", str(count),"input.txt")
                    ltraceOutputFile = os.path.join(cwd,"trace", str(count),"ltraceoutput.txt")
                    os.makedirs(os.path.dirname(sampleInputFile), exist_ok=True)
                    s=open(sampleInputFile,"w+")
                    s.write(self.codeFlows.get(key)[1])
                    s.close()
                    l=open(ltraceOutputFile,"w+")
                    l.write('\n'.join(self.codeFlows.get(key)[2]))
                    l.close()
                    for i in range(0,len(key)):
                        if i is not len(key)-1:
                            codePath+= key[i] + " --> "
                        else:
                            codePath+= key[i]
                    reportDetails += f"""
{count}) {codePath} ran {self.codeFlows.get(key)[0]} times
                    """
                    count +=1

                traceReport = f"""Trace Report

Total Runs: {self.codeFlowCount}

Code Paths:

{reportDetails}

Folders based on code paths have been generated...
                """
                os.makedirs(os.path.dirname(traceReportFile), exist_ok=True)
                t=open(traceReportFile,"w+")
                t.write(traceReport)
                t.close()
                self.stopSem.release()
        self.stopSem.release()

# Use 10 threads for now
threadManager = ThreadManager(4)

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
        for rule in JSONRules :
            self.rules.append(rule.value)
        self.bytesToAdd = ["\0", "%s", "A", "\n"]
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
                ThreadManager.getInstance().threadResultWithLtrace((mutated,0),None)
                return
            (exitCode, ltrace) = runProcessWithLtrace(m)
            ThreadManager.getInstance().threadResultWithLtrace((m,exitCode),ltrace)
            if exitCode != 0:
                return
            m = self.mutate()
    
    def checkFormatStrNum(self,inputStr):
        res = re.search(r"\%(.*?)\$", inputStr).group()
        return res[1:len(res)-1]
    
    def getFormatStr(self, num):
        return "%s" * num;    

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
                    if len(self.jsonObj[key]) < 1000:
                        if continueFlag:
                            continueFlag = False
                    self.jsonObj[key] = self.jsonObj[key] + byte
                if isinstance(self.jsonObj[key], int):
                    if self.jsonObj[key] == 0:
                        self.jsonObj[key] = 1
                    if len(str(self.jsonObj[key])) < 50:
                        if continueFlag:
                            continueFlag = False
                    self.jsonObj[key] = self.jsonObj[key]*-2
                if isinstance(self.jsonObj[key], list):
                    for i in range(0,len(self.jsonObj[key])-1):
                        if isinstance(self.jsonObj[key][i],str):
                            if len(self.jsonObj[key][i]) < 1000:
                                if continueFlag:
                                    continueFlag = False
                                self.jsonObj[key][i] = self.jsonObj[key][i] + byte
                        if isinstance(self.jsonObj[key][i],int):
                            if self.jsonObj[key][i] == 0:
                                self.jsonObj[key][i] = 1
                            if len(str(self.jsonObj[key][i])) < 50:
                                if continueFlag:
                                    continueFlag = False
                            self.jsonObj[key][i] = self.jsonObj[key][i]*-2

                    if len(self.jsonObj[key])<1000:
                        toAdd = 1000 - len(self.jsonObj[key])
                        for i in range(0, toAdd//2):
                            self.jsonObj[key].append("A")
                        for i in range(toAdd//2, 1000):
                            self.jsonObj[key].append(random.randint(-10,10))

            if continueFlag:
                for i in range(0, 500):
                    self.jsonObj[f"add{i}"] = "A"
                for i in range(500, 1000):
                    self.jsonObj[f"add{i}"] = random.randint(-10,10)
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
        for i in range(10):
            inputStr = inputStr + self.craftLine()
        return inputStr

    # forms a valid line of 10 A's
    def craftLongLine(self):
        CSVline = '\n'
        for i in range(0, self.commasPerLine):
            CSVline += 'A'*9+','
        CSVline += 'A'
        return CSVline
    
    def appendLongOverflow(self, inputStr):
        inputStr = inputStr + self.craftLongLine()
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
    
    # append a line of 0's
    def appendZero(self, inputStr):
        newLine = '\n'
        for i in range(0, self.commasPerLine):
            newLine += '0,'
        newLine += '0'
        inputStr = inputStr + newLine
        return inputStr

    def fuzz(self, mutated, stop):
        # Fuzz a program with csv file format
        if stop():
            ThreadManager.getInstance().threadResult((mutated,0))
            return
        exitCode = runProcess("")
        ThreadManager.getInstance().threadResult(("",exitCode))
        if exitCode != 0:
            return

        # Fuzz - Overflow via appending single character csv line - e.g. A,A,A,A,A
        overflow = self.inputStr
        while (True):
            overflow = self.appendOverflow(overflow)
            exitCode = runProcess(overflow)
            ThreadManager.getInstance().threadResult((overflow,exitCode))
            if exitCode != 0:
                return
            if len(overflow) > 10000: 
                break

        # Fuzz - Overflow by appending 10 character values csv line - AAAAAAAAAA,AAAA... etc.
        overflow2 = self.inputStr
        while (True):
            overflow2 = self.appendLongOverflow(overflow2)
            exitCode = runProcess(overflow2)
            ThreadManager.getInstance().threadResult((overflow2,exitCode))
            if exitCode != 0:
                return
            if len(overflow2) > 10000:
                break

        # Fuzz - Payload with large Positive number
        payload = self.largePositive(self.inputStr)
        exitCode = runProcess(payload)
        ThreadManager.getInstance().threadResult((payload,exitCode))
        if exitCode != 0:
            return

        # Fuzz - Payload with large negative number
        payload = self.largeNegative(self.inputStr)
        exitCode = runProcess(payload)
        ThreadManager.getInstance().threadResult((payload,exitCode))
        if exitCode != 0:
            return
        
        # Fuzz - Payload with 0's
        payload = self.appendZero(self.inputStr)
        exitCode = runProcess(payload)
        ThreadManager.getInstance().threadResult((payload,exitCode))
        if exitCode != 0:
            return

        # No vulnerability found
        return ThreadManager.getInstance().threadResult(("",0))

class PlaintextFuzzer(Fuzzer):
    def __init__(self, inputStr):
        super().__init__(inputStr)
        # A list version of the sample input, separated by newline
        self.lines = []
        # Number of lines in the sample input
        self.numLines = 0
        # Variants of mutation to execute
        self.variants = []
    
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

    ###########
    # Fuzzing #
    ###########

    def fuzz(self, mutated, stop):
        # Prepare list of input lines
        testStr = self.inputStr
        self.lines = testStr.split("\n")
        currLines = self.lines.copy()
        # Prepare list of variants
        variants = ["nothing", "overflow", "null", "newline", "format", "ascii", "largeNeg", "largePos", "zero"]
        currVariants = variants.copy()
        # Get total number of lines
        self.numLines = len(self.lines)
        # Begin recursive fuzz
        print("@@@@@ Original testStr: "+testStr+"\n@@@@@ Number of lines: "+str(self.numLines))
        self.recurseFuzz(mutated, stop, 0, currLines, currVariants)

    # We fuzz via recursion (essentially depth-first logic)
    # For every type of mutation in first input line, do every type of mutation for next line and so on...
    def recurseFuzz(self, mutated, stop, currLine, currLines, currVariants):
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
            self.recurseFuzz(mutated, stop, currLine+1, currLines, ["nothing", "overflow", "null", "newline", "format", "ascii", "largeNeg", "largePos", "zero"])
            # Join the lines back into a string and fuzz
            testStr = "\n".join(currLines)
            print("@@@ In beginFuzz: testStr = "+testStr)
            exitCode = runProcess(testStr)
            ThreadManager.getInstance().threadResult((testStr,exitCode))
            # If vulnerability found, return
            if exitCode != 0:
                return

        # No vulnerability found
        return ThreadManager.getInstance().threadResult(("",0))


# Runs a process, returns exit code
def runProcess(testStr):
    p = process("./"+sys.argv[1])
    print("@@@ Sending: " + testStr)
    # print(len(testStr))
    p.sendline(testStr)
    p.shutdown()
    ret = p.poll(block = True)
    p.stderr.close()
    p.stdout.close()
    return ret


def runProcessWithLtrace(testStr):
    p = process("./" + sys.argv[1])
    ltracer = process(["/usr/bin/ltrace",f"-p {p.pid}", f"-s {99999999}"])
    sleep(0.001)
    p.sendline(testStr)
    p.shutdown()
    ret = p.poll(block = True)
    p.stderr.close()
    p.stdout.close()
    output = []
    try:
        while True:
            output.append(ltracer.recvline())
    except:
        pass
    ltracer.shutdown()
    ltracer.stderr.close()
    ltracer.stdout.close()
    return (ret,output)

def ltraceParser(ltraceList):
    codeFlow = []
    originalList = []
    # originalLtrace = ""
    for i in range(0, len(ltraceList)-1):
        currentCall = ltraceList[i].decode()
        # originalLtrace += currentCall
        originalList.append(currentCall)
        libraryCall = re.search(".*\(",currentCall)
        resultOfCall = re.search("\=.*",currentCall)

        if libraryCall is not None and resultOfCall is not None:
            # remove the (
            libraryCall = libraryCall.group()
            libraryCall = libraryCall[:len(libraryCall)-1]
            # remove the  =
            resultOfCall = resultOfCall.group()
            resultOfCall = resultOfCall[2:]
            codeFlow.append((libraryCall, resultOfCall))
    return (codeFlow,originalList)

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
