fuzzer.py
========================

## Usage

```
./fuzzer.py binary binary.txt
```

------------------------

## Description

The fuzzer will receive the runnable binary's name and the name of it's sample input file. The sample input file will be in either JSON, CSV, XML or Plaintext format.

It then determines the type of the input file by attempting to parse the file as XML/JSON, or counting the commas present within the file and seeing if that correlates to a valid CSV file; considering the number of lines in the file. Eventually it defaults to Plaintext if it cannot determine any of the above.

The fuzzer then passes the appropriate fuzzing class (JSON, XML, CSV, Plaintext) to a thread manager. The thread manager starts several threads (based on how many logical threads are on the machine) of the fuzzing class, each running the fuzz() function. Each thread returns to the threadResult() function , where the exitcode is monitored for a segmentation fault, and all other threads can be stopped. Here, this design benefits both where state is held through semaphores, creating processes simultaneously, as well as where it isn't (i.e. completely random mutation), generating mutations and processes simultaneously.

## JSON

For JSON files, we have hardcoded 'rules' that are used initially to mutate the input string. These rules for JSON are

- overflow("A" * 10000)
- boundary_minus (-1), boundary_plus (1), boundary_zero (0)
- large_pos_num (999999999999999999999999999999999999999999999999999999)
- large_neg_num (-999999999999999999999999999999999999999999999999999999)
- format ("%s" *1000)
- one_byte, two_byte, four_byte, eight_byte integer overflows

Phase 1 of JSON fuzzing involves testing each of these inputs for each JSONObject in the given input. This will cause vulnerabilities that do not depend on code flow (i.e. where one JSONObject has to equal x and the other requires an overflow) to be detected early on. Using these inputs, we could detect buffer overflows, where we assumed that 10000 bytes was large enough to overflow a buffer where each JSONObject was a separate buffer, format string vulnerabilities, where sending many %s would cause the binary to attempt to dereference many arbitrary values on the stack (alot of which would segmentation fault), integer overflows (sending 1 more byte than the size of each of the numerical bytes).

Phase 2 of JSON fuzzing involves creating large JSONObjects both vertically (having many sub objects) and horizontally (where their values are large in length). All strings have "bad bytes" appended to them randomly ("\0", "\n","A", "%s") until their length is of size 50, all ints are multiplied by -2 until their length is of size 20 and lists have 1000 ints and strings appended to them, applying the previous rules to them. Once all elements have reached their determined sizes, 100 more JSONObjects are added to the base objects and mutated the same as previously. These mutations are used to not only catch errors in the JSON parser, where it may not have been thought that extra elements could be added, as well as buffer overflows where the buffer is shared across JSONObjects. This phase will also detect semi-conditional code flow vulnerabilities, where each JSON element requires to be the same type as originally defined, however, is still subject to potential integer/buffer overflows and format string vulnerabilities, aided by the potential corruption of '\n' and '\0' required functions like strcmp and fgets.

Phase 3 of JSON fuzzing runs for the remaining length of the runtime of the fuzzer, where one random element is chosen and manipulated based on the original input string. For ints, a random number is chosen between two bounds. For strings, a random number of characters from the original string and random set of characters (selected from all unicode characters). For lists, a random element in the list is chosen and has these rules applied to them based on their type. This phase will detect fully-conditional code, where some elements need to be the same as the original apart from one which could have any of the previous vulnerabilities stated.

In terms of improvement, phase 3 needs to be more deterministic, where this type of randomness will most likely not find the required vulnerability. One way this could be achieved is by setting a thread to each JSON element, allowing state to be stored for each JSON element rather than the whole object itself. This would allow mutations like incrementing an integer between two ranges, where the increment can be reduced each time, allowing for efficient searching of a vulnerable number, or testing all possible permutations of a given string for a set of unicode characters. 

## CSV

For CSV files, the approach was to have a set of cases that we then use to fuzz the program in three phases. The cases are:

- overflow_lines
- overflow_values
- minus, plus
- zero
- large_minus, large_plus
- null_term
- format_string
- new_line
- ascii

**overflow_lines** seeks to use a valid csv line where each value is a single A.

**overflow_values** uses a line where each value is a set of 100 A's.

**minus**, **plus**, **zero**, **large_minus** and **large_plus** use -1, 1, 0, -999999999999999999999999999999999999999999999999999999 and 999999999999999999999999999999999999999999999999999999 respectively.

**null_term**, **format_string** and **new_line** use the null terminator \0, %x operand and a new line \n.

**Ascii** then uses each of the ascii values from 0-127.

Phase 1 of CSV fuzzing involves appending the above cases to mutate the payload. The cases will append a valid line of the case which should check for any binaries that can potentially cause a seg fault when reading in a new line. 

Phase 2 of CSV fuzzing involves mutating the input file line by line with the above cases. E.g. in the case of csv1.txt and case "minus", 
the fuzzer will mutate the initial line of the file so that the first line will be "-1, -1, -1, -1". This should scan for any checks in 
any binary that checks for line integrity. 

Phase 3 of CSV fuzzing is the final mutation based fuzzing where it simply replaces the input file with variations of the above cases. When dealing with the csv format, the main factor at play is to make sure each line is a valid csv input, which can be easily done by 
calculating the number of commas present in each line of the input file and adding one to get the number of values needed per line. As a result, the possible approaches go towards those with a valid csv input line (phase 1 and 2) and those without (phase 3). 

Possible improvements to the csv fuzzer would be to test with more unicode characters and to test with individual value changes rather 
than the line by line changes. Given that the time limit was 3 minutes to fuzz the program, there were concerns that doing an individual 
value based input would drastically increase the time. The way this fuzzer is set up allows for expansion of logic in a fairly simple way. 

## XML

For XML files, the approach was to permutate all available fields in the provided XML document. The XML document is parsed using
the ElementTree XML API which provides several functions that simplify the accessing and modifying of XML document elements. Additionally, it supports the parsing of an existing XML document, to an in-memory string that can be sent directly to the binary. 
(documentation here: https://docs.python.org/2/library/xml.etree.elementtree.html)

The main approach for fuzzing binaries that take XML input was to mutate the existing XML document at all feasible levels (while keeping the size of the generated XML string in mind; testing showed that adding unnecessary tags, or large amounts of text would quickly grow the XML string to an unacceptable size, and would not result in any discovered exploits). Existing attributes, and text within tags are replaced at random with several types of 'bad' input (such as format strings, large ints, large negative ints, etc.). Additional XML elements are also added to the DOM (without breaking the XML document's syntax), in order to other possible vulnerabilities in the binary.

With several threads running, the hope is that we can mutate the existing XML document enough to expose a vulnerability. 
The fuzzer itself is composed of several python Enum classes, which hold the fuzzing inputs, and a XMLFuzzer class which is responsible for mutating the XML string, and threading results. The class-based implementation is open for extension, and simple to understand.


Attributes and text within existing tags are randomly chosen.


Both of these styles of testing, by choosing rules, attempt to cover the most amount of code by attempting to find scenarios where we can exploit vulnerable code. For example, choosing boundary and large integers to test for integer overflow and unexpected parsing of integers, multiple "%s" format strings, to attempt to deference an invalid pointer where there is a format string vulnerability, and many "A"s to attempt to overwrite an important return address such that the program seg faults.

In terms of improvement, the XML fuzzer would benefit from the ability to write very specific test cases (an example of this would be to write a test case that only changes the text attributes to large "A" strings, or inserting a div with a large depth). As we have taken the multithreading approach,
it was very difficult to implement specific test cases, as we run into several concurrency and resource management issues. The current XML fuzzer is only able to randomly mutate attributes, the DOM and text as a 'dumb' fuzzer, and has no logic to infer the best next mutation, given the current state of our
mutated input, or the program's output. We would implement this improvement by first solving the concurrency and resource management issues that come from the fuzzer's multithreaded nature. After this we would be able to write specific test cases and other test cases that select their mutations much more intelligently then our current random method.

## Plaintext

Fuzzing for plaintext consists of three parts.

The **first segment** fuzzes for an overflow vulnerability. Additional characters are incrementally appended to each line of input up till a certain limit. The program is run in between each change to probe for the vulnerability.

The **second segment** recursively fuzzes with a range of mutations that are relatively better known to cause issues. This includes:

- Null \0
- Newline \n
- Format string %s
- 127 Ascii characters
- Large negative number, large positive number
- Zero

For every line of input, the fuzzer either appends or replaces the line with one of the above, and it tests every permutation. Essentially, every type of mutation for the first line with every type of mutation for the second line and so on.

The **third segment** fuzzes indefinitely for the rest of the duration allowed, mutating one random character from every line of input every time (goes back to original after each test). This random character is mutated into another random character from a list containing all ascii characters and some other forms of input like large negative number or "%s".

There were some considerations made when deciding the types of mutations to perform. In the second segment, every permutation is tested which results in exponential time complexity. This is typically bad, but it is very unlikely that it will take too long in the scope of this project. In exchange for being able to have full coverage over the permutations here, it is well worth the otherwise unpleasant time complexity.

In the third segment, mutating without reverting back to the original sample input lines in between was the initial implementation. However it appeared to be less effective than the latter implementation since some binaries require the input to stay somewhat similar to the original sample (in the case of plaintext3). Not reverting back to the original input lines would make it incredibly ineffective when fuzzing such binaries, especially with the random nature of the mutations and a large list of possible characters. It very quickly renders every input "invalid" in a sense, and its nearly impossible to revert back to "valid" input.

Perhaps an improvement to the plaintext fuzzer would be to still include the above earlier implementation as its own test (would be close to a last resort as it basically feeds a bunch of random bytes) - given that the previous methods have not found any bugs. There are also many more ways to mutate that could be included, or perhaps come up with more intelligent mutations based off how the binary reacts.

## Something Awesome

During this assignment, we created a "code flow report" which reports all code flows taken by the fuzzer when it was running, as well as both the input and ltrace output for each code flow. This allows for easier reverse engineering to dynamically understand how the binary might work, and what types of input could cause different paths. The usage is as such:```./fuzzer.py binary binary.txt -report``` , which generates a directory `trace` with a file named `trace.txt`, showing a report of all the code flows and how many times they ran. 

e.g. for json1, `trace.txt` reads:

```
Total Runs: 12

Code Paths:

1) strlen --> strlen --> strncmp --> strlen --> strlen --> strncmp --> strlen --> strlen --> strlen --> strlen --> strlen --> strlen --> strtol --> strndup --> strncpy --> printf ran 7 times
                    
2)  ran 1 times
                    
3) strlen --> puts ran 1 times
                    
4) strlen --> strlen --> strncmp --> strlen --> strlen --> strncmp --> strlen --> strlen --> strtol --> strndup --> strncpy --> printf ran 2 times
                    
5) strlen --> strlen --> strncmp --> strlen --> strlen --> strncmp --> strlen --> strlen --> strtol --> strndup ran 1 times
```

Similarly, folders for each of the code paths,based on the code path number, will be generated containing `input.txt` (showing an example input for this code path) and `ltraceoutput.txt` (showing the ltrace output for this code path). This currently only works reliably for json and plaintext binaries, where there seems to be an issue with connecting ltrace through pid to some of the other binaries.

