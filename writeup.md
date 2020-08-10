fuzzer.py
========================
## Usage

```
./fuzzer.py binary binary.txt
```
------------------------

## Description

The fuzzer will receive the runnable binary's name and the name of it's sample input file.
The sample input file will be in either JSON, CSV, XML or Plaintext format.

It then determines the type of the input file by attempting to parse the file as XML/JSON,
or counting the commas present within the file and seeing if that correlates to a valid CSV
file; considering the number of lines in the file. Eventually it defaults to Plaintext if it cannot
determine any of the above.

The fuzzer then passes the appropriate fuzzing class (JSON, XML, CSV, Plaintext) to a thread manager.
The thread manager starts several threads (number may be altered easily as required) of the fuzzing class, each running the fuzz() function.

## JSON

For JSON files, we have hardcoded 'rules' that are used at random to mutate the input file. These rules for
JSON are

- overflow("A" * 1000)
- boundary_minus (-1), boundary_plus (1), boundary_zero (0)
- large_pos_num (999999999999999999999999999999999999999999999999999999)
- large_neg_num (-999999999999999999999999999999999999999999999999999999)
- format ("%s" *1000)

We randomly choose a rule for each entry in the JSON object and try to run the mutated input.
We record the input if it returns a non-zero exit code in bad.txt.

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


Attributes and text within existing tags are randomly


Both of these styles of testing, by choosing rules, attempt to cover the most amount of code by attempting to find scenarios where we can exploit vulnerable code. For example, choosing boundary and large integers to test for integer overflow and unexpected parsing of integers, multiple "%s" format strings, to attempt to deference an invalid pointer where there is a format string vulnerability, and many "A"s to attempt to overwrite an important return address such that the program seg faults.

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



