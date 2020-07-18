fuzzer.py
========================
Usage
```
python fuzzer.py binary binary.txt
```
------------------------

Fuzzer will recieve the runnable binary's name and the name of it's sample input file.
The sample input file will be in either JSON, CSV, XML or Plaintext format.

Fuzzer then determines the type of the input file by attempting to parse the file as XML/JSON,
or counting the commas present within the file and seeing if that correlates to a valid CSV
file; considering the number of lines in the file. The fuzzer defaults to plaintext if it cannot
determine a type.

Fuzzer then passes the appropriate fuzzing class (JSON, XML, CSV, Plaintext) to a thread manager.
The thread manager starts several threads (this can be altered as required, it is a hardcoded value)
of the fuzzing class, each running the fuzz() function. 

For JSON files, we have hardcoded 'rules' that are used at random to mutate the input file. These rules for
JSON are overflow, boundary_minus (-1), boundary_plus (1), boundary_zero (0), large_pos_num 
(999999999999999999999999999999999999999999999999999999), large_neg_num (-999999999999999999999999999999999999999999999999999999) 
and format (%p). We randomly mutate every json entry with a rule until and try to run the mutated input.
We record the input if it returns a non-zero exit code in bad.txt.

For CSV files, we haven't implement multithreading yet, but we have some hardcoded test cases that we
perform to mutate csv files. These are: adding new lines, adding a large string, adding large positive
numbers to a line, adding large negative numbers to a line and adding zeros to a line.
We record the input if it returns a non-zero exit code in bad.txt.
