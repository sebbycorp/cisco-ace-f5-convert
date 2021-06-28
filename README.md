# cisco-ace-f5-convert

How to use this snippet:

Generate the F5 configuration:


```
python ace2f5.py -f <ACE configuration input file> [-o <F5 configuration output file>] [-n NOT FULLY IMPLEMENTED (will disable out, i.e. validation to screen only]
```
If no output file is defined will output to ACE configuration file name plue '.checking'

Can also run and stay in Python CLI using the -i option e.g.


```
python -i ace2f5.py -f <ACE configuration input file>
```

After manually checking the output file run the following to generate a clean F5 TMOS configuration file with a .output extension. This .output is the file to be imported into F5 LTM


```
python checking-output.py -f <ace2f5.py checking file>
```
