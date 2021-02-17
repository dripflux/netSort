#!/usr/bin/env python3

"""
NAME
	netSortTest - Unit tests for Network Traffic Sorter (netSort).

SYNOPSIS
	netSortTest [component_to_test]...

DESCRIPTION
	Conduct and report on unit tests for netSort.
	Without arguments perform all unit tests.
	If arguments, then only perform categorical unit tests per below.

	raw : Test RawPacket
"""

# Required imports
import sys      # System Module: argv
import netSort  # Network Traffic Sorter Module: *

def main(
		cmdArgv=None
	) :
	"""
	Description: Main program control flow and logic.
	Arguments:
		cmdArgv : Command line arguments, expect same format as sys.argv.
	Return:
		...
	"""
	## Set Up Environment
	if cmdArgv is None :
		argv = sys.argv.copy()
	else :
		argv = cmdArgv
	## Test Components
	if len(argv) == 1 :
		argv.append("raw")
	for componentTest in argv[1:] :
		...
	...

# Function Definitions

if __name__ == "__main__" :  # Called as standalone program
	main()
