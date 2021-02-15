#!/usr/bin/env python3

"""
NAME
	netSort - Network traffic sorter, group, sort, and report network traffic metadata.

SYNOPSIS
	netSort ...

DESCRIPTION
	...
"""

# Required imports
import sys  # System Module: argv

# Declare Required Constants (Immutables)

def main(
		cmdArgv = None
	) :
	"""
	Description: Main program control flow and logic.
	Arguments:
		cmdArgv : Command line arguments, expect same format as sys.argv
	Return:
		...
	"""
	# Perform Function
	## Test Environment
	if cmdArgv is None :
		argv = sys.argv
	else :
		argv = cmdArgv
	...

# Function Definitions

...

if __name__ == "__main__" :  # Called as standalone program
	main()
