#!/usr/bin/env python3

"""
NAME
	netSort - Network traffic sorter. Group, sort, and report network traffic for specified metadata.

SYNOPSIS
	netSort ...

DESCRIPTION
	...
"""

# Required imports
import sys  # System Module: argv

# Declare Required Constants (Immutables)

# Declare Required Variables (Mutables)
config = {}

# Class Definitions

class RawPacket :
	"""
	Description: Model a single raw packet.
	"""

	def __init__(self) :
		"""
		Description: Initialize an empty raw packet.
		"""
		self.ID = None
		self.seconds = 0
		self.srcAddr = None
		self.destAddr = None
		self.proto = None
		self.bytes = 0

	def __str__(self) :
		"""
		Description: CSV representation of RawPacket.
		"""
		return self.toCSV()

	def fromCSV(self, lineCSV="") :
		"""
		Description: Populate RawPacket from CSV representation.
			Fields (index : description):
			0 : ID
			1 : Relative time from beginning of source capture
			2 : Source address
			3 : Destination address
			4 : Protocol, highest identified protocol in network stack
			5 : Payload size in bytes
		"""
		fields = lineCSV.split(",")
		self.ID = fields[0].strip('"')
		self.relTime = float( fields[1].strip('"') )
		self.srcAddr = fields[2].strip('"')
		self.destAddr = fields[3].strip('"')
		self.proto = fields[4].strip('"')
		self.bytes = int( fields[5].strip('"') )

	def toCSV(self) :
		"""
		Description: Return CSV representation of RawPacket.
			Fields (index : description):
			0 : ID
			1 : Relative time from beginning of source capture
			2 : Source address
			3 : Destination address
			4 : Protocol, highest identified protocol in network stack
			5 : Payload size in bytes
		"""
		packetCSV = str(self.ID) + "," + str(self.relTime) + "," + str(self.srcAddr)\
		  + "," + str(self.destAddr) + "," + str(self.proto) + "," + str(self.bytes)
		return packetCSV

def main(
		cmdArgv = None
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
		argv = sys.argv
	else :
		argv = cmdArgv
	configureDefaults()
	...

# Function Definitions

def configureDefaults() :
	"""
	Description: Assign default configuration to config.
	"""
	...

if __name__ == "__main__" :  # Called as standalone program
	main()
