#!/usr/bin/env python3

"""
NAME
	netSort - Network traffic sorter. Group, sort, and report network traffic on specified metadata.

SYNOPSIS
	netSort metadataFile...
	netSort [group <src | dest | connect | proto>] [sort <packets | bytes>] [order <low | high>] metadataFile...
	netSort help

DESCRIPTION
	Process network traffic packet metadata from metadataFile.
	Default I/O format is CSV discussed in RawPacket (ID, relative time, source address, destination address, protocol, payload bytes).
	Group packets by 'group' per below.
	Sort packet groups by 'sort' per below.
	Order output based on 'order' per below.

	group
		src : (default) Group packets by source address
		dest : Group packets by destination address
		connect : Group packets by source and destination pairing permutations, a -> b is separate from b -> a.
		proto : Group packets by protocol.

	sort
		packets : (default) Sort by number of packets for group.
		bytes : Sort by total bytes sent for group.

	order
		low : (default) Order output numerical low to high (i.e. normal sorting).
		high : Order output numerical high to low (i.e. reverse sorting).

	help : Print this help file.
"""

# Required imports
import sys  # System Module: argv

# Declare Required Constants (Immutables)
# Mode Bits
# Group By
# 1|111
GROUP_BY_MASK        = 0o17  # Bits 0-3
GROUP_BY_USE_DEFAULT = 0o00
GROUP_BY_SRC_ADDR    = 0o01
GROUP_BY_DEST_ADDR   = 0o02
GROUP_BY_CONNECT     = 0o03
GROUP_BY_PROTO       = 0o04
GROUP_BY_EXTEND_01   = 0o17
GROUP_BY_DEFAULT     = GROUP_BY_SRC_ADDR
# Count
# 11|11 0|000
SORT_MASK        = 0o360  # Bits 4-7
SORT_USE_DEFAULT = 0o000
SORT_PACKETS     = 0o020
SORT_BYTES       = 0o040
SORT_EXTEND_01   = 0o360
SORT_DEFAULT     = SORT_PACKETS
# Order
# 111|1 00|00 0|000
ORDER_MASK        = 0o7400  # Bits 8-11
ORDER_USE_DEFAULT = 0o0000
ORDER_NUM_LOW     = 0o0400
ORDER_NUM_HIGH    = 0o1000
ORDER_EXTEND_01   = 0o7400
ORDER_DEFAULT     = ORDER_NUM_LOW
# Input Format
# 1|111| 000|0 00|00 0|000
IN_FORMAT_MASK          = 0o170000  # Bits 12-15
IN_FORMAT_USE_DEFAULT   = 0o000000
IN_FORMAT_CSV_HEADER    = 0o010000
IN_FORMAT_CSV_NO_HEADER = 0o020000
IN_FORMAT_EXTEND_01     = 0o170000
IN_FORMAT_DEFAULT       = IN_FORMAT_CSV_HEADER
# Output Data
# 11|11 0|000| 000|0 00|00 0|000
OUT_DATA_MASK        = 0o3600000  # Bits 16-19
OUT_DATA_USE_DEFAULT = 0o0000000
OUT_DATA_TRACK_SORT  = 0o0200000
OUT_DATA_PACKETS     = 0o0400000
OUT_DATA_BYTES       = 0o1000000
OUT_DATA_EXTEND_01   = 0o2000000
OUT_DATA_DEFAULT     = OUT_DATA_TRACK_SORT
# Output Format
# 111|1 00|00 0|000| 000|0 00|00 0|000
OUT_FORMAT_MASK        = 0o74000000  # Bits 20-23
OUT_FORMAT_USE_DEFAULT = 0o00000000
OUT_FORMAT_TSV_HUMAN   = 0o04000000
OUT_FORMAT_TSV_SIMPLE  = 0o10000000
OUT_FORMAT_CSV         = 0o14000000
OUT_FORMAT_EXTEND_01   = 0o74000000
OUT_FORMAT_DEFAULT     = OUT_FORMAT_TSV_HUMAN

# Declare Required Variables (Mutables)
config = {}

# Class Definitions

class RawPacket :
	"""
	Description: Model a single raw packet.
	"""

	def __init__(
			self
		) :
		"""
		Description: Initialize an empty raw packet.
		"""
		self.ID = None
		self.relTime = 0
		self.srcAddr = None
		self.destAddr = None
		self.proto = None
		self.bytes = 0

	def __str__(
			self
		) :
		"""
		Description: CSV representation of RawPacket.
		"""
		return self.toCSV()

	def fromCSV(
			self
			, lineCSV = ""
		) :
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

	def toCSV(
			self
		) :
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

class ProcPacket :
	"""
	Description: Singleton for processed packets based on grouping, counting, and ordering mode processed from a RawPacket.
	"""

	def __init__(
			self
			, packet
		) :
		"""
		Description: Initialize an empty, or as specified ProcPacket.
		Arguments:
			packet : RawPacket instance
		"""
		self.group = None
		self.count = 0
		self.bytes = 0
		if packet is not None :
			modeGroup = config["mode"] & GROUP_BY_MASK
			if modeGroup == GROUP_BY_USE_DEFAULT :
				modeGroup = GROUP_BY_DEFAULT
			if modeGroup == GROUP_BY_SRC_ADDR :
				self.group = packet.srcAddr
			elif modeGroup == GROUP_BY_DEST_ADDR :
				self.group = packet.destAddr
			elif modeGroup == GROUP_BY_CONNECT :
				self.group = str(packet.srcAddr) + " -> " + str(packet.destAddr)
			elif modeGroup == GROUP_BY_PROTO :
				self.group = packet.proto
			self.count = 1
			self.bytes = packet.bytes

	def __iadd__(
			self
			, other
		) :
		if self.group == other.group :
			self.count += other.count
			self.bytes += other.bytes
		return self

	def __eq__(
			self
			, other
		) :
		modeSort = config["mode"] & SORT_MASK
		if modeSort == SORT_USE_DEFAULT :
			modeSort = SORT_DEFAULT
		if modeSort == SORT_PACKETS :
			return (self.count == other.count) and (self.group == other.group)
		elif modeSort == SORT_BYTES :
			return (self.bytes == other.bytes) and (self.group == other.group)

	def __ge__(
			self
			, other
		) :
		modeSort = config["mode"] & SORT_MASK
		if modeSort == SORT_USE_DEFAULT :
			modeSort = SORT_DEFAULT
		if modeSort == SORT_PACKETS :
			if self.count > other.count :
				return True
			elif self.count == other.count :
				return self.group >= other.group
			else :
				return False
		elif modeSort == SORT_BYTES :
			if self.bytes > other.bytes :
				return True
			elif self.bytes == other.bytes :
				return self.group >= other.group
			else :
				return False

	def __gt__(
			self
			, other
		) :
		modeSort = config["mode"] & SORT_MASK
		if modeSort == SORT_USE_DEFAULT :
			modeSort = SORT_DEFAULT
		if modeSort == SORT_PACKETS :
			if self.count > other.count :
				return True
			elif self.count == other.count :
				return self.group > other.group
			else :
				return False
		elif modeSort == SORT_BYTES :
			if self.bytes > other.bytes :
				return True
			elif self.bytes == other.bytes :
				return self.group > other.group
			else :
				return False

	def __le__(
			self
			, other
		) :
		modeSort = config["mode"] & SORT_MASK
		if modeSort == SORT_USE_DEFAULT :
			modeSort = SORT_DEFAULT
		if modeSort == SORT_PACKETS :
			if self.count < other.count :
				return True
			elif self.count == other.count :
				return self.group <= other.group
			else :
				return False
		elif modeSort == SORT_BYTES :
			if self.bytes < other.bytes :
				return True
			elif self.bytes == other.bytes :
				return self.group <= other.group
			else :
				return False

	def __lt__(
			self
			, other
		) :
		modeSort = config["mode"] & SORT_MASK
		if modeSort == SORT_USE_DEFAULT :
			modeSort = SORT_DEFAULT
		if modeSort == SORT_PACKETS :
			if self.count < other.count :
				return True
			elif self.count == other.count :
				return self.group < other.group
			else :
				return False
		elif modeSort == SORT_BYTES :
			if self.bytes < other.bytes :
				return True
			elif self.bytes == other.bytes :
				return self.group < other.group
			else :
				return False

	def __str__(
			self
		) :
		strPacket = str(self.group) + "," + str(self.count) + "," + str(self.bytes)
		return strPacket

class ProcPackets :
	"""
	Description: Container for ProcPacket singletons.
	"""

	def __init__(
			self
			, file = None
			, format = IN_FORMAT_USE_DEFAULT
		) :
		"""
		Description: Initialize an empty packet container, or with specified data from file per format.
		Design philosophy, container attributes should be internally managed, not directly manipulated by external code.
		"""
		self.__rawPackets = []
		self.__procPackets = {}
		self.__resultPackets = []
		if file is not None :
			self.appendPackets(file, format)

	def appendPackets(
			self
			, file = None
			, format = IN_FORMAT_USE_DEFAULT
		) :
		if file is not None :
			# Prepare for opening input file
			formatIn = format & IN_FORMAT_MASK
			if formatIn == IN_FORMAT_USE_DEFAULT :
				formatIn = IN_FORMAT_DEFAULT
			fileOpenMode = "rt"
			try :
				packetsFile = open(file, mode=fileOpenMode)
			except :
				raise
			# Convert input file to packet per line format
			packetPerLine = []
			if (formatIn & IN_FORMAT_CSV_HEADER) or (formatIn & IN_FORMAT_CSV_NOHEADER) :
				packetPerLine = packetsFile
			skipFirst = False
			if formatIn & IN_FORMAT_CSV_HEADER :
				skipFirst = True
			# Process packet per line
			for packetLine in packetPerLine :
				if skipFirst :
					skipFirst = False
					continue
				pureCSV = packetLine.strip()
				newPacket = RawPacket()
				newPacket.fromCSV(pureCSV)
				self.__rawPackets.append(newPacket)

	def processPerMode(
			self
			, mode = None
		) :
		"""
		Description: Lowest level API; process RawPackets based on mode or config["mode"] if None.
		Arguments:
			mode : Mode to group, count, and order RawPackets per.
		Returns:
			[list] : List of ProcPacket objects grouped and ordered, each ProcPacket has count and bytes data.
		"""
		if mode is not None :
			combinedMasks = GROUP_BY_MASK | SORT_MASK | ORDER_MASK
			config["mode"] = (combinedMasks & mode) | (config["mode"] & ~combinedMasks)
		self.__processGroupBy()
		self.__resultPackets = list(self.__procPackets.values())
		self.__resultPackets.sort()
		return self.__resultPackets.copy()

	def __processGroupBy(
			self
		) :
		"""
		Description: Process RawPackets based on group mode.
		"""
		# Set up for processing
		self.__procPackets.clear()
		# Traverse and group raw packets
		for rawPacket in self.__rawPackets :
			procPacket = ProcPacket(rawPacket)
			if procPacket.group not in self.__procPackets :
				self.__procPackets[procPacket.group] = procPacket
			else :
				self.__procPackets[procPacket.group] += procPacket

	def connectionByBytes(
			self
			, orderMode = None
		) :
		"""
		Description: ...
		Arguments:
			orderMode : Ordering mode for processed packets.
		Returns:
			[list] : List of tuples per group, count, and order processed packet data.
		"""
		...

	def connectionByPackets(
			self
			, orderMode = None
		) :
		"""
		Description: ...
		Arguments:
			orderMode : Ordering mode for processed packets.
		Returns:
			[list] : List of tuples per group, count, and order processed packet data.
		"""
		...

	def destinationByBytes(
			self
			, orderMode = None
		) :
		"""
		Description: ...
		Arguments:
			orderMode : Ordering mode for processed packets.
		Returns:
			[list] : List of tuples per group, count, and order processed packet data.
		"""
		...

	def destinationByPackets(
			self
			, orderMode = None
		) :
		"""
		Description: ...
		Arguments:
			orderMode : Ordering mode for processed packets.
		Returns:
			[list] : List of tuples per group, count, and order processed packet data.
		"""
		...

	def protocolByBytes(
			self
			, orderMode = None
		) :
		"""
		Description: ...
		Arguments:
			orderMode : Ordering mode for processed packets.
		Returns:
			[list] : List of tuples per group, count, and order processed packet data.
		"""
		...

	def protocolByPackets(
			self
			, orderMode = None
		) :
		"""
		Description: ...
		Arguments:
			orderMode : Ordering mode for processed packets.
		Returns:
			[list] : List of tuples per group, count, and order processed packet data.
		"""
		...

	def sourceByBytes(
			self
			, orderMode = None
		) :
		"""
		Description: ...
		Arguments:
			orderMode : Ordering mode for processed packets.
		Returns:
			[list] : List of tuples per group, count, and order processed packet data.
		"""
		...

	def sourceByPackets(
			self
			, orderMode = None
		) :
		"""
		Description: ...
		Arguments:
			orderMode : Ordering mode for processed packets.
		Returns:
			[list] : List of tuples per group, count, and order processed packet data.
		"""
		if orderMode is not None :
			procMode = orderMode & ORDER_MASK
		else :
			procMode = config["mode"] & ORDER_MASK
		procMode = procMode & ~GROUP_BY_MASK
		procMode = procMode & ~SORT_MASK
		procMode = procMode | GROUP_BY_SRC_ADDR | SORT_PACKETS
		return self.processPerMode(procMode)

	def clear(
			self
		) :
		"""
		Description: Clear source packets and results from previous processing; retains configuration mode.
		"""
		self.clearResults()
		self.__rawPackets.clear()

	def clearResults(
			self
		) :
		"""
		Description: Clear results from previous processing.
		"""
		self.__procPackets.clear()
		self.__resultPackets.clear()

	def recallResults(
			self
		) :
		"""
		Description: Recall results from last processing.
		Returns:
			[list] : List of tuples from last successful packet processing.
		"""
		return self.__resultPackets.copy()

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
	# Set Up Environment
	if cmdArgv is None :
		argv = sys.argv
	else :
		argv = cmdArgv
	# Handle help option
	if "help" in argv :
		print(__doc__)
		sys.exit()
	configureDefaults()
	...

# Function Definitions

def configureDefaults(
	) :
	"""
	Description: Assign default configuration to config.
	"""
	config["mode"] = \
	    GROUP_BY_USE_DEFAULT \
	  | SORT_USE_DEFAULT \
	  | ORDER_USE_DEFAULT \
	  | IN_FORMAT_USE_DEFAULT \
	  | OUT_DATA_USE_DEFAULT \
	  | OUT_FORMAT_USE_DEFAULT

def outputResults(
		results
		, file = sys.stdout
		, mode = None
	) :
	"""
	Description: ...
	"""
	if mode is not None :
		outMode = mode & SORT_MASK
	else :
		outMode = config["mode"] & SORT_MASK
	if outMode == SORT_USE_DEFAULT :
		outMode = SORT_DEFAULT
	for resultProcPacket in results :
		outData = str(resultProcPacket.group) + "\t"
		if outMode == SORT_PACKETS :
			outData += str(resultProcPacket.count)
		elif outMode == SORT_BYTES :
			outData += str(resultProcPacket.bytes)
		print(outData, file=file)

configureDefaults()
if __name__ == "__main__" :  # Called as standalone program
	main()
