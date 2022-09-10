#!/usr/bin/env python3


"""
NAME
	netSort.py  Network traffic sorter. Group, sort, and report network traffic on specified metadata.

SYNOPSIS
	netSort.py help

	netSort.py metadataFile...
	netSort.py [group <src | dest | connect | conversation | proto>] [sort <packets | bytes>] [order <low | high | sequence>] metadataFile...

DESCRIPTION
	Process network traffic packet metadata from metadataFile.
	Default I/O format is CSV discussed in RawPacket (ID, relative time, source address, destination address, protocol, packet bytes).
	Group packets by 'group' per below.
	Sort packet groups by 'sort' per below.
	Order output based on 'order' per below.

	help : Print this help message.

	group : Group packets per below argument, repeats overwrite previous setting.
		src : (default) Group packets by source address.
		dest : Group packets by destination address.
		connect : Group packets by source and destination pairing permutations, a -> b is separate from b -> a.
		conversation : Group packets source and destination socket (src.addr, src.port, dest.addr, dest.port) permutations
		proto : Group packets by protocol.

	sort : Sort packets per below argument, repeats overwrite previous setting.
		packets : (default) Sort by number of packets for group.
		bytes : Sort by total bytes sent for group.

	order : Order packet sorting per below argument, repeats overwrite previous setting.
		low : (default) Order output numerical low to high (i.e. normal sorting).
		high : Order output numerical high to low (i.e. reverse sorting).
		sequence : Sort by conversation start sequence, only available for "group conversation".

	from : (reserved for future use)

	to : (reserved for future use)

	as : (reserved for future use)
"""


# Required imports
import enum  # Enumeration Module: Enum()
import sys   # System Module: argv


# Declare Required Constants (Immutables)
# Mode Bits
# Group By - Value Style
# 1|111
GROUP_BY_MASK        = 0o17  # Bits 0-3
GROUP_BY_USE_DEFAULT = 0o00
GROUP_BY_SRC_ADDR    = 0o01
GROUP_BY_DEST_ADDR   = 0o02
GROUP_BY_CONNECT     = 0o03
GROUP_BY_PROTO       = 0o04
GROUP_BY_EXTEND_01   = 0o17
GROUP_BY_DEFAULT     = GROUP_BY_SRC_ADDR
# Sort - Value Style
# 11|11 0|000
SORT_MASK        = 0o360  # Bits 4-7
SORT_USE_DEFAULT = 0o000
SORT_PACKETS     = 0o020
SORT_BYTES       = 0o040
SORT_EXTEND_01   = 0o360
SORT_DEFAULT     = SORT_PACKETS
# Order - Value Style
# 111|1 00|00 0|000
ORDER_MASK        = 0o7400  # Bits 8-11
ORDER_USE_DEFAULT = 0o0000
ORDER_NUM_LOW     = 0o0400
ORDER_NUM_HIGH    = 0o1000
ORDER_EXTEND_01   = 0o7400
ORDER_DEFAULT     = ORDER_NUM_LOW
# Input Format - Value Style
# 1|111| 000|0 00|00 0|000
IN_FORMAT_MASK          = 0o170000  # Bits 12-15
IN_FORMAT_USE_DEFAULT   = 0o000000
IN_FORMAT_CSV_HEADER    = 0o010000
IN_FORMAT_CSV_NO_HEADER = 0o020000
IN_FORMAT_FILE_OBJ      = 0o030000
IN_FORMAT_EXTEND_01     = 0o170000
IN_FORMAT_DEFAULT       = IN_FORMAT_CSV_HEADER
# Output Data - Flag Style
# 11|11 0|000| 000|0 00|00 0|000
OUT_DATA_MASK        = 0o3600000  # Bits 16-19
OUT_DATA_USE_DEFAULT = 0o0000000
OUT_DATA_TRACK_SORT  = 0o0200000
OUT_DATA_PACKETS     = 0o0400000
OUT_DATA_BYTES       = 0o1000000
OUT_DATA_EXTEND_01   = 0o2000000
OUT_DATA_DEFAULT     = OUT_DATA_TRACK_SORT
# Output Format - Value Style
# 111|1 00|00 0|000| 000|0 00|00 0|000
OUT_FORMAT_MASK        = 0o74000000  # Bits 20-23
OUT_FORMAT_USE_DEFAULT = 0o00000000
OUT_FORMAT_TSV_HUMAN   = 0o04000000
OUT_FORMAT_TSV_SIMPLE  = 0o10000000
OUT_FORMAT_CSV         = 0o14000000
OUT_FORMAT_EXTEND_01   = 0o74000000
OUT_FORMAT_DEFAULT     = OUT_FORMAT_TSV_HUMAN


# Declare Required Variables (Mutables)
cfgGlobal = {}


# Enumerations

class Subcommand(enum.Enum) :
	"""
	Enumeration of subcommands.
	"""
	UNKNOWN = "unknown"
	GROUP   = "group"
	HELP    = "help"
	ORDER   = "order"
	SORT    = "sort"
	# Aliases


class SPLTcsv(enum.Enum) :
	"""
	Enumeration of Sequence of Packet Length and Timing CSV field indexes, 0 basis indexing.
	"""

	frame    = 0  # Frame number of packet
	relTime  = 1  # Arrival time of packet, relative to start of capture file
	srcAddr  = 2  # Source address of packet, highest layer address between Data Link and Network layers
	destAddr = 3  # Destination address of packet, highest layer address between Data Link and Network layers
	srcPort  = 4  # Source port of packet, Transport layer
	destPort = 5  # Destination port of packet, Transport layer
	protocol = 6  # Protocol of packet, highest layer protocol between Data Link and Application layers
	length   = 7  # Length of packet in bytes, excludes Data Link layer frame synchronization header and footer bytes
	info     = 8  # Summary information of packet


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
		self.ID       = None
		self.relTime  = 0
		self.srcAddr  = None
		self.destAddr = None
		self.srcPort  = None
		self.destPort = None
		self.proto    = None
		self.bytes    = 0


	def __str__(
			self
		) :
		"""
		Description: CSV representation of RawPacket.
		"""
		return self.toCSV()


	def fromCSV(
			self
			, lineCSV
		) :
		"""
		Description: Populate RawPacket from CSV representation, CSV field indexing per SPLTcsv enumeration.
		Arguments:
			lineCSV : Single line packet fields in CSV format
		"""
		try :
			fields = lineCSV.split(",")
		except :
			raise
		self.ID       = fields[SPLTcsv.frame.value].strip('"')
		self.relTime  = float( fields[SPLTcsv.relTime.value].strip('"') )
		self.srcAddr  = fields[SPLTcsv.srcAddr.value].strip('"')
		self.destAddr = fields[SPLTcsv.destAddr.value].strip('"')
		self.srcPort  = fields[SPLTcsv.srcPort.value].strip('"')
		self.destPort = fields[SPLTcsv.destPort.value].strip('"')
		self.proto    = fields[SPLTcsv.protocol.value].strip('"')
		self.bytes    = int( fields[SPLTcsv.length.value].strip('"') )
		self.info     = fields[SPLTcsv.info.value].strip('"')


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
			4 : Source port
			5 : Destination port
			6 : Protocol, highest identified protocol in network stack
			7 : Packet size in bytes
			8 : Information
		"""
		packetCSV = str(self.ID) + "," + str(self.relTime) \
		            + "," + str(self.srcAddr) + "," + str(self.destAddr) \
		            + "," + str(self.srcPort) + "," + str(self.destPort) \
		            + "," + str(self.proto) + "," + str(self.bytes) \
		            + "," + str(self.info)
		return packetCSV


class ProcPacket :
	"""
	Description: Data object for processed packets based on grouping, counting, and ordering mode processed from a RawPacket.
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
			modeGroup = cfgGlobal["mode"] & GROUP_BY_MASK
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
		"""
		Description: Return equality Boolean based on Sort Mode.
		"""
		modeSort = cfgGlobal["mode"] & SORT_MASK
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
		"""
		Description: Return greater than or equality Boolean based on Sort Mode.
		"""
		modeSort = cfgGlobal["mode"] & SORT_MASK
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
		"""
		Description: Return greater than Boolean based on Sort Mode.
		"""
		modeSort = cfgGlobal["mode"] & SORT_MASK
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
		"""
		Description: Return less than or equality Boolean based on Sort Mode.
		"""
		modeSort = cfgGlobal["mode"] & SORT_MASK
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
		"""
		Description: Return less than Boolean based on Sort Mode.
		"""
		modeSort = cfgGlobal["mode"] & SORT_MASK
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
		"""
		Description: CSV representation of ProcPacket.
		"""
		strPacket = str(self.group) + "," + str(self.count) + "," + str(self.bytes)
		return strPacket


class ProcPackets :
	"""
	Description: Container for ProcPacket objects.
	"""


	def __init__(
			self
			, file = None
			, format = IN_FORMAT_USE_DEFAULT
		) :
		"""
		Description: Initialize an empty packet container, or with specified data from file per format.
		Design philosophy, container attributes should be internally managed, not directly manipulated by external code.
		Arguments:
			file : Name of input file, or file object of raw packets
			format : Format of file
		"""
		self.__rawPackets = []
		self.__procPackets = {}
		self.__resultPackets = []
		if file is not None :
			self.appendPackets(file, format)


	def appendPackets(
			self
			, file
			, format = IN_FORMAT_USE_DEFAULT
		) :
		"""
		Description: Append raw packets from file per format to current raw packets container.
		Arguments:
			file : Name of input file, or file object of raw packets
			format : Format of file
		"""
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
		if (formatIn & IN_FORMAT_CSV_HEADER) or (formatIn & IN_FORMAT_CSV_NO_HEADER) :
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
		Description: Lowest level API; process RawPackets based on mode or cfgGlobal["mode"] if None.
		Arguments:
			mode : Mode to group, count, and order RawPackets per.
		Returns:
			[list] : List of ProcPacket objects grouped and ordered, each ProcPacket has count and bytes data.
		"""
		if mode is not None :
			combinedMasks = GROUP_BY_MASK | SORT_MASK | ORDER_MASK
			cfgGlobal["mode"] = (combinedMasks & mode) | (cfgGlobal["mode"] & ~combinedMasks)
		self.__processGroupBy()
		self.__resultPackets = list(self.__procPackets.values())
		self.__resultPackets.sort()
		# Reverse order if needed
		orderMode = cfgGlobal["mode"] & ORDER_MASK
		if orderMode == ORDER_NUM_HIGH :
			self.__resultPackets.reverse()
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
		if orderMode is not None :
			procOrderMode = orderMode & ORDER_MASK
		else :
			procOrderMode = cfgGlobal["mode"] & ORDER_MASK
		procMode = procOrderMode | GROUP_BY_CONNECT | SORT_BYTES
		return self.processPerMode(procMode)


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
		if orderMode is not None :
			procOrderMode = orderMode & ORDER_MASK
		else :
			procOrderMode = cfgGlobal["mode"] & ORDER_MASK
		procMode = procOrderMode | GROUP_BY_CONNECT | SORT_PACKETS
		return self.processPerMode(procMode)


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
		if orderMode is not None :
			procOrderMode = orderMode & ORDER_MASK
		else :
			procOrderMode = cfgGlobal["mode"] & ORDER_MASK
		procMode = procOrderMode | GROUP_BY_DEST_ADDR | SORT_BYTES
		return self.processPerMode(procMode)


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
		if orderMode is not None :
			procOrderMode = orderMode & ORDER_MASK
		else :
			procOrderMode = cfgGlobal["mode"] & ORDER_MASK
		procMode = procOrderMode | GROUP_BY_DEST_ADDR | SORT_PACKETS
		return self.processPerMode(procMode)


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
		if orderMode is not None :
			procOrderMode = orderMode & ORDER_MASK
		else :
			procOrderMode = cfgGlobal["mode"] & ORDER_MASK
		procMode = procOrderMode | GROUP_BY_PROTO | SORT_BYTES
		return self.processPerMode(procMode)


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
		if orderMode is not None :
			procOrderMode = orderMode & ORDER_MASK
		else :
			procOrderMode = cfgGlobal["mode"] & ORDER_MASK
		procMode = procOrderMode | GROUP_BY_PROTO | SORT_PACKETS
		return self.processPerMode(procMode)


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
		if orderMode is not None :
			procOrderMode = orderMode & ORDER_MASK
		else :
			procOrderMode = cfgGlobal["mode"] & ORDER_MASK
		procMode = procOrderMode | GROUP_BY_SRC_ADDR | SORT_BYTES
		return self.processPerMode(procMode)


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
			procOrderMode = orderMode & ORDER_MASK
		else :
			procOrderMode = cfgGlobal["mode"] & ORDER_MASK
		procMode = procOrderMode | GROUP_BY_SRC_ADDR | SORT_PACKETS
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
		argv = None
	) :
	"""
	Main program control flow.

	:param argv: Argument vector, same format as sys.argv.
	:type argv: list[str]

	:return: None
	:rtype: none
	"""
	# Set Up Environment
	configureDefaults()
	cmdArgv = useArgv(argv)
	# Prepare for processing
	inputFilenames = processArgv(cmdArgv.copy())
	# Process input data
	networkMetadata = ProcPackets()
	for inputFilename in inputFilenames :
		networkMetadata.appendPackets(inputFilename)
	# Create ProcPackets
	results = networkMetadata.processPerMode()
	# Output Results
	outputResults(results)


def usage(
	) :
	"""
	Display usage statement and exit.

	:return: None
	:rtype: none
	"""
	# Core actions
	print(__doc__)


def configureDefaults(
	) :
	"""
	Assign default configuration to config.

	:param cfgGlobal:
	"""
	cfgGlobal["mode"] = \
	    GROUP_BY_USE_DEFAULT \
	  | SORT_USE_DEFAULT \
	  | ORDER_USE_DEFAULT \
	  | IN_FORMAT_USE_DEFAULT \
	  | OUT_DATA_USE_DEFAULT \
	  | OUT_FORMAT_USE_DEFAULT


def useArgv(
		argv
	) :
	"""
	Derive and return argv to use (passed in argv or sys.argv) based on argv.

	:param argv: Argument vector to use for derivation.
	:type argv: list[str] or none

	:return: Derived argument vector.
	:rtype: list[str]
	"""
	# Core actions
	returnArgv = argv if argv is not None else sys.argv
	return returnArgv


def processArgv(
		argv
	) :
	"""
	Description:
	Arguments:
		argv : Command line arguments, expect same format as sys.argv.
	Return:
		[list] : List of input filenames.
	"""
	# Set up working set
	parserState = {}
	parserState['command'] = None
	filenames = []
	skipIt = False
	for token in argv[1:] :
		if skipIt :
			skipIt = False
			parserState['command'] = None
			continue
		if knownSubcommand(token) :
			processCommand(parserState, token)
		else :
			processCommand(parserState, None, token)
		if token == "group" :  # Argument: Subcommand: group
			if i < len(argv) - 1 :
				saveCurrMode = cfgGlobal["mode"] & ~ GROUP_BY_MASK
				groupByStr = argv[i+1]
				if groupByStr == "src" :
					newGroupMode = GROUP_BY_SRC_ADDR
				elif groupByStr == "dest" :
					newGroupMode = GROUP_BY_DEST_ADDR
				elif groupByStr == "connect" :
					newGroupMode = GROUP_BY_CONNECT
				elif groupByStr == "proto" :
					newGroupMode = GROUP_BY_PROTO
				else :
					sys.exit("(netSort) ERROR: Improper 'group' Usage, see 'help'.")
				cfgGlobal["mode"] = saveCurrMode | newGroupMode
			else :
				sys.exit("(netSort) ERROR: Improper 'group' Usage, see 'help'.")
			skipIt = True
		elif token == "sort" :  # Argument: Subcommand: sort
			if i < len(argv) - 1 :
				saveCurrMode = cfgGlobal["mode"] & ~ SORT_MASK
				sortStr = argv[i+1]
				if sortStr == "packets" :
					newSortMode = SORT_PACKETS
				elif sortStr == "bytes" :
					newSortMode = SORT_BYTES
				else :
					sys.exit("(netSort) ERROR: Improper 'sort' Usage, see 'help'.")
				cfgGlobal["mode"] = saveCurrMode | newSortMode
			else :
				sys.exit("(netSort) ERROR: Improper 'sort' Usage, see 'help'.")
			skipIt = True
		elif token == "order" :  # Argument: Sub-command: order
			if i < len(argv) - 1 :
				saveCurrMode = cfgGlobal["mode"] & ~ ORDER_MASK
				orderStr = argv[i+1]
				if orderStr == "low" :
					newOrderMode = ORDER_NUM_LOW
				elif orderStr == "high" :
					newOrderMode = ORDER_NUM_HIGH
				else :
					sys.exit("(netOrder) ERROR: Improper 'order' Usage, see 'help'.")
				cfgGlobal["mode"] = saveCurrMode | newOrderMode
			else :
				sys.exit("(netOrder) ERROR: Improper 'order' Usage, see 'help'.")
			skipIt = True
		else :  # Argument: Input filename
			filenames.append(argv[i])
	return filenames.copy()


def knownSubcommand(
		term
	) :
	"""
	Determine if term is a known subcommand or not.

	:param term: Value to test.
	:type term: any

	:return: True if term is a known subcommand, otherwise False.
	:rtype: bool
	"""
	# Set up working set
	...
	# Core actions
	derivedSubcommand = deriveSubcommand(term)
	isSubcommand = True if derivedSubcommand is not Subcommand.UNKNOWN else False
	return isSubcommand


def deriveSubcommand(
		hint
	) :
	"""
	Derive subcommand from hint.

	:param hint: ...
	:type hint: str of

	:return: Derived subcommand.
	:rtype: Subcommand
	"""
	# Set up working set
	helpSubcommandHints  = {"help" , "HELP" , Subcommand.HELP }
	groupSubcommandHints = {"group", "GROUP", Subcommand.GROUP}
	orderSubcommandHints = {"order", "ORDER", Subcommand.ORDER}
	sortSubcommandHints  = {"sort" , "SORT" , Subcommand.SORT }
	derivedSubcommand = Subcommand.UNKNOWN
	# Core actions
	if   hint in helpSubcommandHints  :
		derivedSubcommand = Subcommand.HELP
	elif hint in groupSubcommandHints :
		derivedSubcommand = Subcommand.GROUP
	elif hint in orderSubcommandHints :
		derivedSubcommand = Subcommand.ORDER
	elif hint in sortSubcommandHints  :
		derivedSubcommand = Subcommand.SORT
	return derivedSubcommand


def processCommand(
		parserState
		, command
		, argument = None
	) :
	"""
	Description: Process command.
	Arguments:
		parserState : State of parser
		command : Command to process
		argument : Argument to command
	"""
	# Set up working set
	commandTriggersOnArg = {
	    # "as"
	#   , "from"
	    "group"
	  , "order"
	  , "sort"
	#   , "to"
	}
	# Core actions
	if parserState['command'] :  # Already processing a command, treat as argument
		actOnCommand(parserState, parserState['command'], argument)
	else :
		if command in commandTriggersOnArg :
			parserState['command'] = command
		else :
			actOnCommand(parserState, command)


def processArgument(
		  parserState
		, argument
		, config
	) :
	"""
	Process argument based on parserState and config.

	:param parserState: Current state of parser.
	:type parserState: dict

	:param argument: Argument being processed.
	:type argument: str

	:param config: Program configuration settings.
	:type config: dict
	"""
	# Set up working set
	...
	# Core actions
	...


def actOnCommand(
		parserState
		, command
		, argument = None
	) :
	"""
	Description: Perform action based on command.
	Arguments:
		parserState : State of parser
		command : Command to act on
		argument : Argument to command
	"""
	# Set up working set
	...
	# Core actions
	parserState['command'] = None  # Default: consume command
	if command == "help" :
		usage()
		sys.exit()
	else :
		...


def outputResults(
		results
		, file = sys.stdout
		, mode = None
	) :
	"""
	Description: ...
	"""
	if mode is not None :
		outDataMode = mode & OUT_DATA_MASK
		sortMode = mode & SORT_MASK
	else :
		outDataMode = cfgGlobal["mode"] & OUT_DATA_MASK
		sortMode = cfgGlobal["mode"] & SORT_MASK
	if outDataMode == OUT_DATA_USE_DEFAULT :
		outDataMode = OUT_DATA_DEFAULT
	if outDataMode == OUT_DATA_TRACK_SORT :
		if sortMode == SORT_USE_DEFAULT :
			sortMode = SORT_DEFAULT
		if sortMode == SORT_PACKETS :
			outDataMode = OUT_DATA_PACKETS
		elif sortMode == SORT_BYTES :
			outDataMode = OUT_DATA_BYTES
		elif sortMode == SORT_EXTEND_01 :
			...
	for resultProcPacket in results :
		outData = str(resultProcPacket.group) + "\t"
		if outDataMode == OUT_DATA_PACKETS :
			outData += str(resultProcPacket.count)
		elif outDataMode == OUT_DATA_BYTES :
			outData += str(resultProcPacket.bytes)
		print(outData, file=file)


configureDefaults()
if __name__ == "__main__" :  # Called as standalone program
	main()
