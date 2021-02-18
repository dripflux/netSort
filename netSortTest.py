#!/usr/bin/env python3

"""
NAME
	netSortTest - Unit tests for Network Traffic Sorter (netSort).

SYNOPSIS
	netSortTest
	(FUTURE) netSortTest [component_to_test]...

DESCRIPTION
	Run unit tests for netSort.
	Without arguments perform all unit tests.
	(FUTURE) If arguments, then only perform categorical unit tests per below.

	raw : Test RawPacket class
"""

# Required imports
import sys       # System Module: argv
import unittest  # Unit Test Module: TestCase
import netSort   # Network Traffic Sorter Module: *

# Class Definitions

class RawPacketExistTestCase(
		unittest.TestCase
	) :
	"""
	Description: RawPacket class attribute and method exist test cases.
	"""

	def setUp(
			self
		) :
		"""
		Description: Common test case setup.
		"""
		self.emptyPacket = netSort.RawPacket()

	def testAttribute_ID(
			self
		) :
		"""
		Description: Test that 'ID' attribute exists in RawPacket.
		"""
		self.assertIn("ID", dir(self.emptyPacket))

	def testAttribute_relTime(
			self
		) :
		"""
		Description: Test that 'relTime' attribute exists in RawPacket.
		"""
		self.assertIn("relTime", dir(self.emptyPacket))

	def testAttribute_srcAddr(
			self
		) :
		"""
		Description: Test that 'srcAddr' attribute exists in RawPacket.
		"""
		self.assertIn("srcAddr", dir(self.emptyPacket))

	def testAttribute_destAddr(
			self
		) :
		"""
		Description: Test that 'destAddr' attribute exists in RawPacket.
		"""
		self.assertIn("destAddr", dir(self.emptyPacket))

	def testAttribute_proto(
			self
		) :
		"""
		Description: Test that 'proto' attribute exists in RawPacket.
		"""
		self.assertIn("proto", dir(self.emptyPacket))

	def testAttribute_bytes(
			self
		) :
		"""
		Description: Test that 'bytes' attribute exists in RawPacket.
		"""
		self.assertIn("bytes", dir(self.emptyPacket))

	def testMethod_fromCSV(
			self
		) :
		"""
		Description: Test that 'fromCSV' attribute exists in RawPacket.
		"""
		self.assertIn("fromCSV", dir(self.emptyPacket))

	def testMethod_toCSV(
			self
		) :
		"""
		Description: Test that 'toCSV' attribute exists in RawPacket.
		"""
		self.assertIn("toCSV", dir(self.emptyPacket))

class RawPacketEmptyTestCase(
		unittest.TestCase
	) :
	"""
	Description: Test new RawPacket instance empty status.
	"""

	def setUp(
			self
		) :
		"""
		Description: Common test case setup.
		"""
		self.emptyPacket = netSort.RawPacket()

	def testAttribute_ID(
			self
		) :
		"""
		Description: Test that 'ID' attribute is None for new RawPacket instance.
		"""
		self.assertIsNone(self.emptyPacket.ID)

	def testAttribute_relTime(
			self
		) :
		"""
		Description: Test that 'relTime' attribute equals 0 for new RawPacket instance.
		"""
		self.assertEqual(self.emptyPacket.relTime, 0)

	def testAttribute_srcAddr(
			self
		) :
		"""
		Description: Test that 'srcAddr' attribute is None for new RawPacket instance.
		"""
		self.assertIsNone(self.emptyPacket.srcAddr)

	def testAttribute_destAddr(
			self
		) :
		"""
		Description: Test that 'destAddr' attribute is None for new RawPacket instance.
		"""
		self.assertIsNone(self.emptyPacket.destAddr)

	def testAttribute_proto(
			self
		) :
		"""
		Description: Test that 'proto' attribute is None for new RawPacket instance.
		"""
		self.assertIsNone(self.emptyPacket.proto)

	def testAttribute_bytes(
			self
		) :
		"""
		Description: Test that 'bytes' attribute equals 0 for new RawPacket instance.
		"""
		self.assertEqual(self.emptyPacket.bytes, 0)

class RawPacketExpectFailTestCase(
		unittest.TestCase
	) :
	"""
	Description: RawPacket test cases expected to fail.
	"""

	def setUp(
			self
		) :
		"""
		Description: Common test case setup.
		"""
		...

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
		argv = sys.argv.copy()
	else :
		argv = cmdArgv
	# Test Components
	unittest.main()
	...

# Function Definitions

if __name__ == "__main__" :  # Called as standalone program
	main()
