#!/usr/bin/python3
#(C) 2018 Peter Michael Green <plugwash@debian.org>
#This software is provided 'as-is', without any express or implied warranty. In
#no event will the authors be held liable for any damages arising from the use
#of this software.
#
#Permission is granted to anyone to use this software for any purpose, including
#commercial applications, and to alter it and redistribute it freely, subject to
#the following restrictions:
#
#1. The origin of this software must not be misrepresented; you must not claim.
#that you wrote the original software. If you use this software in a product,
#an acknowledgment in the product documentation would be appreciated but is.
#not required.
#
#2. Altered source versions must be plainly marked as such, and must not be
#misrepresented as being the original software.
#
#3. This notice may not be removed or altered from any source distribution

#This program finds the inverse of a list of ip ranges and/or cidr blocks.
#
#Each command line parameter specifies either an individual ip (e.g. 10.0.0.0)
#, a range of ips (e.g. 10.0.0.0-10.1.2.3) or a cidr block (e.g. 10.0.0.0/8)
#
#All ranges/blocks should be of the same version (either v4 or v6 but not a 
#mixture)
#
#First the input is converted to a sorted list of non-overlapping ranges
#Then the list of ranges is inverted
#Finally the ranges are converted to cidr blocks.
#
#The outputs of all three stages are printed to standard output.

from ipaddress import ip_network
from ipaddress import ip_address
import sys

inputlist = sys.argv[1:]
#inputlist = ["9.0.0.0/12","9.0.0.0/8","9.0.0.0/16","10.0.0.0/8","11.0.0.0/8","192.168.0.0/16","172.16.0.0/12"]
#inputlist = ["2000::/3","5000::-6000::"]

rangelist = []
for inputitem in inputlist:
	if "-" in inputitem:
		start,end = inputitem.split('-')
		start = ip_address(start)
		end = ip_address(end)
		if (end < start):
			raise ValueError("range end must not be less than range start")
	else:
		network = ip_network(inputitem)
		start = network.network_address
		#ipv6 doesn't actually have broadcast addresses but nevertheless python
		#still seems to use "broadcast_address" to get the last address in a network.
		end = network.broadcast_address
	rangelist.append((start,end))

rangelist.sort()
currentstart = None
currentend = None
cleanrangelist = []
#since we sorted the list, new ranges can only overlap the end of the current
#range, not the start of it.
for (newstart,newend) in rangelist:
	#print("processing "+str(newstart)+"-"+str(newend))
	if currentstart is None:
		currentstart = newstart
		currentend = newend
	else:
		if (int(newstart) - int(currentend)) > 1:
			#print("ranges do not overlap or abut")
			cleanrangelist.append((currentstart,currentend))
			currentstart = newstart
			currentend = newend
		else:
			#print("ranges overlap or abut")
			currentend = max(currentend,newend)

#this will fail on empty lists, but we don't care.
cleanrangelist.append((currentstart,currentend))

print("input converted to a sorted list of non-overlapping ranges")
for start,end in cleanrangelist:
	print(str(start)+'-'+str(end))
print()

ipversion = cleanrangelist[0][0].version
if (ipversion == 4):
	ipzero = ip_address("0.0.0.0")
	ipmax = ip_address("255.255.255.255")
	addrbits = 32
else:
	ipzero = ip_address("::")
	ipmax = ip_address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	addrbits = 128

inverserangelist = []
prevrangeep1 = ipzero
for rangestart,rangeend in cleanrangelist:
	if prevrangeep1 != rangestart:
		inverserangelist.append((prevrangeep1,rangestart-1))
	if rangeend != ipmax:
		prevrangeep1 = rangeend + 1
	else:
		prevrangeep1 = None

if prevrangeep1 is not None:
	inverserangelist.append((prevrangeep1,ipmax))

print("inverted range list ("+str(len(inverserangelist))+" entries)")
for (start,end) in inverserangelist:
	print(str(start)+'-'+str(end))
print()

#print(inverserangelist)

def counttrailingbinzeros(value, maxzeros):
	result = 0
	bit = 1
	while (result < maxzeros) and ((value & bit) == 0):
		result += 1
		bit <<= 1
	return result

#print(repr(int(ipmax)))

results = []
for (start,end) in inverserangelist:
	length = int(end) - int(start) + 1
	#print(repr(length))
	while length > 0:
		starttrailingzeros = counttrailingbinzeros(int(start),addrbits)
		maxinvmaskforlength = length.bit_length() -1
		#print(repr(starttrailingzeros))
		#print(repr(maxinvmaskforlength))
		invmask = min(starttrailingzeros,maxinvmaskforlength)
		mask = addrbits - invmask 
		#print("start="+str(start)+" mask="+str(mask))
		result = ip_network((start,mask))
		results.append(result)
		cidrlen = 1 << invmask
		length -= cidrlen
		if length > 0:
			#we need a conditional here because otherwise we can
			#overflow the end of the address range
			start += cidrlen

print("inverse in cidr blocks ("+str(len(results))+" entries)")
for result in results:
	print(str(result))

#print(repr(ipnetworklist))
