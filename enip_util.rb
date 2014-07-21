#!/usr/bin/ruby

require 'socket'
require 'enip'

INPUT_ASSEMBLY = 100 # 0x64
OUTPUT_ASSEMBLY = 150 # 0x96
CONFIG_ASSEMBLY = 151 # 0x97
INPUT_ONLY_HEARTBEAT_ASSEMBLY = 152 # 0x98
LISTEN_ONLY_HEARTBEAT_ASSEMBLY = 153 # 0x99

def parse_unicast arg
	return true if arg == "unicast"
	return false if arg == "multicast"
	usage
end

def usage
	puts "usage: enip_util.rb <options> <parameter>" 
	puts 
	puts "options:"
	puts "\t-identity <network_addr>|<ip_addr>"
	puts "\t-services <network_addr>|<ip_addr>"
	puts "\t-interfaces <network_addr>|<ip_addr>"

	puts "\t-cip_ethernet_link <ip_addr> <instance>"

	puts "\t-assembly_size <ip_addr> <instance_number>"
	puts "\t-assembly_data <ip_addr> <instance_number>"

	puts "\t-exclusive_owner <ip_addr> <subnet_mask> <unicast|multicast> <rpi_msec>"
	puts "\t-input_only <ip_addr> <subnet_mask> <unicast|multicast> <rpi_msec>"
	puts "\t-listen_only <ip_addr> <subnet_mask> <rpi_msec>"
	exit 1
end

def param_length n
	if ARGV.length < n
		puts "not enough parameters" 
		exit 1
	end
end

#
# --- main ------------------
#

usage if ARGV.length < 1
	
Kernel.srand
ENIP.serial_number = rand() * 10000
ENIP.vendor_id = 1323      # Systeme Helmholz GmbH Vendor ID

case ARGV[0]
when "-identity"
	param_length 2
	socket = ENIP::UDPSocket.open
	socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, true)
	socket.identity(ARGV[1]).each { |item| item.print }

when "-services"
	param_length 2
	socket = ENIP::UDPSocket.open
	socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, true)
	socket.services(ARGV[1]).each { |item| item.print }

when "-interfaces"
	param_length 2
	socket = ENIP::UDPSocket.open
	socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, true)
	socket.interfaces(ARGV[1]).each { |item| item.print }

when "-cip_ethernet_link"
  param_length 3
  session = ENIP::Session.new ENIP::TCPSocket.open ARGV[1]
	link = session.ethernet_link[ARGV[2].to_i]
	puts "  Interace Speed: #{link.interface_speed}"
	puts "  Interface Flags: #{link.interface_flags}"
	puts "  Physical Address: #{link.physical_address}"

when "-assembly_size"
	param_length 3
	ip = ARGV[1]
	instance_nr =	ARGV[2].to_i
	socket = ENIP::TCPSocket.new ip
	session = ENIP::Session.new socket

	size = session.assembly[instance_nr].size
	puts "Size of assembly #{instance_nr} at #{ip}: #{size}"

when "-assembly_data"
	param_length 3
	ip = ARGV[1]
	instance_nr =	ARGV[2].to_i
	socket = ENIP::TCPSocket.new ip
	session = ENIP::Session.new socket

  data = session.assembly[instance_nr].read
	puts "#{data.unpack("H*")[0]}"

when "-exclusive_owner"
	param_length 5
	ip = ARGV[1]
	nm = ARGV[2]
	unicast = parse_unicast ARGV[3]
	rpi = ARGV[4].to_i
	session = ENIP::Session.new ENIP::TCPSocket.new ip
	isz = session.assembly[INPUT_ASSEMBLY].size
	osz = session.assembly[OUTPUT_ASSEMBLY].size
	cm = ENIP::ConnectionManager.new
	c = ENIP::ExclusiveOwnerConnection.new session, ip, nm, rpi, 3, unicast, isz, osz, INPUT_ASSEMBLY, OUTPUT_ASSEMBLY, CONFIG_ASSEMBLY, nil
	c.run = true
	cm << c
	cm.forever

when "-input_only"
	param_length 5
	ip = ARGV[1]
	nm = ARGV[2]
	unicast = parse_unicast ARGV[3]
	rpi = ARGV[4].to_i
	session = ENIP::Session.new ENIP::TCPSocket.new ip
	isz = session.assembly[INPUT_ASSEMBLY].size
	cm = ENIP::ConnectionManager.new
	c = ENIP::InputOnlyConnection.new session, ip, nm, rpi, 3, unicast, isz, INPUT_ASSEMBLY, INPUT_ONLY_HEARTBEAT_ASSEMBLY, CONFIG_ASSEMBLY, nil
	cm << c
	cm.forever

when "-listen_only"
	param_length 4
	ip = ARGV[1]
	nm = ARGV[2]
	rpi = ARGV[3].to_i
	session = ENIP::Session.new ENIP::TCPSocket.new ip
	isz = session.assembly[INPUT_ASSEMBLY].size
	cm = ENIP::ConnectionManager.new
	c = ENIP::ListenOnlyConnection.new session, ip, nm, rpi, 3, isz, INPUT_ASSEMBLY, LISTEN_ONLY_HEARTBEAT_ASSEMBLY, CONFIG_ASSEMBLY, nil
	cm << c
	cm.forever

else 
  puts "unknwon option >#{ARGV[0]}<"
	exit 1
end
