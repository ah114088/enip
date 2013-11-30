#!/usr/bin/ruby

require 'enip.rb'

INPUT_ASSEMBLY_NUM                = 100
OUTPUT_ASSEMBLY_NUM               = 150
CONFIG_ASSEMBLY_NUM               = 151
HEARBEAT_INPUT_ONLY_ASSEMBLY_NUM  = 152
HEARBEAT_LISTEN_ONLY_ASSEMBLY_NUM = 153

INPUT_ASSEMBLY_SIZE               = 32
OUTPUT_ASSEMBLY_SIZE              = 32

class ExclusiveOwnerConnection < ENIP::ExclusiveOwnerConnection
	def initialize session, ip_addr, rpi, timeout_multiplier, unicast
		super(session, ip_addr, rpi, timeout_multiplier, unicast, 
					INPUT_ASSEMBLY_SIZE, OUTPUT_ASSEMBLY_SIZE, 
					INPUT_ASSEMBLY_NUM, OUTPUT_ASSEMBLY_NUM, CONFIG_ASSEMBLY_NUM)
	end
end

class InputOnlyConnection < ENIP::InputOnlyConnection
	def initialize session, ip_addr, rpi, timeout_multiplier, unicast
		super(session, ip_addr, rpi, timeout_multiplier, unicast, 
					INPUT_ASSEMBLY_SIZE, INPUT_ASSEMBLY_NUM, 
				HEARBEAT_INPUT_ONLY_ASSEMBLY_NUM, CONFIG_ASSEMBLY_NUM)
	end
end

class ListenOnlyConnection < ENIP::ListenOnlyConnection
	def initialize session, ip_addr, rpi, timeout_multiplier
		super(session, ip_addr, rpi, timeout_multiplier,
					INPUT_ASSEMBLY_SIZE, INPUT_ASSEMBLY_NUM, 
				HEARBEAT_LISTEN_ONLY_ASSEMBLY_NUM, CONFIG_ASSEMBLY_NUM)
	end
end

# ------------------------------------------------------------

if ARGV.length != 1
	puts "usage: opener.rb <device_ip>" 
	exit 1
end
device_ip = ARGV[0]

# ------------------------------------------------------------
Kernel.srand
ENIP.vendor_id = 1323
ENIP.serial_number = rand * 10000
ENIP.block_io = false 

# 
# UDP operations
#
udp_socket = ENIP::UDPSocket.open
udp_socket.identity(device_ip)[0].print
udp_socket.services(device_ip)[0].print
udp_socket.interfaces(device_ip)[0].print

# 
# TCP operations
#
socket = ENIP::TCPSocket.open device_ip
socket.nop
socket.identity.print
socket.services.print
socket.interfaces.print

# 
# Session operations
#
session = ENIP::Session.new socket

#
# reset the device
#
session.identity[1].reset 0

#
# Exclpicit Messaging operations
#
puts session.assembly[INPUT_ASSEMBLY_NUM].read.unpack("H*")
session.assembly[OUTPUT_ASSEMBLY_NUM].write ENIP::BinString.new(OUTPUT_ASSEMBLY_SIZE)
	
# 
# Identity object attributes
#
ident = session.identity[1]
puts "vendor_id: #{ident.vendor_id}"
puts "device_type: #{ident.device_type}"
puts "product code: #{ident.product_code}"
puts "revision: #{ident.revision}"
puts "status: #{ident.status}"
puts "serial_number: #{ident.serial_number}"
puts "product_name: #{ident.product_name}"

# 
# TCP/IP Interface object attributes
#
t = session.tcpip_interface[1]
puts "status: #{t.status}"
puts "configuration capabilities: #{t.configuration_capabilities}"
puts "configuration control: #{t.configuration_control}"
puts "physical link: #{t.physical_link}"
puts "confguration: #{t.configuration}"
puts "hostname: #{t.hostname}"

# 
# TCP/IP Interface class attributes
#
tc = session.tcpip_interface
puts "revision: #{tc.revision}"
puts "max_instance: #{tc.max_instance}"
puts "number_instances: #{tc.number_instances}"

# 
# Ethernet Link object attributes
#
puts "speed #{session.ethernet_link[1].interface_speed}"
puts "flags: #{session.ethernet_link[1].interface_flags}"
puts "mac address: #{session.ethernet_link[1].physical_address}"

cm = ENIP::ConnectionMultiplexer.new

rpi = 100 # 100 ms
ucast = false # multicast

# 
# Input Only CIP connection
#
puts "Start input only connection"
cm << c1 = InputOnlyConnection.new(session, device_ip, rpi, 3, true)
cm.run(1)
puts "Quit input only connection"
cm.delete c1

# 
# Exclusive Owner CIP connection
#
puts "Start exclusive owner connection"
cm << c = ExclusiveOwnerConnection.new(session, device_ip, rpi, 3, false)
cm.run(0.5)

c.run = true
cm.run(0.5)

# 
# Listen Only CIP connection
#
puts "Start listen only connection"
cm << c2 = ListenOnlyConnection.new(session, device_ip, rpi, 3)
cm.run(1)
puts "Quit listen only connection"
cm.delete c2

cm.run(1)
cm.delete c
puts "Quit exclusive owner connection"

session.close
socket.close

exit 0
