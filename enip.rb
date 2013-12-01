#!/usr/bin/ruby

#
# Ruby module for EtherNet/IP
#
# Supports:
# - UDP socket operations
# - TCP socket operations
# - Query operations for class/object attributes
# - Explicit Messaging operations
# - Implicit Messaging operations (class 1)

require 'socket'
require 'ipaddr'

module ENIP
  IMPLICIT_MESSAGING_PORT = 0x08AE # 2222
  EXPLICIT_MESSAGING_PORT = 0xAF12 # 44818

  # module global variables
  module_function
  def block_io; @block_io end
  def block_io= v; @block_io = v end
  def vendor_id; @vendor_id end
  def vendor_id= v; @vendor_id = v end
  def serial_number; @serial_number end
  def serial_number= s; @serial_number = s end

  def get_new_connection_serial_number 
    if @csn.nil?
      @csn = 1 
    else
      @csn += 1 
    end 
    return @csn
  end

  # general error code constants
  CIP_ERROR_SUCCESS                  = 0x00
  CIP_ERROR_CONNECTION_FAILURE       = 0x01
  CIP_ERROR_PATH_DESTINATION_UNKNOWN = 0x05
  CIP_ERROR_PATH_SEGMENT_ERROR       = 0x04
  CIP_ERROR_SERVICE_NOT_SUPPORTED    = 0x08
  CIP_ERROR_ATTRIBUTE_NOT_SETTABLE   = 0x0E
  CIP_ERROR_DEVICE_STATE_CONFLICT    = 0x10
  CIP_ERROR_NOT_ENOUGH_DATA          = 0x13
  CIP_ERROR_ATTRIBUTE_NOT_SUPPORTED  = 0x14 
  CIP_ERROR_TOO_MUCH_DATA            = 0x15 
  CIP_ERROR_OBJECT_DOES_NOT_EXIST    = 0x16 
  CIP_ERROR_INVALID_PARAMETER        = 0x20

  # extended status constants
  CIP_EXTENDED_STATUS_CONNECTION_IN_USE_OR_DUPLICATE_FORWARD_OPEN = 0x0100
  CIP_EXTENDED_STATUS_OWNERSHIP_CONFLICT                          = 0x0106
  CIP_EXTENDED_STATUS_TARGET_CONNECTION_NOT_FOUND                 = 0x0107
  CIP_EXTENDED_STATUS_INVALID_CONNECTION_SIZE                     = 0x0109
  CIP_EXTENDED_STATUS_INVALID_PATH                                = 0x0117
  CIP_EXTENDED_STATUS_NON_LISTEN_ONLY_CONNECTION_NOT_OPENED       = 0x0119

  # Encapsulation Protocol Command Constants  
  COMMAND_NOP                = 0x00
  COMMAND_LISTSERVICES       = 0x0004
  COMMAND_LISTIDENTITY       = 0x0063
  COMMAND_LISTINTERFACES     = 0x0064
  COMMAND_REGISTERSESSION    = 0x0065
  COMMAND_UNREGISTERSESSION  = 0x0066
  COMMAND_SENDRRDATA         = 0x006F
  COMMAND_SENDUNITDATA       = 0x0070
  COMMAND_INDICATESTATUS     = 0x0072
  COMMAND_CANCEL             = 0x0073
  
  # Common Packat Format Item Type IDs
  CPF_TYPE_NULL_ADDRESS       = 0x0000
  CPF_TYPE_CONNECTED_ADDRESS  = 0x00A1
  CPF_TYPE_SEQUENCED_ADDRESS  = 0x8002
  CPF_TYPE_SOCKADDR_O2T       = 0x8000
  CPF_TYPE_SOCKADDR_T2O       = 0x8001
  CPF_TYPE_CONNECTED_DATA     = 0x00B1
  CPF_TYPE_UNCONNECTED_DATA   = 0x00B2

  # CIP class constants
  CLASS_IDENTITY              = 0x0001
  CLASS_MESSAGE_ROUTER        = 0x0002
  CLASS_DEVICENET             = 0x0003
  CLASS_ASSEMBLY              = 0x0004
  CLASS_CONNECTION_MANAGER    = 0x0006
  CLASS_TCPIP_INTERFACE       = 0x00f5
  CLASS_ETHERNET_LINK         = 0x00f6

  # CIP service constants
  SERVICE_GET_ATTRIBUTES_ALL    = 0x01
  SERVICE_SET_ATTRIBUTES_ALL    = 0x02
  SERVICE_RESET                 = 0x05
  SERVICE_GET_ATTRIBUTE_SINGLE  = 0x0e
  SERVICE_SET_ATTRIBUTE_SINGLE  = 0x10
  SERVICE_FORWARD_CLOSE         = 0x4e
  SERVICE_FORWARD_OPEN          = 0x54
  SERVICE_GET_CONNECTION_OWNER  = 0x5a
  
  class CIPException < StandardError
    attr_reader :extended_status
    def initialize(msg, extended_status)
      super(msg)
      @extended_status = extended_status
    end
  end
  class ConnectionFailure < CIPException; end
  class PathDestinationUnknown < CIPException; end
  class PathSegmentError < CIPException; end
  class ServiceNotSupported < CIPException; end
  class AttributeNotSettable < CIPException; end
  class DeviceStateConflict < CIPException; end
  class NotEnoughData < CIPException; end
  class AttributeNotSupported < CIPException; end
  class TooMuchData < CIPException; end
  class ObjectDoesNotExist < CIPException; end
  class InvalidParameter < CIPException; end

  class EncapException < StandardError; end
  class EncapInvalidCommand < EncapException; end
  class EncapInsufficientMemory < EncapException; end
  class EncapIncorrectData < EncapException; end
  class EncapInvalidSessionHandle < EncapException; end
  class EncapInvalidLength < EncapException; end
  class EncapUnsupportedProtocol < EncapException; end

  class NotYetImplemented < CIPException; end

  # -------------------------------------------------------------

  class PackBuffer < String
    def eat(n)
      self[0..n-1] = ''
    end

    def put_val value, char
      self << [value].pack(char)
    end
    def put_byte v ; put_val(v, "C") end
    def put_usint v ; put_val(v, "C") end
    def put_uint v ; put_val(v, "v") end
    def put_word v ; put_val(v, "v") end
    def put_udint v ; put_val(v, "V") end
    def put_epath value
      put_usint value.length >> 1
      value.each { |c| put_byte c }
    end
    def put_sendrrdata data
      put_udint 0 # interface handle, shall be 0 for CIP
      put_uint 60 # timeout in seconds
      self << data if ! data.nil?
    end

    def get_val char, size
      val = self.unpack(char)[0]
      eat(size)
      val
    end
    def get_byte ; get_val("C", 1) end
    def get_usint ; get_val("C", 1) end
    def get_uint ; get_val("v", 2) end
    def get_word ; get_val("v", 2) end
    def get_int_be ; get_val("n", 2) end # big endian
    def get_uint_be ; get_val("n", 2) end # big endian
    def get_udint ; get_val("V", 4) end
    def get_dword ; get_val("V", 4) end
    def get_udint_be ; get_val("N", 4) end # big endian
    def get_socket_address
        sin_family = get_int_be
        sin_port = get_uint_be
        sin_addr = get_udint_be
        eat(8) # sin_zero
        val = [IPAddr.new(sin_addr, sin_family), sin_port]
    end
    def get_short_string
      len = get_usint
      val = self[0,len]
      eat(len)
      val
    end
    def get_string
      len = get_uint
      if len > 0
        val = self[0,len]
        eat(len)
      else
        val = ""
      end
      val
    end
    def get_mac_addr
      val = ""
      6.times { |i|
        val += "-" if i != 0 
        val += sprintf("%02X", get_usint)
      }
      val
    end
    def get_interface # Network interface configuration
      ip_addr = get_udint
      ip = IPAddr.new(ip_addr, Socket::AF_INET)
      val = "#{ip} "

      netmask = get_udint
      ip = IPAddr.new(netmask, Socket::AF_INET)
      val += "#{ip} "

      gateway = get_udint
      ip = IPAddr.new(gateway, Socket::AF_INET)
      val += "#{ip} "

      nameserver = get_udint
      ip = IPAddr.new(nameserver, Socket::AF_INET)
      val += "#{ip} "

      nameserver2 = get_udint
      ip = IPAddr.new(nameserver2, Socket::AF_INET)
      val += "#{ip} "

      domain = get_string
      val += "#{domain} "
      return val
    end
    def get_epath
      val = Epath.new
      psize = get_uint
      while psize > 0
        pident = get_usint
        case pident
        when 0x20 # 8 bit class ID
          class_id = get_usint
          psize -= 1
          val << pident
          val << class_id

        when 0x21 # 16 bit class ID
          eat(1) # pad byte
          class_id = get_uint
          psize -= 2
          val << pident
          val << class_id

        when 0x24 # 8 bit instance Nr
          instance_nr = get_usint
          psize -= 1
          val << pident
          val << instance_nr

        when 0x25 # 16 bit class ID
          eat(1) # pad byte
          instance_nr = get_uint
          psize -= 2
          val << pident
          val << instance_nr
        else
          puts "path identifier not yet implemented"
        end
      end
      val
    end
  end
  class Epath < Array
    def to_s
      s = ""
      self.each_with_index { |byte,i|
        s += " " if i != 0  
        s += sprintf("%02X", byte)
      }
      s
    end
  end

  def encapsulate command, session=0, data=nil
    request = PackBuffer.new
    request.put_uint command
    if data.nil?
      request.put_uint 0
    else
      request.put_uint data.length
    end
    request.put_udint session
    request.put_udint 0                           # status code
    8.times { request.put_byte 0 }                # sender context
    request.put_udint 0                           # options
    if ! data.nil?
      request << data
    end
    request
  end

  def decapsulate reply
    command = reply.get_uint
    length = reply.get_uint
    session = reply.get_udint
    status = reply.get_udint
    8.times { reply.get_byte }     # sender context
    options = reply.get_udint
    throw_encap_exception status
    [ command, length, session, options ]
  end

  # -------------------------------------------------------------

  class Identity
    attr_accessor :ip_address, :port
    def initialize(r)
      type = r.get_uint
      len = r.get_uint
      raise if type != 0x0C

      @version = r.get_uint
      sa = r.get_socket_address
      @ip_address = sa[0]
      @port = sa[1]
      @vendor_id = r.get_uint
      @device_type = r.get_uint
      @product_code = r.get_uint
      @revision_major = r.get_usint
      @revision_minor = r.get_usint
      @status = r.get_word
      @serial_number = r.get_udint
      @product_name = r.get_short_string
      @state = r.get_usint
    end
    def print
      puts "\tEncapsulation Protocol Version: #{@version}"
      puts "\tSocket Address: #{@ip_address}:#{@port}"
      puts "\tVendor ID: #{@vendor_id}"
      puts "\tDevice Type: #{@device_type}"
      puts "\tProduct Code: #{@product_code}"
      puts "\tRevision: #{@revision_major}.#{@revision_minor}"
      puts "\tStatus: #{@status}"
      puts "\tSerial Number: #{@serial_number}"
      puts "\tProduct Name: #{@product_name}"
      puts "\tState: #{@state}"
    end
  end

  class Service
    CAP_TCP = 0x0020
    CAP_UDP = 0x0100
    def initialize(r)
      type = 0
      version = 0
      cap = 0
      name = 0

      items = r.get_uint

      items.times {
        type     = r.get_uint
        len      = r.get_uint
        version  = r.get_uint
        cap      = r.get_uint
        name     = r[0, 16]
        r.eat(16)
      }

      if type == 0x100
        @capabilities = cap
      else
        raise "device has no communication service"
      end
    end
    def print
      if (@capabilities & CAP_TCP) == CAP_TCP
        puts "   CIP over TCP"
      end
      if (@capabilities & CAP_UDP) == CAP_UDP
        puts "   CIP over UDP"
      end
    end
  end

  class Interface
    def initialize(r)
      @ninterfaces = r.get_uint
    end
    def print
      puts "\t#{@ninterfaces} interfaces"
    end
  end

  # -------------------------------------------------------------

  class TCPSocket < TCPSocket
    def initialize host_ip
      super(host_ip, EXPLICIT_MESSAGING_PORT)
    end
    def encap_tx_rx command, session=0, data=nil
      write ENIP.encapsulate(command, session, data)
      r_len = ENIP.decapsulate(PackBuffer.new(recv(24)))[1]
      PackBuffer.new(recv(r_len))
    end
    def identity
      reply = encap_tx_rx COMMAND_LISTIDENTITY
      reply.get_uint # ignore number
      Identity.new reply
    end
    def services
      reply = encap_tx_rx COMMAND_LISTSERVICES
      Service.new reply
    end
    def interfaces
      reply = encap_tx_rx COMMAND_LISTINTERFACES
      Interface.new reply
    end
    def nop
      write ENIP.encapsulate COMMAND_NOP
    end
  end

  # -------------------------------------------------------------

  class UDPSocket < UDPSocket
    def receive
      items = []
      start = Time.now
      while Time.now - start < 1.0
        begin
          rcv = self.recvfrom_nonblock(1024)
          ip = rcv[1]
          reply = PackBuffer.new(rcv[0])
          if reply.length >= 24
            clen = ENIP.decapsulate(reply)[1]
            if clen >= 2
              items << yield(reply)
            end
          end

        rescue Errno::EAGAIN
        rescue Errno::EWOULDBLOCK
        end
      end
      items
    end

    def send_request addr, command
      request = ENIP.encapsulate command
      self.send(request, 0, addr, EXPLICIT_MESSAGING_PORT)
    end
    def identity addr
      send_request addr, COMMAND_LISTIDENTITY
      receive { |reply|
        reply.get_uint # ignore number
        Identity.new(reply)
      }
    end
    def services addr
      send_request addr, COMMAND_LISTSERVICES
      receive { |reply| Service.new(reply) }
    end
    def interfaces(addr)
      send_request addr, COMMAND_LISTINTERFACES
      receive { |reply| Interface.new(reply) }
    end
  end

  # -------------------------------------------------------------

  class Session
    attr_reader :socket, :session_handle
    def initialize socket
      @socket = socket
      protocol_version = 1
      option_flags = 0
      @socket.write ENIP.encapsulate(COMMAND_REGISTERSESSION, 0, [protocol_version, option_flags].pack("vv"))
      reply = ENIP.decapsulate(PackBuffer.new(@socket.recv(32)))
      @session_handle = reply[2]
    end
    def close
      @socket.write ENIP.encapsulate(COMMAND_UNREGISTERSESSION, @session_handle)
    end

    # send/receive unconnected message
    def cip_ucmm mr_request
      cpf_request = CommonPacket.new
      cpf_request << [CPF_TYPE_NULL_ADDRESS, nil]
      cpf_request << [CPF_TYPE_UNCONNECTED_DATA, mr_request]

      srrd_request = PackBuffer.new.put_sendrrdata(cpf_request.pack)
      reply = @socket.encap_tx_rx COMMAND_SENDRRDATA, @session_handle, srrd_request
      reply.eat(6) # ignore unused sendRRData fields

      cpf_reply = CommonPacket.new
      cpf_reply.unpack reply
      return cpf_reply
    end

    def identity
      ClassService.new self, CLASS_IDENTITY, IdentityService
    end
    def tcpip_interface
      ClassService.new self, CLASS_TCPIP_INTERFACE, TCPIPInterfaceService
    end
    def ethernet_link
      ClassService.new self, CLASS_ETHERNET_LINK, EthernetLinkService
    end
    def connection_manager
      ClassService.new self, CLASS_CONNECTION_MANAGER, ConnectionManagerService
    end
    def message_router
      ClassService.new self, CLASS_MESSAGE_ROUTER, MessageRouterService
    end
    def assembly
      ClassService.new self, CLASS_ASSEMBLY, AssemblyService
    end
  end

  # -------------------------------------------------------------

  class CIPService
    def cip_service service_code, epath, data=nil
      mr_request = MessageRouterRequest.new(service_code, epath, data)
      cpf_reply = @session.cip_ucmm mr_request.pack

      mr_reply = cpf_reply.get_item_of_type(CPF_TYPE_UNCONNECTED_DATA)
      mr_reply.get_usint # ignore service code
      mr_reply.get_usint # ignore reserved field

      general_status = mr_reply.get_usint
      extended_status = 0
      extended_status_size = mr_reply.get_usint
      extended_status_size.times { extended_status = mr_reply.get_word }
      ENIP.throw_cip_exception general_status, extended_status
      return mr_reply
    end
    def get_attribute_single attribute
      epath = @epath.clone.concat([0x30, attribute])
      cip_service SERVICE_GET_ATTRIBUTE_SINGLE, epath
    end
    def set_attribute_single attribute, bytes
      epath = @epath.clone.concat([0x30, attribute])
      cip_service SERVICE_SET_ATTRIBUTE_SINGLE, epath, bytes
    end
    def get_attributes_all
      cip_service SERVICE_GET_ATTRIBUTES_ALL, @epath
    end
    def set_attributes_all bytes
      cip_service SERVICE_SET_ATTRIBUTES_ALL, @epath, bytes
    end
  end

  # -------------------------------------------------------------

  class ClassService < CIPService
    def initialize session, class_id, instance_class
      @session = session
      @epath = [ 0x20, class_id, 0x24, 0 ]
      @instance_class = instance_class
    end
    def [] index
      raise "instance index may not be 0" if index == 0
      epath = @epath.clone
      epath[3] = index
      @instance_class.new(@session, epath)
    end
    def revision ; get_attribute_single(1).get_uint end
    def max_instance ; get_attribute_single(2).get_uint end
    def number_instances ; get_attribute_single(3).get_uint end
  end

  # -------------------------------------------------------------

  class InstanceService < CIPService
    def initialize session, epath
      @session = session
      @epath = epath
    end
  end

  # -------------------------------------------------------------

  class AssemblyService < InstanceService
    def size ; get_attribute_single(4).get_uint end
    def read ; get_attribute_single 3 end
    def write bytes ; set_attribute_single 3, bytes end
  end

  # -------------------------------------------------------------

  class TCPIPInterfaceService < InstanceService
    def status ; get_attribute_single(1).get_dword end
    def configuration_capabilities ; get_attribute_single(2).get_dword end
    def configuration_control ; get_attribute_single(3).get_dword end
    def physical_link ; get_attribute_single(4).get_epath end
    def configuration ; get_attribute_single(5).get_interface end
    def hostname ; get_attribute_single(6).get_string end
  end

  # -------------------------------------------------------------

  class IdentityService < InstanceService
    def vendor_id ; get_attribute_single(1).get_uint end
    def device_type ; get_attribute_single(2).get_uint end
    def product_code ; get_attribute_single(3).get_uint end
    def revision
      revision = get_attribute_single(4)
      major = revision.get_usint
      minor = revision.get_usint
      "#{major}.#{minor}"
    end
    def status ; get_attribute_single(5).get_word end
    def serial_number ; get_attribute_single(6).get_udint end
    def product_name ; get_attribute_single(7).get_short_string end
    # reset_service_parameter:
    # 0   Hardware-Reset
    # 1   zurueck zum Auslieferungszustand, dann Hardware-Reset
    # 2   zurueck zum Auslieferungszustand, ausser bei Netzwerk-Konfiguration, dann Hardware-Reset
    def reset reset_service_parameter
      cip_service SERVICE_RESET, @epath, PackBuffer.new.put_usint(reset_service_parameter)
    end
  end

  # -------------------------------------------------------------

  class MessageRouterService < InstanceService
  end

  # -------------------------------------------------------------

  class ConnectionManagerService < InstanceService
    def forward_open fo_request
      mr_request = MessageRouterRequest.new SERVICE_FORWARD_OPEN, @epath, fo_request.pack
      cpf_reply = @session.cip_ucmm mr_request.pack

      mr_reply = cpf_reply.get_item_of_type(CPF_TYPE_UNCONNECTED_DATA)
      mr_reply.get_usint # ignore service code
      mr_reply.get_usint # ignore reserved field

      general_status = mr_reply.get_usint
      extended_status = 0
      extended_status_size = mr_reply.get_usint
      extended_status_size.times { extended_status = mr_reply.get_word }

      if general_status != CIP_ERROR_SUCCESS
        fo_response = UnsuccessfulForwardOpen.new(mr_reply) # ???
        ENIP.throw_cip_exception general_status, extended_status
      end
      return SuccessfulForwardOpen.new(mr_reply, cpf_reply)
    end
    def forward_close fc_request
      mr_request = MessageRouterRequest.new(SERVICE_FORWARD_CLOSE, @epath, fc_request.pack)
      cpf_reply = @session.cip_ucmm mr_request.pack

      mr_reply = cpf_reply.get_item_of_type(CPF_TYPE_UNCONNECTED_DATA)
      mr_reply.get_usint # ignore service code
      mr_reply.get_usint # ignore reserved field

      general_status = mr_reply.get_usint
      extended_status = 0
      extended_status_size = mr_reply.get_usint
      extended_status_size.times { extended_status = mr_reply.get_word }

      if general_status != CIP_ERROR_SUCCESS
        fc_response = UnsuccessfulForwardClose.new(mr_reply)
        ENIP.throw_cip_exception general_status, extended_status
      end
      fc_response = SuccessfulForwardClose.new(mr_reply)
      return fc_response
    end
  end

  # -------------------------------------------------------------

  class EthernetLinkService < InstanceService
    def interface_speed
      get_attribute_single(1).get_udint
    end
    def interface_flags
      get_attribute_single(2).get_dword
    end
    def physical_address
      get_attribute_single(3).get_mac_addr
    end
  end

  # -------------------------------------------------------------

  def throw_cip_exception error_code, extended_status
    return if error_code == CIP_ERROR_SUCCESS

    case extended_status
    when CIP_EXTENDED_STATUS_TARGET_CONNECTION_NOT_FOUND
      ext = "target connection not found"
    when CIP_EXTENDED_STATUS_OWNERSHIP_CONFLICT
      ext = "ownership conflict"
    when CIP_EXTENDED_STATUS_CONNECTION_IN_USE_OR_DUPLICATE_FORWARD_OPEN
      ext = "connection in use or duplicate forward open"
    when CIP_EXTENDED_STATUS_INVALID_CONNECTION_SIZE
      ext = "invalid connection size"
    when CIP_EXTENDED_STATUS_INVALID_PATH
      ext = "invalid produced or consumed application path"
    when CIP_EXTENDED_STATUS_NON_LISTEN_ONLY_CONNECTION_NOT_OPENED
      ext = "no non-listen connection opened"
    end

    if ext.nil?
      ext = "unknown extended status #{extended_status}"
    end

    case error_code
    when CIP_ERROR_CONNECTION_FAILURE
      raise ConnectionFailure.new("connection failure: " + ext, extended_status)
    when CIP_ERROR_PATH_DESTINATION_UNKNOWN
      raise PathDestinationUnknown.new("destination path references unknown object: " + ext, extended_status)
    when CIP_ERROR_PATH_SEGMENT_ERROR
      raise PathSegmentError.new("path segment error: " + ext, extended_status)
    when CIP_ERROR_SERVICE_NOT_SUPPORTED
      raise ServiceNotSupported.new("service not supported: " + ext, extended_status)
    when CIP_ERROR_ATTRIBUTE_NOT_SETTABLE
      raise AttributeNotSettable.new("attribute not settable: " + ext, extended_status)
    when CIP_ERROR_DEVICE_STATE_CONFLICT
      raise DeviceStateConflict.new("device state conflict: " + ext, extended_status)
    when CIP_ERROR_NOT_ENOUGH_DATA
      raise NotEnoughData.new("not enough data: " + ext, extended_status)
    when CIP_ERROR_ATTRIBUTE_NOT_SUPPORTED
      raise AttributeNotSupported.new("attribute not supported: " + ext, extended_status)
    when CIP_ERROR_TOO_MUCH_DATA
      raise TooMuchData.new("too much data: " + ext, extended_status)
    when CIP_ERROR_OBJECT_DOES_NOT_EXIST
      raise ObjectDoesNotExist.new("object does not exist: " + ext, extended_status)
    when CIP_ERROR_INVALID_PARAMETER
      raise InvalidParameter.new("invalid parameter: " + ext, extended_status)
    else
      raise NotYetImplemented.new("not yet implemented CIP exception with error code #{error_code}", extended_status)
    end
  end

  def ENIP.throw_encap_exception(status)
    case status
    when 1
      raise EncapInvalidCommand
    when 2
      raise EncapInsufficientMemory
    when 3
      raise EncapIncorrectData
    when 0x64
      raise EncapInvalidSessionHandle
    when 0x65
      raise EncapInvalidLength
    when 0x69
      raise EncapUnsupportedProtocol
    end 
  end

  class ForwardOpenRequest
    attr_accessor :connection_type
    attr_accessor :priority_time_tick, :timeout_ticks, :o2t_network_connection_id, :t2o_network_connection_id, 
                  :connection_serial_number, :connection_timeout_multiplier, 
                  :o2t_rpi, :o2t_network_connection_params, :t2o_rpi, :t2o_network_connection_params, 
                  :transport_type, :connection_path
    def initialize
      @priority_time_tick = @timeout_ticks = @o2t_network_connection_id = @t2o_network_connection_id = 0
      @connection_serial_number = @connection_timeout_multiplier = 0
      @o2t_rpi = @o2t_network_connection_params = @t2o_rpi = @t2o_network_connection_params = 0
      @transport_type = 0
      @connection_path = nil 
    end

    def pack
      r = PackBuffer.new
      r.put_byte @priority_time_tick
      r.put_usint @timeout_ticks
      r.put_udint @o2t_network_connection_id
      r.put_udint @t2o_network_connection_id
      r.put_uint @connection_serial_number
      r.put_uint ENIP.vendor_id
      r.put_udint ENIP.serial_number
      r.put_usint @connection_timeout_multiplier
      3.times { r.put_byte 0 }
      r.put_udint @o2t_rpi
      r.put_word @o2t_network_connection_params
      r.put_udint @t2o_rpi
      r.put_word @t2o_network_connection_params
      r.put_byte @transport_type
      r.put_epath @connection_path
      r
    end
  end

   class SuccessfulForwardOpen
    attr_accessor :o2t_network_connection_id, :t2o_network_connection_id, :connection_serial_number,
                  :originator_vendor_id, :originator_serial_number, :connection_serial_number,
                  :o2t_api, :t2o_api, :application_reply_size
    attr_accessor :o2t_sockaddr, :t2o_sockaddr

    def initialize(r, cpf_reply)
      @o2t_network_connection_id = r.get_udint
      @t2o_network_connection_id = r.get_udint
      @connection_serial_number  = r.get_uint
      @originator_vendor_id      = r.get_uint
      @originator_serial_number  = r.get_udint
      @o2t_api                   = r.get_udint
      @t2o_api                   = r.get_udint
      application_reply_size     = r.get_usint
                                   r.get_usint # reserved
      r.eat(application_reply_size << 1)                 # application reply

      sa = cpf_reply.get_item_of_type(CPF_TYPE_SOCKADDR_O2T)
      @o2t_sockaddr = sa.get_socket_address if ! sa.nil?
      sa = cpf_reply.get_item_of_type(CPF_TYPE_SOCKADDR_T2O)
      @t2o_sockaddr = sa.get_socket_address if ! sa.nil?
    end
  end
 
   class UnsuccessfulForwardOpen
    attr_accessor :connection_serial_number,
                  :originator_vendor_id, :connection_serial_number,
                  :remaining_path_size
    def initialize(r)
      @connection_serial_number  = r.get_uint
      @originator_vendor_id      = r.get_uint
      @originator_serial_number  = r.get_udint
      @remaining_path_size       = r.get_usint
                                   r.get_usint # reserved
    end
  end
 
  class ForwardCloseRequest
    attr_accessor :priority_time_tick, :timeout_ticks,
                  :connection_serial_number, :connection_path
    def initialize
      @priority_time_tick = @timeout_ticks = @connection_serial_number = 0
      @connection_path = nil
    end

    def pack
      r = PackBuffer.new
      r.put_byte @priority_time_tick
      r.put_usint @timeout_ticks
      r.put_uint @connection_serial_number
      r.put_uint ENIP.vendor_id
      r.put_udint ENIP.serial_number
      r.put_usint @connection_path.length >> 1
      r.put_usint 0                            # reserved
      tmp = PackBuffer.new
      tmp.put_epath @connection_path
      r << tmp[1..connection_path.length]
      return r
    end
  end

  class SuccessfulForwardClose
    attr_accessor :connection_serial_number, :originator_vendor_id, :originator_serial_number

    def initialize(r)
      @connection_serial_number = r.get_uint
      @originator_vendor_id     = r.get_uint
      @originator_serial_number = r.get_udint
      application_reply_size    = r.get_usint
                                  r.get_usint # reserved
      r.eat(application_reply_size << 1)                 # application reply
    end
  end

  class UnsuccessfulForwardClose
    attr_accessor :connection_serial_number, :originator_vendor_id, :originator_serial_number

    def initialize(r)
      @connection_serial_number = r.get_uint
      @originator_vendor_id =     r.get_uint
      @originator_serial_number = r.get_udint
                                  r.get_usint # remaining path size
                                  r.get_usint # reserved
    end
  end
 
  class MessageRouterRequest
    # EPATH_CONNECTION_MANAGER = [ 0x20, 0x06, 0x24, 0x01 ]
    # EPATH_IDENTITY = [ 0x20, 0x06, 0x24, 0x01 ]

    attr_accessor :service, :epath, :request_data 
    def initialize(service, epath, request_data)
      @service = service 
      @epath = epath 
      @request_data = request_data 
    end
    def pack
      r = PackBuffer.new
      r.put_usint @service
      r.put_usint @epath.length >> 1
      @epath.each { |c|
        r.put_usint c
      }
      r << @request_data if ! @request_data.nil?
      return r
    end
  end

  class CommonPacket < Array
    def pack
      r = PackBuffer.new
      r.put_uint self.length

      self.each { |item|
        r.put_uint item[0]
        if item[1].nil?
          r.put_uint 0
        else
          r.put_uint item[1].length
          r << item[1]
        end
      }
      return r
    end
    def unpack(r)
      items = r.get_uint
      items.times {
        item_type = r.get_uint
        item_len = r.get_uint
        if item_len == 0
          self << [item_type, nil]
        else
          self << [item_type, PackBuffer.new(r[0..item_len-1])]
          r.eat(item_len)
        end
      }
    end
    def get_item_of_type(type)
      item = self.find { |pair| pair[0] == type }
      return nil if item.nil?
      return item[1]
    end
  end
 
  class ExclusiveOwnerRequest < ForwardOpenRequest
    def initialize rpi_msec, timeout_multiplier, unicast, isize, osize, iinstance, oinstance, cinstance
      super()
      @connection_path = [ 0x20, CLASS_ASSEMBLY, 0x24, cinstance, 0x2C, oinstance, 0x2C, iinstance ]
      @connection_serial_number = ENIP.get_new_connection_serial_number
      @o2t_rpi = rpi_msec * 1000
      @t2o_rpi = rpi_msec * 1000
      @connection_timeout_multiplier = timeout_multiplier 
      @o2t_network_connection_params =
        (2 << 13) |        # Connection Type = POINT2POINT,
        (2 << 10) |        # Priority = SCHEDULED
        (0 << 9)  |        # Use fixed size
        ((osize + 2 + 4) << 0) # Connection size in bytes
      
      @t2o_network_connection_params =
        (2 << 10) |        # Priority = SCHEDULED
        (0 << 9)  |        # Use fixed size
        ((isize + 2) << 0)     # Connection size in bytes
      if unicast 
        @t2o_network_connection_params |=  (2 << 13)   # Connection Type = POINT2POINT
      else
        @t2o_network_connection_params |=  (1 << 13)   # Connection Type = MULTICAST
      end 
      @transport_type                = 0x01  # direction: client, production trigger: cyclic, transport class: 1 
      @t2o_network_connection_id = rand * 1000
    end
  end

  class InputOnlyRequest < ForwardOpenRequest
    def initialize rpi_msec, timeout_multiplier, unicast, isize, iinstance, oinstance, cinstance
      super()
      @connection_path = [ 0x20, CLASS_ASSEMBLY, 0x24, cinstance, 0x2C, oinstance, 0x2C, iinstance ]
      @connection_serial_number = ENIP.get_new_connection_serial_number
      @o2t_rpi = rpi_msec * 1000
      @t2o_rpi = rpi_msec * 1000
      @connection_timeout_multiplier = timeout_multiplier 
      @o2t_network_connection_params =
        (2 << 13) |        # Connection Type = POINT2POINT,
        (2 << 10) |        # Priority = SCHEDULED
        (0 << 9)  |        # Use fixed size
        (2  << 0)          # Connection size in bytes
      @t2o_network_connection_params =
        (2 << 10) |        # Priority = SCHEDULED
        (0 << 9)  |        # Use fixed size
        ((isize + 2) << 0)     # Connection size in bytes
      if unicast 
        @t2o_network_connection_params |=  (2 << 13)   # Connection Type = POINT2POINT
      else
        @t2o_network_connection_params |=  (1 << 13)   # Connection Type = MULTICAST
      end 
      @transport_type                = 0x01  # direction: client, production trigger: cyclic, transport class: 1 
      @t2o_network_connection_id = rand * 1000
    end
  end

  class ListenOnlyRequest < ForwardOpenRequest
    def initialize rpi_msec, timeout_multiplier, isize, iinstance, oinstance, cinstance
      super()
      @connection_path = [ 0x20, CLASS_ASSEMBLY, 0x24, cinstance, 0x2C, oinstance, 0x2C, iinstance ]
      @connection_serial_number = ENIP.get_new_connection_serial_number
      @o2t_rpi = rpi_msec * 1000
      @t2o_rpi = rpi_msec * 1000
      @connection_timeout_multiplier = timeout_multiplier 
      @o2t_network_connection_params =
        (2 << 13) |        # Connection Type = POINT2POINT,
        (2 << 10) |        # Priority = SCHEDULED
        (0 << 9)  |        # Use fixed size
        (2 << 0)           # Connection size in bytes
      @t2o_network_connection_params =
        (2 << 10) |        # Priority = SCHEDULED
        (0 << 9)  |        # Use fixed size
        ((isize + 2) << 0)     # Connection size in bytes
      @t2o_network_connection_params |=  (1 << 13)   # Connection Type = MULTICAST
      @transport_type                = 0x01  # direction: client, production trigger: cyclic, transport class: 1 
      @t2o_network_connection_id = rand * 1000
    end
  end

  class Connection
    attr_accessor :idata, :rpi, :timeout_multiplier, :timeout
    attr_accessor :next_send, :last_recv, :o2t_network_connection_id, :t2o_network_connection_id
    attr_accessor :ip_addr, :unicast, :multicast_addr
    attr_accessor :producing_seqno, :consuming_seqno
    def initialize session, ip_addr, unicast, rpi, fo_request
      now = Time.now
      @session = session
      @producing_seqno = 0
      @consuming_seqno = 0
      @ip_addr = ip_addr
      @rpi = rpi
      @next_send = now + rpi.to_f / 1000
      @last_recv = now
      @timeout = false
      @unicast = unicast
      @timeout_multiplier = fo_request.connection_timeout_multiplier
      @connection_path = fo_request.connection_path
      @connection_serial_number = fo_request.connection_serial_number

      fo_reply = @session.connection_manager[1].forward_open fo_request
      @o2t_network_connection_id = fo_reply.o2t_network_connection_id
      @t2o_network_connection_id = fo_reply.t2o_network_connection_id
      if ! unicast
        @multicast_addr = fo_reply.t2o_sockaddr[0].to_s
      end
    end
    def close
      fc_request = ENIP::ForwardCloseRequest.new
      fc_request.connection_path = @connection_path
      fc_request.connection_serial_number  = @connection_serial_number
      @session.connection_manager[1].forward_close fc_request
    end
  end

  # --------------------------------------------------------------------------

  class BinString < String
    def initialize size, val=0
      super()
      size.times { self << val.chr }
    end
  end

  # --------------------------------------------------------------------------

  class ExclusiveOwnerConnection < Connection
    attr_accessor :run, :odata
    def initialize session, ip_addr, rpi, timeout_multiplier, unicast, isize, 
                    osize, iinstance, oinstance, cinstance
      @run = false
      @odata = BinString.new(osize)
      @producing_seqno = 1
      fo_request = ExclusiveOwnerRequest.new rpi, timeout_multiplier, unicast,
            isize, osize, iinstance, oinstance, cinstance
      super session, ip_addr, unicast, rpi, fo_request
    end
  end

  # --------------------------------------------------------------------------

  class InputOnlyConnection < Connection
    def initialize session, ip_addr, rpi, timeout_multiplier, unicast, isize,
            iinstance, oinstance, cinstance
      fo_request = InputOnlyRequest.new rpi, timeout_multiplier, unicast,
            isize, iinstance, oinstance, cinstance
      super session, ip_addr, unicast, rpi, fo_request
    end
  end

  # --------------------------------------------------------------------------

  class ListenOnlyConnection < Connection
    def initialize session, ip_addr, rpi, timeout_multiplier, isize,
            iinstance, oinstance, cinstance
      fo_request = ListenOnlyRequest.new rpi, timeout_multiplier, isize, 
            iinstance, oinstance, cinstance
      super session, ip_addr, true, rpi, fo_request
    end
  end

  # --------------------------------------------------------------------------

  class ConnectionMultiplexerException < StandardError ; end
  class ConnectionTimeout < ConnectionMultiplexerException ; end

  class ConnectionMultiplexer < Array
    attr_accessor :trace
    def initialize
      @udp_socket = UDPSocket.open
      begin
        @udp_socket.bind(Socket::INADDR_ANY, IMPLICIT_MESSAGING_PORT)

      rescue Errno::EADDRINUSE
        STDERR.puts "implicit messaging port #{IMPLICIT_MESSAGING_PORT} in use ..."
        GC.start
        sleep 0.5
        retry
      end
      @mcast = {}
      @trace = false
    end
    def close
      @udp_socket.close
    end
    # add connection
    def << c
      super c
      if ! c.unicast
        if @mcast[c.multicast_addr].nil?
          # STDERR.puts "setsockopt(ADD,#{c.multicast_addr})"
          ip =  IPAddr.new(c.multicast_addr).hton + IPAddr.new("0.0.0.0").hton
          @udp_socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_ADD_MEMBERSHIP, ip)
          @mcast[c.multicast_addr] = 1
        else
          @mcast[c.multicast_addr] += 1
        end
      end
    end
    # delete connection
    def delete c
      c.close
      if ! c.unicast
        @mcast[c.multicast_addr] -= 1
        if @mcast[c.multicast_addr] == 0
          # STDERR.puts "setsockopt(DEL,#{c.multicast_addr})"
          ip =  IPAddr.new(c.multicast_addr).hton + IPAddr.new("0.0.0.0").hton
          @udp_socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_DROP_MEMBERSHIP, ip)
          @mcast.delete c.multicast_addr
        end
      end
      super c
    end
    def recv
      start = Time.now
      udp_packet = @udp_socket.recvfrom_nonblock(1024)
      msg = ENIP::PackBuffer.new(udp_packet[0])
      cpf = ENIP::CommonPacket.new
      cpf.unpack msg

      addr_data = cpf.get_item_of_type(ENIP::CPF_TYPE_SEQUENCED_ADDRESS)
      connid = addr_data.get_udint
      seqno = addr_data.get_udint

      self.each { |c|
        next if c.t2o_network_connection_id != connid
        if seqno != c.consuming_seqno 
          c.idata = cpf.get_item_of_type(ENIP::CPF_TYPE_CONNECTED_DATA)
          c.consuming_seqno = seqno
        end
        STDERR.puts "recv #{c.idata.length} bytes connid: #{connid} " \
          "seqno: #{seqno} took: #{sprintf("%5.3f", Time.now - start)} s" if @trace

        c.last_recv = Time.now
        # break
      }
    end
    def send c
      c.producing_seqno += 1

      addr_data = ENIP::PackBuffer.new
      addr_data.put_udint c.o2t_network_connection_id
      addr_data.put_udint c.producing_seqno
      data = ENIP::PackBuffer.new
      data.put_uint c.producing_seqno

      if c.is_a? ExclusiveOwnerConnection
        header32bit = c.run ? 1 << 0 : 0
        data.put_udint header32bit
        data << c.odata
        bytes = c.odata.length
      else
        bytes = 0
      end

      cpf = ENIP::CommonPacket.new
      cpf << [ ENIP::CPF_TYPE_SEQUENCED_ADDRESS, addr_data]
      cpf << [ ENIP::CPF_TYPE_CONNECTED_DATA, data]
      @udp_socket.send(cpf.pack, 0, c.ip_addr, ENIP::IMPLICIT_MESSAGING_PORT)
      STDERR.puts "send #{bytes} bytes for connid: #{c.o2t_network_connection_id} seqno: #{c.producing_seqno}" if @trace
    end
    def interval
      begin
        recv 
      rescue Errno::EAGAIN, Errno::EWOULDBLOCK
      end

      self.each { |c| 
        next if c.timeout == true
        passed_time = Time.now - c.last_recv 
        if passed_time > c.rpi.to_f/1000 * (4 << c.timeout_multiplier)
          c.timeout = true  
          STDERR.puts "connid #{c.t2o_network_connection_id} timed out by #{passed_time}"
          raise ConnectionTimeout, "connid #{c.t2o_network_connection_id} timed out by #{passed_time}"
        end
      }

      self.each { |c| 
        if !c.timeout && c.next_send <= Time.now
          send c
          c.next_send = Time.now + c.rpi.to_f / 1000
          # puts "next_send: #{sprintf("%5.3f", c.next_send.to_f)}"
        end
      }
      sleep 0.0005
    end
    def run sec
      start = Time.now
      interval while Time.now - start < sec
    end
    def forever
      interval while true 
    end
  end
end
