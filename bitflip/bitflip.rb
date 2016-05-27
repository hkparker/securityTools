#!/usr/bin/env ruby

require 'net/http'
require 'resolv'

def pad_with_zeros(string)
	padded = string
	until padded.length == 8
		padded = "0" + padded
	end
	return padded
end

def is_valid_domain_char(original, char)
	return false if char == original - 32
	return (65 <= char && char <= 90) || (97 <= char && char <= 122) || (char == 45)
end

def is_valid_domain(domain, tlds)
	return false if (domain.size > 255 || domain.size < 4)
	return false if !domain.include?(".")
	domain.split(".").each do |chunk|
		return false if (chunk[0] == "-" || chunk[chunk.size] == "-")
	end
	if tlds != nil
		return false if !tlds.include?(domain.split(".")[-1])
	end
	return true
end

def download_tlds
	tlds = nil
	puts "Downloading current list of top level domains..."
	begin
		Net::HTTP.start("data.iana.org") do |http|
			resp = http.get("/TLD/tlds-alpha-by-domain.txt")
			tlds = resp.body.downcase.split("\n")
			tlds.delete_at(0)
		end
	rescue
		puts "Unable to download list of top level domains."
	end
	puts "Success."
	return tlds
end

def resolve_ip(hostname)
	begin
		return Resolv.getaddress(hostname)
	rescue
	end
end

def name_to_bin_array(name)
	name_array = name.split("")
	binary_array = []
	name_array.each do |char|
		binary_array << pad_with_zeros(char.ord.to_s(2))
	end
	return binary_array
end

puts "bitflip.rb: A script for finding bitsquatted domains"
tlds = download_tlds

if ARGV[0] == nil
	print "Enter the domain name: "
	name = gets.chomp.downcase
else
	name = ARGV[0]
end

binary_array = name_to_bin_array(name)
puts "Flipping #{binary_array.join.size} bits!"
ip_hash = {}

binary_array.each_with_index do |octet, n|
	octet_array = octet.split("")
	octet_array.each_with_index do |bit, i|
		flipped = (bit == "1" ? "0" : "1")
		char = octet_array.dup
		char[i] = flipped
		char = char.join
		if is_valid_domain_char(octet.to_i(2), char.to_i(2))
			letter = char.to_i(2).chr.downcase
			domain = name.dup
			domain[n] = letter
			if is_valid_domain(domain, tlds)
				domain_ip = resolve_ip(domain)
				if domain_ip == nil
					puts domain
				else
					if ip_hash[domain_ip] == nil
						ip_hash[domain_ip] = [domain]
					else
						ip_hash[domain_ip] << domain
					end
					puts "#{domain} resolves to #{domain_ip}"
				end
			end
		end
	end
end

puts ip_hash
