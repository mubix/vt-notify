#!/usr/bin/env ruby
# encoding: utf-8

$PROGRAM_NAME = 'VirusTotalNotifier'

# require 'rubygems' # uncomment this for use w/ ruby 1.8.7
require 'json'
require 'net/http'
require 'digest/sha1'
require 'optparse'
require 'net/smtp'

def send_email(to,opts={})
	opts[:from] = 'VirusTotal-Notify@localhost'
	opts[:from_alias] ='Virus Total Notifier'
	opts[:subject] ="Virus Total Detection"
	opts[:body]        ||= "If you see this, there has been a malfunction with the script, please goto https://github.com/AshtinBlanchard/vt-notify/ and submit an issue describing what you were doing and your version of Ruby. Upload with the issue the terminal logs from the script."

	msg = <<END_OF_MESSAGE
From: #{opts[:from_alias]} <#{opts[:from]}>
To: <#{to}>
Subject: #{opts[:subject]}

#{opts[:body]}
END_OF_MESSAGE

	$smtpserver ||= 'localhost'
	Net::SMTP.start($smtpserver) do |smtp|
		smtp.send_message msg, opts[:from], to
	end
end



def getsha1(filename)
	begin
		contents = open(filename, "rb") {|io| io.read }
		sha1 = Digest::SHA1.hexdigest(contents)
		return sha1
	rescue
		return
	end
end

def ping_vt(resource)
	url = 'http://www.virustotal.com/vtapi/v2/file/report'
	uri = URI.parse(url)
	response = Net::HTTP.post_form(uri, {"apikey" => $apikey, "resource" => resource})
	return response
end

def breakuplist(hashlist)
	hashgroup = []
	(0.step(hashlist.size, 25)).each do |x|
		hashgroup << hashlist[x..(x+25)]
	end
	return hashgroup
end

def parse_results(result)
	if result['response_code'] == 0
		$notfound += 1
		return
	else
		$found << result['resource']
		puts "#{result['resource']} was found #{result['positives']} out of #{result['total']} on #{result['scan_date']}"
		if $emailaddr
			send_email $emailaddr, :body => "#{result['resource']} was found #{result['positives']} out of #{result['total']} on #{result['scan_date']}\n Permalink: #{result['permalink']}"
		end
		File.open($logfilename, 'a') {|f| f.write("#{result['resource']},#{result['positives']}-#{result['total']},#{result['scan_date']},#{result['permalink']}\n") }
	end
end

######### MAIN #############
argcheck = 0

# Parse arguments
OptionParser.new do |o|
	o.on('-e EMAIL // email address of who to notify upon detection') { |emailaddr| $emailaddr = emailaddr }
	o.on('-m SMTPSERVER // smtp server to relay email through') { |smtpserver| $smtpserver = smtpserver }
	o.on('-s FILENAME // binary file to track') { |binname| $binname = binname; argcheck = 1 }
	o.on('-S SHA1 // single SHA1 hash to track') { |sha1arg| $sha1arg = sha1arg; argcheck = 1 }
	o.on('-f FILENAME // file contaning SHA1 hashes to track') { |hashfilename| $hashfilename = hashfilename; argcheck = 1 }
	o.on('-d DIRECTORY // directory of binary files to track') { |directory| $directory = directory; argcheck = 1 }
	o.on('-a APIKEYFILENAME // file contianing API key hash on first line, defaults to apikey.txt') { |apikeyfile| $apikeyfile = apikeyfile}
	o.on('-l LOGFILENAME // file to write/read positive entries to/from, defaults to results.log') { |logfilename| $logfilename = logfilename}
	o.on('-i INTERVAL // how often VT is checked, defaults to every 10 minutes') { |interval| $interval = interval.to_i }
	o.on('-h // this useful help text') { puts o; exit }
	o.parse!
end

if argcheck == 0
	puts 'No tracking arguments specified. Exiting'
	exit
end

# Make sure arguments have something useful
$interval ||= 600 # 10 minutes in seconds
$found = []
$logfilename ||= 'results.log'
$apikeyfile ||= 'apikey.txt'

# See the following blog post, but since API limits are based on KEY+IP,
# the VT peeps recommend using an application specific key distributed w/ the tool:
# http://blog.virustotal.com/2012/12/public-api-request-rate-limits-and-tool.html
# todo: update API key to new version

begin
	$apikey = File.open($apikeyfile) {|f| f.readline.strip}
rescue Errno::ENOENT
	puts 'API key file not found. Using built-in: e09d42ac15ac172f50c1e340e551557d6c46d2673fc47b53ef5977b609d5ebe5'
	$apikey = 'e09d42ac15ac172f50c1e340e551557d6c46d2673fc47b53ef5977b609d5ebe5'
end

puts "Using API key: #{$apikey}"

begin
	File.open($logfilename).each_line do |line|
		$found << line.split(',')[0].strip
	end
rescue Errno::ENOENT
	puts 'No results file to read from, will create one if results found'
end

loop {

	hashlist = []

	if $binname
		begin
			hashlist << getsha1($binname)
		rescue Errno::ENOENT
			puts 'Binary not found, exiting'
			exit
		end
	end

	if $hashfilename
		begin
			File.open($hashfilename, 'r').each_line do |line|
				hashlist << line.strip
			end
		rescue Errno::ENOENT
			puts 'Hash file not found, exiting'
			exit
		end
	end

	if $sha1arg
		hashlist << $sha1arg
	end

	if $directory
		begin
			wd = Dir.getwd
			Dir.chdir($directory)
			filelist = Dir['**/*'].reject {|fn| File.directory?(fn)}
			puts 'Generating SHA1 hashes for all binaries in directory recursively, this could take some time...'
			puts 'This is done for every check just in case files change.'
			filelist.each do |file|
				hashlist << getsha1(file)
			end
			# Return to working directory
			Dir.chdir(wd)
		rescue Errno::ENOENT
			puts 'No such folder specified for -d, please check to make sure the folder exists'
			Dir.chdir(wd)
			exit
		end
	end

	if hashlist.size == 0
		puts 'Hash list is empty'
		puts 'Sleeping for 30 seconds then trying again'
		sleep(30)
		next
	end

	#Remove already detected
	$found.each do |removeme|
		hashlist.delete(removeme)
	end


	hashgroup = []
	$notfound = 0
	hashgroup = breakuplist(hashlist)

	# delete any empty groups as a result of the list being divisible by 25
	hashgroup.delete([])

	#puts hashgroup.inspect

	apiminutelimit = 1
	hashgroup.each do |group|
		response = ping_vt(group.join(','))
		if apiminutelimit == 4
			puts 'Virus Total API limits 4 requests per minute, limit reached, sleeping for 60 seconds'
			apiminutelimit = 0
			sleep(60)
		else
			apiminutelimit += 1
		end

		if response.body != nil
			results = JSON.parse(response.body)

			if results.class == Array
				results.each do |result|
					parse_results(result)
				end
			elsif results.class == Hash
				parse_results(results)
			end
		else
			puts "No response from Virus Total, delaying for 10 seconds and trying again..."
			sleep(10)
			redo
		end
	end

	puts "======================================"
	puts "               RESULTS                "
	puts "======================================"
	puts "Checked:     #{hashlist.size}"
	puts "Not found:   #{$notfound.to_s}"
	puts "Found:       #{$found.size}"
	puts ""

	puts "check complete, sleeping for #{$interval} seconds"
	sleep($interval)
}
