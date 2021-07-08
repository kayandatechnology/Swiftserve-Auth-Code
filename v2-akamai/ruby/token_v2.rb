#!/usr/bin/env ruby
# Copyright (c) 2012, Akamai Technologies, Inc.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Akamai Technologies nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL AKAMAI TECHNOLOGIES BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'cgi'
require 'openssl'
require 'optparse'

# Set up the command line parsing.
token_config = {}
opt_parse = OptionParser.new do|opts|
  opts.banner = 'Usage:akamai_token_v2 [options]'

  token_config[:token_type] = 'URL'
  opts.on('-t', '--token_type TOKEN_TYPE', 'Select a preset: (Not Supported Yet) 2.0, 2.0.2') do|token_type|
    token_config[:token_type] = token_type
  end

  token_config[:token_name] = 'hdnts'
  opts.on('-n', '--token_name TOKEN_NAME', 'Parameter name for the new token. [Default:hdnts]') do|token_name|
    token_config[:token_name] = token_name
  end

  token_config[:ip] = nil
  opts.on('-i', '--ip IP_ADDRESS', 'IP Address to restrict this token to.') do|ip|
    token_config[:ip] = ip
  end

  token_config[:start_time] = nil
  opts.on('-s', '--start_time START_TIME', '--start_time START_TIME', 'What is the start time. (Use now for the current time)') do|start_time|
    if start_time == 'now'
      token_config[:start_time] = Time.new.getgm
    else
      token_config[:start_time] = start_time
    end
  end

  token_config[:end_time] = nil
  opts.on('-e', '--end_time END_TIME', 'When does this token expire? --exp overrides --window') do|end_time|
    token_config[:end_time] = end_time
  end

  token_config[:window_secs] = nil
  opts.on('-w', '--window NUMBER_OF_SECONDS', 'How long is this token valid for?') do|window_secs|
    token_config[:window_secs] = window_secs
  end

  token_config[:url] = nil
  opts.on('-u', '--url URL', 'URL path.') do|url|
    token_config[:url] = url
  end

  token_config[:acl] = nil
  opts.on('-a', '--acl ACCESS_LIST', 'Access control list delimited by ! (Default: /*)') do|acl|
    token_config[:acl] = acl
  end

  token_config[:key] = nil
  opts.on('-k', '--key KEY', 'Secret required to generate the token.') do|key|
    token_config[:key] = key
  end

  token_config[:payload] = nil
  opts.on('-p', '--payload PAYLOAD', 'Additional text added to the calculated digest.') do|payload|
    token_config[:payload] = payload
  end

  token_config[:algo] = 'sha256'
  opts.on('-A', '--algo ALGORITHM', 'Algorithm to use to generate the token. (sha1, sha256, or md5) [Default:sha256]') do|algo|
    case algo.downcase when 'sha1', 'sha256', 'md5'
      token_config[:algo] = algo.downcase
    else
        puts 'algo must be one of sha1, sha256, or md5'
        exit
    end
  end

  token_config[:salt] = nil
  opts.on('-S', '--salt SALT', 'Additional data validated by the token but NOT included in the token body.') do|salt|
    token_config[:salt] = salt
  end

  token_config[:session_id] = nil
  opts.on('-I', '--session_id SESSION_ID', 'The session identifier for single use tokens or other advanced cases.') do|session_id|
    token_config[:session_id] = session_id
  end

  token_config[:field_delimiter] = '~'
  opts.on('-d', '--field_delimiter', 'Character used to delimit token body fields. [Default:~]') do|field_delimiter|
    token_config[:field_delimiter] = field_delimiter
  end

  token_config[:acl_delimiter] = '!'
  opts.on('-D', '--acl_delimiter', 'Character used to delimit acl fields. [Default:!]') do|acl_delimiter|
    token_config[:acl_delimiter] = acl_delimiter
  end

  token_config[:escape_early] = nil
  opts.on('-x', '--escape_early', 'Causes strings to be url encoded before being used. (legacy 2.0 behavior)') do
    token_config[:escape_early] = 1
  end

  token_config[:escape_early_upper] = nil
  opts.on('-X', '--escape_early_upper', 'Causes strings to be url encoded before being used. (legacy 2.0 behavior)') do
    token_config[:escape_early_upper] = 1
  end

  token_config[:verbose] = nil
  opts.on('-v', '--verbose', 'Display more details about the inputs') do
    token_config[:verbose] = 1
  end

  opts.on('-h', '--help', 'Display this help info') do
    puts opts
    exit
  end
end

# parse parses ARGV but parse! removes the options as they are parsed.
opt_parse.parse!

if token_config[:start_time] != nil
  token_config[:start_time] = token_config[:start_time].to_i
end

if token_config[:end_time] != nil
  if token_config[:end_time].to_i < token_config[:start_time].to_i
    puts 'WARNING:token will have already expired.'
  end
else
  # Calculate the end time if it hasn't already been given a value.
  if token_config[:window_secs] != nil
    if token_config[:start_time] == nil
      token_config[:end_time] = Time.new.getgm.to_i + token_config[:window_secs].to_i
    else
      token_config[:end_time] = token_config[:start_time].to_i + token_config[:window_secs].to_i
    end
  else
    puts 'You must provide an expiration time or a duration window.'
    exit
  end
end

if token_config[:key] == nil or token_config[:key].length < 1
  puts 'You must provide a secret in order to generate a token'
  exit
end

if token_config[:acl] == nil and token_config[:url] == nil
  puts 'You must provide a URL or an ACL.'
  exit
end

if token_config[:acl] and token_config[:acl].length > 0 and token_config[:url] and token_config[:url].length > 1
  puts 'You must provide a URL OR an ACL, not both.'
  exit
end

if token_config[:verbose] != nil
  puts 'Akamai Token Generation Parameters'
  puts 'Token Type           : %s' % token_config[:token_type].upcase
  puts 'Token Name           : %s' % token_config[:token_name]
  puts 'Start Time           : %d' % token_config[:start_time]
  puts 'Window(seconds)      : %d' % token_config[:window_secs]
  puts 'End Time             : %d' % token_config[:end_time]
  puts 'IP                   : %s' % token_config[:ip]
  puts 'URL                  : %s' % token_config[:url]
  puts 'ACL                  : %s' % token_config[:acl]
  puts 'Key/Secret           : %s' % token_config[:key]
  puts 'Payload              : %s' % token_config[:payload]
  puts 'Algo                 : %s' % token_config[:algo]
  puts 'Salt                 : %s' % token_config[:salt]
  puts 'Session ID           : %s' % token_config[:session_id]
  puts 'Field Delimiter      : %s' % token_config[:field_delimiter]
  puts 'ACL Delimiter        : %s' % token_config[:acl_delimiter]
  puts 'Escape Early         : %s' % token_config[:escape_early]
  puts 'Escape Early Upper   : %s' % token_config[:escape_early_upper]
  puts 'Generating token...'
end

# Conditionally add the pieces of the token that were provided on the command line.
token_pieces = Array.new
if token_config[:ip] != nil
  token_pieces[token_pieces.length] = 'ip=%s' % token_config[:ip]
end
if token_config[:start_time] != nil
  token_pieces[token_pieces.length] = 'st=%s' % token_config[:start_time]
end
token_pieces[token_pieces.length] = 'exp=%s' % token_config[:end_time]
if token_config[:acl] != nil
  if token_config[:escape_early]
    token_pieces[token_pieces.length] = 'acl=%s' % CGI::escape(token_config[:acl]).gsub(/(%..)/) {$1.downcase}
  else
    if token_config[:escape_early_upper]
      token_pieces[token_pieces.length] = 'acl=%s' % CGI::escape(token_config[:acl]).gsub(/(%..)/) {$1.upcase}
    else
      token_pieces[token_pieces.length] = 'acl=%s' % token_config[:acl]
    end
  end
end
if token_config[:session_id] != nil
  token_pieces[token_pieces.length] = 'id=%s' % token_config[:session_id]
end
if token_config[:payload] != nil
  token_pieces[token_pieces.length] = 'data=%s' % token_config[:payload]
end
new_token = token_pieces.join(token_config[:field_delimiter])
if token_config[:url] and token_config[:url].length > 0 and token_config[:acl] == nil
  if token_config[:escape_early]
    token_pieces[token_pieces.length] = 'url=%s' % CGI::escape(token_config[:url]).gsub(/(%..)/) {$1.downcase}
  else
    if token_config[:escape_early_upper]
      token_pieces[token_pieces.length] = 'url=%s' % CGI::escape(token_config[:url]).gsub(/(%..)/) {$1.upcase}
    else
      token_pieces[token_pieces.length] = 'url=%s' % token_config[:url]
    end
  end
end
if token_config[:salt] != nil
  token_pieces[token_pieces.length] = 'salt=%s' % token_config[:salt]
end

# Prepare the key
bin_key = Array(token_config[:key].gsub(/\s/,'')).pack("H*")

# Generate the hash
digest = OpenSSL::Digest::Digest.new(token_config[:algo])
hmac = OpenSSL::HMAC.new(bin_key, digest)
hmac.update(token_pieces.join(token_config[:field_delimiter]))

# Output the new token
puts '%s=%s%shmac=%s' % [token_config[:token_name], new_token, token_config[:field_delimiter], hmac.hexdigest()]

