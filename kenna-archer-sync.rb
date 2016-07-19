# kenna-archer-sync
require 'rest-client'
require 'json'
require 'csv'

@token = ARGV[0]
@file_name = ARGV[1]

@vuln_api_url = 'https://api.kennasecurity.com/vulnerabilities'
@search_url = @vuln_api_url + '/search?q='
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json'}

# Encoding characters
enc_colon = "%3A"
enc_dblquote = "%22"
enc_space = "%20"

start_time = Time.now
output_filename = "kenna-archer-sync-log_#{start_time.strftime("%Y%m%dT%H%M")}.txt"

## Iterate through CSV
CSV.foreach(@file_name, :headers => true) do |row|
  log_output = File.open(output_filename,'w+')
  log_output << "Reading line #{$.}... (time: #{Time.now.to_s}, start time: #{start_time.to_s}\n"
  puts "Reading line #{$.}... "

  ## Pull from CSV
  tm_record = row['Scan Record ID']
  archer_status = row['Vulnerability Status']
  hostname_str = row['Qualys DNS Hostname']
  qid_str = row['QID']

  ## Build query string/URL
  api_query = "hostname#{enc_colon}#{enc_dblquote}#{hostname_str}#{enc_dblquote}#{enc_space}AND#{enc_space}scanner_id#{enc_colon}#{qid_str}"
  query_url = "#{@search_url}#{api_query}"

  ## Query API with query_url
  vuln_id = nil
  query_response = RestClient::Request.execute(
    method: :get,
    url: query_url,
    headers: @headers
  )
  query_response_json = JSON.parse(query_response)

  ## parse JSON, pull out vuln ID
  if query_response_json.has_key?("vulnerabilities")
    if query_response_json["vulnerabilities"].count > 0
      if query_response_json["vulnerabilities"].first.has_key?("id")
        vuln_id = "#{query_response_json["vulnerabilities"].first["id"]}"
      end
    end
  end
  
  if !vuln_id.nil?
    puts "Found Kenna vuln_id: #{vuln_id}, updating..."
    log_output << "Found Kenna vuln_id: #{vuln_id}, updating...\n"
    log_output.close
    vuln_url = "#{@vuln_api_url}/#{vuln_id}"

    ## update vuln ID with data
    vuln_update_json = {
      'vulnerability' => {
        'status' => 'false_positive_by_human',
        'notes' => 'updated by Kenna test script',
        'custom_fields' => {
          1199 => tm_record,
          4037 => archer_status
        }
      }
    }

    update_response = RestClient::Request.execute(
      method: :put,
      url: vuln_url,
      headers: @headers,
      payload: vuln_update_json
    )
  end

end
