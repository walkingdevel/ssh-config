module ssh_config

import os

struct SshConfig {
mut:
	host                              string
	address_family                    string
	batch_mode                        bool
	bind_address                      string
	challenge_response_authentication bool
	check_host_ip                     bool
	cipher                            string
	ciphers                           string
	clear_all_forwardings             bool
	compression                       bool
	compression_level                 int
	connection_attempts               int
	connect_timeout                   int
	control_master                    string
	control_path                      string
	dynamic_forward                   string
	enable_ssh_keysign                bool
	escape_char                       string
	exit_on_forward_failure           bool
	forward_agent                     bool
	forward_x11                       bool
	forward_x11_trusted               bool
	gateway_ports                     bool
	global_known_hosts_file           string
	gss_api_authentication            bool
	gss_api_key_exchange              bool
	gss_api_client_identity           string
	gss_api_delegate_credentials      bool
	gss_api_renewal_forces_rekey      bool
	gss_api_trust_dns                 bool
	hash_known_hosts                  bool
	hostbased_authentication          bool
	host_key_algorithms               string
	host_key_alias                    string
	hostname                          string
	identities_only                   bool
	identity_file                     string
	kbd_interactive_authentication    bool
	kbd_interactive_devices           string
	local_command                     string
	local_forward                     string
	log_level                         string
	macs                              string
	number_of_password_prompts        int
	password_authentication           bool
	permit_local_command              bool
	port                              int
	preferred_authentications         string
	protocol                          string
	proxy_command                     string
	rekey_limit                       string
	remote_forward                    string
	rhosts_rsa_authentication         bool
	rsa_authentication                bool
	send_env                          string
	server_alive_count_max            int
	server_alive_interval             int
	smartcard_device                  string
	strict_host_key_checking          string
	tcp_keep_alive                    bool
	tunnel                            string
	tunnel_device                     string
	use_privileged_port               bool
	user                              string
	user_known_hosts_file             string
	verify_host_key_dns               string
	visual_host_key                   bool
	xauth_location                    string
}

pub fn parse_file(path string) !map[string]SshConfig {
	directory_path := os.dir(path)
	absolute_path := os.abs_path(directory_path)
	config := os.read_file(path)!

	return parse_config(absolute_path, config)
}

pub fn parse(config string) !map[string]SshConfig {
	return parse_config('', config)!
}

fn parse_config(path string, config string) !map[string]SshConfig {
	mut configs := map[string]SshConfig{}
	mut current_host := ''

	for config_line in config.split_into_lines() {
		is_comment := config_line.starts_with('#')
		is_empty_line := config_line.trim_space().len == 0

		if is_comment || is_empty_line {
			continue
		}

		line_parts := config_line.trim_space().split(' ')

		if line_parts.len < 2 {
			continue
		}

		if is_include_declaration(config_line) && path.len > 0 {
			include_path := line_parts[1]
			absolute_path := if include_path.starts_with('/') {
				include_path
			} else {
				os.join_path(path, include_path)
			}

			include_configs := parse_file(absolute_path)!
			merge_configs(mut configs, include_configs)
		}

		if is_host_declaration(config_line) {
			host := line_parts[1]
			is_host_empty := host.len == 0

			if !is_host_empty {
				current_host = host
				configs[host] = get_default_config(host)
			}
		}

		if is_property_declaration(config_line) {
			property_name := line_parts.first().to_lower()
			property_value := line_parts[1..].join(' ')

			if compare_strings(property_name, 'AddressFamily') {
				configs[current_host].address_family = property_value
			}

			if compare_strings(property_name, 'BatchMode') {
				configs[current_host].batch_mode = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'BindAddress') {
				configs[current_host].bind_address = property_value
			}

			if compare_strings(property_name, 'ChallengeResponseAuthentication') {
				configs[current_host].challenge_response_authentication = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'CheckHostIP') {
				configs[current_host].check_host_ip = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'Cipher') {
				configs[current_host].cipher = property_value
			}

			if compare_strings(property_name, 'Ciphers') {
				configs[current_host].ciphers = property_value
			}

			if compare_strings(property_name, 'ClearAllForwardings') {
				configs[current_host].clear_all_forwardings = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'Compression') {
				configs[current_host].compression = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'CompressionLevel') {
				configs[current_host].compression_level = property_value.int()
			}

			if compare_strings(property_name, 'ConnectionAttempts') {
				configs[current_host].connection_attempts = property_value.int()
			}

			if compare_strings(property_name, 'ConnectTimeout') {
				configs[current_host].connect_timeout = property_value.int()
			}

			if compare_strings(property_name, 'ControlMaster') {
				configs[current_host].control_master = property_value.to_lower()
			}

			if compare_strings(property_name, 'ControlPath') {
				configs[current_host].control_path = property_value
			}

			if compare_strings(property_name, 'DynamicForward') {
				configs[current_host].dynamic_forward = property_value
			}

			if compare_strings(property_name, 'EnableSSHKeysign') {
				configs[current_host].enable_ssh_keysign = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'EscapeChar') {
				configs[current_host].escape_char = property_value
			}

			if compare_strings(property_name, 'ExitOnForwardFailure') {
				configs[current_host].exit_on_forward_failure = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'ForwardAgent') {
				configs[current_host].forward_agent = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'ForwardX11') {
				configs[current_host].forward_x11 = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'ForwardX11Trusted') {
				configs[current_host].forward_x11_trusted = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'GatewayPorts') {
				configs[current_host].gateway_ports = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'GlobalKnownHostsFile') {
				configs[current_host].global_known_hosts_file = property_value
			}

			if compare_strings(property_name, 'GSSAPIAuthentication') {
				configs[current_host].gss_api_authentication = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'GSSAPIKeyExchange') {
				configs[current_host].gss_api_key_exchange = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'GSSAPIClientIdentity') {
				configs[current_host].gss_api_client_identity = property_value
			}

			if compare_strings(property_name, 'GSSAPIDelegateCredentials') {
				configs[current_host].gss_api_delegate_credentials = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'GSSAPIRenewalForcesRekey') {
				configs[current_host].gss_api_renewal_forces_rekey = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'GSSAPITrustDns') {
				configs[current_host].gss_api_trust_dns = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'HashKnownHosts') {
				configs[current_host].hash_known_hosts = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'HostbasedAuthentication') {
				configs[current_host].hostbased_authentication = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'HostKeyAlgorithms') {
				configs[current_host].host_key_algorithms = property_value
			}

			if compare_strings(property_name, 'HostKeyAlias') {
				configs[current_host].host_key_alias = property_value
			}

			if compare_strings(property_name, 'HostName') {
				configs[current_host].hostname = property_value
			}

			if compare_strings(property_name, 'IdentitiesOnly') {
				configs[current_host].identities_only = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'IdentityFile') {
				configs[current_host].identity_file = property_value
			}

			if compare_strings(property_name, 'KbdInteractiveAuthentication') {
				configs[current_host].kbd_interactive_authentication = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'KbdInteractiveDevices') {
				configs[current_host].kbd_interactive_devices = property_value.to_lower()
			}

			if compare_strings(property_name, 'LocalCommand') {
				configs[current_host].local_command = property_value
			}

			if compare_strings(property_name, 'LocalForward') {
				configs[current_host].local_forward = property_value
			}

			if compare_strings(property_name, 'LogLevel') {
				configs[current_host].log_level = property_value.to_upper()
			}

			if compare_strings(property_name, 'MACs') {
				configs[current_host].macs = property_value
			}

			if compare_strings(property_name, 'NumberOfPasswordPrompts') {
				configs[current_host].number_of_password_prompts = property_value.int()
			}

			if compare_strings(property_name, 'PasswordAuthentication') {
				configs[current_host].password_authentication = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'PermitLocalCommand') {
				configs[current_host].permit_local_command = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'Port') {
				configs[current_host].port = property_value.int()
			}

			if compare_strings(property_name, 'PreferredAuthentications') {
				configs[current_host].preferred_authentications = property_value
			}

			if compare_strings(property_name, 'Protocol') {
				configs[current_host].protocol = property_value
			}

			if compare_strings(property_name, 'ProxyCommand') {
				configs[current_host].proxy_command = property_value
			}

			if compare_strings(property_name, 'RekeyLimit') {
				configs[current_host].rekey_limit = property_value
			}

			if compare_strings(property_name, 'RemoteForward') {
				configs[current_host].remote_forward = property_value
			}

			if compare_strings(property_name, 'RhostsRSAAuthentication') {
				configs[current_host].rhosts_rsa_authentication = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'RSAAuthentication') {
				configs[current_host].rsa_authentication = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'SendEnv') {
				configs[current_host].send_env = property_value
			}

			if compare_strings(property_name, 'ServerAliveCountMax') {
				configs[current_host].server_alive_count_max = property_value.int()
			}

			if compare_strings(property_name, 'ServerAliveInterval') {
				configs[current_host].server_alive_interval = property_value.int()
			}

			if compare_strings(property_name, 'SmartcardDevice') {
				configs[current_host].smartcard_device = property_value
			}

			if compare_strings(property_name, 'StrictHostKeyChecking') {
				configs[current_host].strict_host_key_checking = property_value.to_lower()
			}

			if compare_strings(property_name, 'TCPKeepAlive') {
				configs[current_host].tcp_keep_alive = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'Tunnel') {
				configs[current_host].tunnel = property_value
			}

			if compare_strings(property_name, 'TunnelDevice') {
				configs[current_host].tunnel_device = property_value
			}

			if compare_strings(property_name, 'UsePrivilegedPort') {
				configs[current_host].use_privileged_port = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'User') {
				configs[current_host].user = property_value
			}

			if compare_strings(property_name, 'UserKnownHostsFile') {
				configs[current_host].user_known_hosts_file = property_value
			}

			if compare_strings(property_name, 'VerifyHostKeyDNS') {
				configs[current_host].verify_host_key_dns = property_value
			}

			if compare_strings(property_name, 'VisualHostKey') {
				configs[current_host].visual_host_key = property_to_bool(property_value)
			}

			if compare_strings(property_name, 'XAuthLocation') {
				configs[current_host].xauth_location = property_value
			}
		}
	}

	return configs
}

fn is_include_declaration(value string) bool {
	return value.to_lower().starts_with('include ')
}

fn is_host_declaration(value string) bool {
	return value.to_lower().starts_with('host ')
}

fn is_property_declaration(property string) bool {
	clean_property := property.trim_space()
	is_property_empty := clean_property.len == 0
	has_indent := property.starts_with(' ') || property.starts_with('\t')

	return !is_property_empty && has_indent
}

fn compare_strings(x string, y string) bool {
	return x.to_lower() == y.to_lower()
}

fn property_to_bool(property string) bool {
	return property.to_lower() == 'yes'
}

fn get_default_config(host string) SshConfig {
	return SshConfig{
		host: host
		// default values from specification
		challenge_response_authentication: true
		check_host_ip: true
		compression_level: 6
		connection_attempts: 1
		escape_char: '~'
		global_known_hosts_file: '/etc/ssh/ssh_known_hosts'
		log_level: 'INFO'
		kbd_interactive_authentication: true
		number_of_password_prompts: 3
		password_authentication: true
		port: 22
		rsa_authentication: true
		server_alive_count_max: 3
		strict_host_key_checking: 'ask'
		tunnel: 'no'
		tunnel_device: 'any:any'
		verify_host_key_dns: 'no'
	}
}

fn merge_configs(mut x map[string]SshConfig, y map[string]SshConfig) {
	for host, config in y {
		x[host] = config
	}
}
