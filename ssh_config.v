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
	control_master                    string [to_lower_case]
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
	kbd_interactive_devices           string [to_lower_case]
	local_command                     string
	local_forward                     string
	log_level                         string [to_upper_case]
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
	strict_host_key_checking          string [to_lower_case]
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

			$for field in SshConfig.fields {
				field_name := field.name
				config_param := convert_structure_field_name_to_config_param(field_name)

				$if field.typ is bool {
					if compare_strings(property_name, config_param) {
						configs[current_host].$(field.name) = property_to_bool(property_value)
					}
				}

				$if field.typ is int {
					if compare_strings(property_name, config_param) {
						configs[current_host].$(field.name) = property_value.int()
					}
				}

				$if field.typ is string {
					if compare_strings(property_name, config_param) {
						if 'to_lower_case' in field.attrs {
							configs[current_host].$(field.name) = property_value.to_lower()
						} else if 'to_upper_case' in field.attrs {
							configs[current_host].$(field.name) = property_value.to_upper()
						} else {
							configs[current_host].$(field.name) = property_value
						}
					}
				}
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

fn convert_structure_field_name_to_config_param(name string) string {
	return name.replace('_', '')
}
