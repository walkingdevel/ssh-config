module ssh_config

import os

// SshConfig represents a parsed SSH configuration.
pub struct SshConfig {
pub mut:
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

// parse_file parses an SSH configuration file. The current working directory is used as the base path for relative include paths.
pub fn parse_file(path string) !map[string]SshConfig {
	absolute_path := os.abs_path(os.dir(path))

	config_raw := os.read_file(path)!
	return parse_with_path(absolute_path, config_raw)
}

// parse parses an SSH configuration string. Includes are ignored.
pub fn parse(config_raw string) !map[string]SshConfig {
	return parse_with_path('', config_raw)
}

// parse_with_path parses an SSH configuration string. The base path is used as the base path for
// relative include paths. ıf the base path is empty, includes are ignored.
pub fn parse_with_path(path string, config_raw string) !map[string]SshConfig {
	// parsed SSH configurations
	mut configs := map[string]SshConfig{}
	// the current host being parsed
	mut current_host := ''

	for config_line in config_raw.split_into_lines() {
		config_line_lower := config_line.to_lower()
		config_line_lower_trimmed := config_line_lower.trim_space()

		// skip empty lines and comments
		if config_line_lower_trimmed.starts_with('#') || config_line_lower_trimmed.len == 0 {
			continue
		}

		line_parts := config_line.trim_space().split_nth(' ', 2)

		// ignore invalid lines, lines must be "<ident> <value>"
		if line_parts.len < 2 {
			continue
		}

		// handle include statements, ignore if no path is set
		if config_line_lower.starts_with('include ') && path != '' {
			include_path := line_parts[1]

			absolute_path := if include_path.starts_with('/') {
				include_path
			} else {
				os.join_path(path, include_path)
			}

			include_configs := parse_file(absolute_path)!
			merge_configs(mut configs, include_configs)
		}

		// handle host declarations
		if config_line_lower.starts_with('host ') {
			host := line_parts[1]

			current_host = host
			configs[host] = get_default_config(host)
		}

		// handle property declarations
		// ignore property declarations if no host is set
		if is_property_declaration(config_line_lower) && current_host != '' {
			property_name_lower := line_parts.first().to_lower()
			property_value := line_parts[1]

			$for field in SshConfig.fields {
				if property_name_lower == field.name.replace('_', '') {
					$if field.typ is bool {
						configs[current_host].$(field.name) = property_to_bool(property_value.to_lower())
					}

					$if field.typ is int {
						configs[current_host].$(field.name) = property_value.int()
					}

					$if field.typ is string {
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

fn is_property_declaration(property string) bool {
	clean_property := property.trim_space()
	is_property_empty := clean_property.len == 0

	// properties must be indented
	return !is_property_empty && (property.starts_with(' ') || property.starts_with('\t'))
}

fn property_to_bool(property string) bool {
	return property == 'yes'
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
