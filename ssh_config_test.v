module ssh_config

fn test_parse_empty_config() {
	config := parse_config_file('./fixtures/.ssh/empty') or { panic(err) }

	assert config.keys().len == 0
}

fn test_parse_standart_config() {
	config := parse_config_file('./fixtures/.ssh/standart') or { panic(err) }
	postgres_config := config['postgres']

	assert postgres_config.host == 'postgres'
	assert postgres_config.hostname == '1.1.1.1'
	assert postgres_config.user == 'app'
	assert postgres_config.port == 22
}

fn test_parse_local_forward_config() {
	config := parse_config_file('./fixtures/.ssh/local-forward') or { panic(err) }
	kibana_config := config['kibana']

	assert kibana_config.host == 'kibana'
	assert kibana_config.hostname == '2.2.2.2'
	assert kibana_config.user == 'root'
	assert kibana_config.compression
	assert kibana_config.local_forward == '5601 127.0.0.1:5601'
}

fn test_parse_non_standart_config() {
	config := parse_config_file('./fixtures/.ssh/non-standart') or { panic(err) }
	server_config := config['server']

	assert server_config.host == 'server'
	assert server_config.hostname == '2.2.2.2'
	assert server_config.user == 'root'
	assert server_config.password_authentication
	assert server_config.user_known_hosts_file == '/test/path'
}
