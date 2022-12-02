# Install.

```sh
v install https://github.com/walkingdevel/ssh-config
```

# Usage.

```v
import ssh_config

fn main() {
	configs := ssh_config.parse_ssh_config_file('/Users/user/.ssh/config') or { panic(err) }

	postgres_config := configs['postgres']

	println(configs.keys())
	println(postgres_config.hostname)
	println(postgres_config.user)
	println(postgres_config.port)
}
```
