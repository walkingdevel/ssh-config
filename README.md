# Install.

```sh
v install https://github.com/walkingdevel/ssh-config
```

# Usage.

```v
import ssh_config

fn main() {
	configs := ssh_config.parse_ssh_config_file('/Users/user/.ssh/config') or { panic(err) }

	println(configs.keys())
}
```
