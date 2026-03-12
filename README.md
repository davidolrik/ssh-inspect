# ssh-inspect

Shows the SSH configuration that applies to a given hostname, separating global (`Host *`) settings from host-specific ones. Only user-defined options are shown — SSH built-in defaults are excluded.

## Install

### mise

```sh
mise use -g github:davidolrik/ssh-inspect
```

### go install

```sh
go install github.com/davidolrik/ssh-inspect@latest
```

### Build from source

```sh
git clone https://github.com/davidolrik/ssh-inspect.git
cd ssh-inspect
go build -o ssh-inspect .
```

## Usage

```sh
ssh-inspect <hostname>
```

### Example

```sh
$ ssh-inspect myserver
Host *
    AddKeysToAgent       true
    ControlMaster        auto
    ControlPath          ~/.ssh/control/%h__%p__%r
    IdentityFile         ~/.ssh/id_ed25519

Host myserver
    Hostname             myserver.example.com
    User                 deploy
    Port                 2222
    IdentityFile         ~/.ssh/deploy_key
    ProxyJump            bastion
```

The output is a valid SSH config format. `Host *` options are shown first (sorted alphabetically), followed by host-specific blocks with priority keys (Hostname, User, Port, IdentityFile, ProxyJump) listed first. If the host uses `ProxyJump`, each hop in the chain gets its own block.

When stdout is a terminal, output is syntax-highlighted with ANSI colors. Set `NO_COLOR` to disable.

## Shell completion

Tab completion for hostnames is available, sourced from your SSH config and `known_hosts` files.

```sh
# Bash
ssh-inspect completion bash > /etc/bash_completion.d/ssh-inspect

# Zsh
ssh-inspect completion zsh > "${fpath[1]}/_ssh-inspect"

# Fish
ssh-inspect completion fish > ~/.config/fish/completions/ssh-inspect.fish
```

## How it works

`ssh-inspect` uses `ssh -G` to query the fully resolved SSH configuration for a hostname. To isolate user-defined settings from SSH defaults, it queries a random non-matching hostname as a baseline and diffs the two. `Host *` and `Match all` blocks are detected by temporarily modifying the config so the baseline hostname is excluded from wildcard matching. Raw (un-interpolated) values are preserved for wildcard options that contain tokens like `%h` or `%p`.

## Requirements

- OpenSSH `ssh` in `PATH`
- Go 1.26.1 or later (to build from source)
