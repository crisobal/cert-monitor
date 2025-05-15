# Cert-Monitor

**Still work in progress**


## Purpose
Monitors a list of tls target servers. The list of servers can be provided by a config file. 
TThe vertificates of the monitored target severs are checked if their remaining lifetime is 
at least a given value.

## Usage

```
Usage: cert-monitor <COMMAND>

Commands:
  install-service  Installs the Windows service
  monitor          Monitors all the targes given in the sites config file
  check            Checks the target given on the command line
  help             Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Check a single target server
```
Usage: cert-monitor check [OPTIONS] --target-host <target_host>

Options:
  -t, --target-host <target_host>  Full qualified target host to query
  -p, --target-port <target_port>  Port of the service at target host [default: 443]
  -o, --cert-output                Output the certificate instead of the table
  -h, --help                       Print help
```

### Monitor target servers

To monitor a list of target servers for certificate expiration use the monitor command.  

```
Usage: cert-monitor monitor [OPTIONS] --config-file <FILE>

Options:
  -c, --config-file <FILE>         config file
  -i, --interval-hours <interval>  monitor interval
  -d, --daemon                     Daemon mode without verbose console output but log entries instead
  -o, --cert-output                Output the certificate instead of the table
  -h, --help                       Print help
```


In the config file you can provide 0..n target sites to monitor. The config file looks like this:

```json
{
  "logTarget": "monitor",
  "sites": [   
    {
      "targetFqn": "www.tschirky.ch",
      "service": "flup",
      "port": 443,
      "minValidDays": 15
    },
    {
      "targetFqn": "www.fhr.ch",
      "service": "other",
      "port": 443,
      "minValidDays": 15
    }    
  ]
}
```

## ToDo
Open points:
- "logTarget" in sites.json not implemented
- Service installation not implemented. could also get removed in the future as it would potentially be windows 
specific as for Linux it would be better to provide systemd service files to install. 