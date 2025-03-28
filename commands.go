package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

type readLiner interface {
	ReadLine() (string, error)
}

type commandContext struct {
	args           []string
	stdin          readLiner
	stdout, stderr io.Writer
	pty            bool
	user           string
}

type command interface {
	execute(context commandContext) (uint32, error)
}

var commands = map[string]command{
	"sh":    cmdShell{},
	"bash":  cmdShell{},
	"true":  cmdTrue{},
	"false": cmdFalse{},
	"echo":  cmdEcho{},
	"cat":   cmdCat{},
	"su":    cmdSu{},
}

var shellProgram = []string{"bash"}

func executeProgram(context commandContext) (uint32, error) {
	if len(context.args) == 0 {
		return 0, nil
	}
	fmt.Println("receive command", context.args)
	command := commands[context.args[0]]
	if command == nil {
		// _, err := fmt.Fprintf(context.stderr, "%v: command not found\n", context.args[0])
		// return 127, err
		return 0, nil
	}
	return command.execute(context)
}

type cmdShell struct{}

func (cmdShell) execute(context commandContext) (uint32, error) {
	var prompt string
	if context.pty {
		switch context.user {
		case "root":
			prompt = "root@DGX-A100:~# "
		default:
			prompt = "(base) " + context.user + "@DGX-A100:~$ "
		}
	}
	var lastStatus uint32
	var line string
	var err error
	for {
		_, err = fmt.Fprint(context.stdout, prompt)
		if err != nil {
			return lastStatus, err
		}
		line, err = context.stdin.ReadLine()
		if err != nil {
			return lastStatus, err
		}
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}
		if args[0] == "exit" {
			var err error
			var status uint64 = uint64(lastStatus)
			if len(args) > 1 {
				status, err = strconv.ParseUint(args[1], 10, 32)
				if err != nil {
					status = 255
				}
			}
			return uint32(status), nil
		}
		newContext := context
		newContext.args = args
		if lastStatus, err = executeProgram(newContext); err != nil {
			return lastStatus, err
		}
	}
}

type cmdTrue struct{}

func (cmdTrue) execute(context commandContext) (uint32, error) {
	return 0, nil
}

type cmdFalse struct{}

func (cmdFalse) execute(context commandContext) (uint32, error) {
	return 1, nil
}

type cmdEcho struct{}

func (cmdEcho) execute(context commandContext) (uint32, error) {
	_, err := fmt.Fprintln(context.stdout, strings.Join(context.args[1:], " "))
	return 0, err
}

type cmdCat struct{}

var etcpasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:996:996:systemd Time Synchronization:/:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
syslog:x:102:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:991:991:systemd Resolver:/:/usr/sbin/nologin
uuidd:x:103:103::/run/uuidd:/usr/sbin/nologin
usbmux:x:104:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
tss:x:105:105:TPM software stack,,,:/var/lib/tpm:/bin/false
systemd-oom:x:990:990:systemd Userspace OOM Killer:/:/usr/sbin/nologin
kernoops:x:106:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
whoopsie:x:107:109::/nonexistent:/bin/false
dnsmasq:x:999:65534:dnsmasq:/var/lib/misc:/usr/sbin/nologin
avahi:x:108:111:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
tcpdump:x:109:112::/nonexistent:/usr/sbin/nologin
sssd:x:110:113:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
cups-pk-helper:x:112:114:user for cups-pk-helper service,,,:/nonexistent:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
saned:x:113:116::/var/lib/saned:/usr/sbin/nologin
geoclue:x:114:117::/var/lib/geoclue:/usr/sbin/nologin
cups-browsed:x:115:114::/nonexistent:/usr/sbin/nologin
hplip:x:116:7:HPLIP system user,,,:/run/hplip:/bin/false
gnome-remote-desktop:x:988:988:GNOME Remote Desktop:/var/lib/gnome-remote-desktop:/usr/sbin/nologin
polkitd:x:987:987:User for polkitd:/:/usr/sbin/nologin
rtkit:x:117:119:RealtimeKit,,,:/proc:/usr/sbin/nologin
colord:x:118:120:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
gnome-initial-setup:x:119:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:120:121:Gnome Display Manager:/var/lib/gdm3:/bin/false
nm-openvpn:x:121:122:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
nvidia-persistenced:x:122:124:NVIDIA Persistence Daemon,,,:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
sshd:x:123:65534::/run/sshd:/usr/sbin/nologin
ollama:x:997:984::/usr/share/ollama:/bin/false`

func (cmdCat) execute(context commandContext) (uint32, error) {
	if len(context.args) > 1 {
		for _, file := range context.args[1:] {
			if file == "/etc/passwd" {
				if _, err := fmt.Fprintln(context.stdout, etcpasswd); err != nil {
					return 0, err
				}
			} else {
				// 这里要编
				if _, err := fmt.Fprintf(context.stderr, "%v: %v: No such file or directory\n", context.args[0], file); err != nil {
					return 0, err
				}
			}
		}
		return 1, nil
	}
	var line string
	var err error
	for err == nil {
		line, err = context.stdin.ReadLine()
		if err == nil {
			_, err = fmt.Fprintln(context.stdout, line)
		}
	}
	return 0, err
}

type cmdSu struct{}

func (cmdSu) execute(context commandContext) (uint32, error) {
	newContext := context
	newContext.user = "root"
	if len(context.args) > 1 {
		newContext.user = context.args[1]
	}
	newContext.args = shellProgram
	return executeProgram(newContext)
}
