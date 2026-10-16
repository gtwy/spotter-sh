// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"context"
	"os/exec"
	"strings"
)

func (in Input) decideInfra(name string, argv []string) Outcome {
	switch name {
	case "docker":
		return in.decideDocker(argv)
	case "kubectl":
		return in.decideKubectl(argv)
	case "helm":
		if len(argv) > 1 && (argv[1] == "uninstall" || argv[1] == "delete") {
			return in.danger("F", "helm uninstall", "removes a release", "uninstall drops the release's resources", "uninstall one release you named on purpose", nil, "helm uninstall")
		}
	case "terraform":
		return in.decideTerraform(argv)
	case "aws":
		if hasSub(argv, "--recursive") && containsArg(argv, "rm") {
			return in.danger("F", "aws s3 rm --recursive", "deletes a bucket prefix", "recursive s3 rm is a bulk delete", "rm one key, or sync with --dryrun first", nil, "aws s3 rm")
		}
	case "gsutil":
		if containsArg(argv, "rm") && (hasShort(argv, 'r') || hasSub(argv, "-r")) {
			return in.danger("F", "gsutil rm -r", "recursive object delete", "rm -r walks a prefix", "name the objects", nil, "gsutil rm")
		}
	case "gcloud":
		if containsArg(argv, "delete") {
			return in.danger("F", "gcloud delete", "deletes a cloud resource", "delete is not reversible", "confirm the resource name", nil, "gcloud delete")
		}
	case "crontab":
		if hasShort(argv, 'r') || hasSub(argv, "-r") {
			return in.danger("F", "crontab -r", "removes the whole crontab", "-r is next to -e", "use crontab -e", nil, "crontab -r")
		}
	case "systemctl":
		return in.decideSystemctl(argv)
	case "iptables":
		if hasShort(argv, 'F') || hasSub(argv, "--flush") || containsArg(argv, "-F") {
			return in.danger("F", "iptables -F", "flushes firewall rules", "the host can become unreachable", "delete one rule", nil, "iptables -F")
		}
	case "userdel":
		if hasShort(argv, 'r') {
			return in.danger("F", "userdel -r", "deletes a user and their home", "-r removes the home directory", "userdel without -r, then remove files yourself", nil, "userdel -r")
		}
	}
	return allow()
}

func (in Input) decideDocker(argv []string) Outcome {
	if len(argv) < 2 {
		return allow()
	}
	// docker rm -v, docker volume rm, docker system prune -a --volumes, docker compose down -v
	args := argv[1:]
	if args[0] == "rm" && (hasShort(argv, 'v') || hasSub(argv, "--volumes")) {
		return in.danger("F", "docker rm -v", "removes containers and their volumes", "volumes hold the data", "docker rm without -v", nil, "docker rm -v")
	}
	if args[0] == "volume" && len(args) > 1 && args[1] == "rm" {
		return in.danger("F", "docker volume rm", "deletes a volume", "volume data does not come back", "confirm the volume name", nil, "docker volume rm")
	}
	if args[0] == "system" && len(args) > 1 && args[1] == "prune" {
		a := hasShort(argv, 'a') || hasSub(argv, "--all")
		v := hasSub(argv, "--volumes")
		if a && v {
			return in.danger("F", "docker system prune", "prunes images and volumes", "this deletes unused volumes", "prune without --volumes", nil, "docker system prune")
		}
	}
	if args[0] == "compose" && containsArg(args, "down") && (hasShort(argv, 'v') || hasSub(argv, "--volumes")) {
		return in.danger("F", "docker compose down -v", "removes compose volumes", "down -v deletes named volumes", "docker compose down", nil, "compose down -v")
	}
	if args[0] == "compose" && len(args) > 1 && args[1] == "down" && hasSub(argv, "-v") {
		return in.danger("F", "docker compose down -v", "removes compose volumes", "down -v deletes named volumes", "docker compose down", nil, "compose down -v")
	}
	return allow()
}

func (in Input) decideKubectl(argv []string) Outcome {
	if len(argv) < 2 || argv[1] != "delete" {
		return allow()
	}
	all := hasSub(argv, "--all") || hasSub(argv, "-A") || hasSub(argv, "--all-namespaces")
	ns := false
	for i, w := range argv {
		if w == "ns" || w == "namespace" || w == "namespaces" {
			ns = true
		}
		if w == "-n" || w == "--namespace" {
			_ = i
		}
	}
	if all || ns {
		return in.danger("F", "kubectl delete", "deletes namespaced or all resources", "--all and namespace deletes are wide", "name one resource", nil, "kubectl delete")
	}
	return allow()
}

func (in Input) decideTerraform(argv []string) Outcome {
	if len(argv) < 2 {
		return allow()
	}
	sub := argv[1]
	if sub == "destroy" || hasSub(argv, "-destroy") {
		return in.danger("F", "terraform destroy", "destroys infrastructure", "destroy removes real resources", "review a plan first", nil, "terraform destroy")
	}
	if sub == "apply" && (hasSub(argv, "-auto-approve") || hasSub(argv, "--auto-approve")) {
		// Without a live plan we cannot see deletions. A missing plan is
		// unclassifiable and allowed; a timeout would be a catch. The argv
		// itself is the common accident, so auto-approve is a danger catch.
		return in.danger("F", "terraform apply -auto-approve", "applies a plan without a prompt", "auto-approve hides deletions", "apply without -auto-approve", nil, "terraform apply")
	}
	return allow()
}

func (in Input) decideSystemctl(argv []string) Outcome {
	verb, units, user := parseSystemctl(argv)
	switch verb {
	case "poweroff", "reboot", "halt":
		return in.decidePower("systemctl "+verb, argv)
	case "stop", "disable":
		if len(units) == 0 {
			return in.danger("F", "systemctl "+verb, verb+" with no unit", "stopping the wrong unit drops a service", "name the unit", nil, "systemctl "+verb)
		}
		for _, unit := range units {
			active, timed := in.unitActive(unit, user)
			if timed {
				return in.timeoutCatch("systemctl "+verb, 0)
			}
			if active {
				return in.danger("F", "systemctl "+verb, verb+" running unit "+unit, "the unit is running", "name the unit and prefer restart when you mean reload", []string{unit}, "systemctl "+verb)
			}
		}
	}
	return allow()
}

func parseSystemctl(argv []string) (verb string, units []string, user bool) {
	args := argv[1:]
	for i := 0; i < len(args); i++ {
		w := args[i]
		if w == "--" {
			units = append(units, args[i+1:]...)
			break
		}
		switch w {
		case "--user":
			user = true
			continue
		case "--system", "--no-block", "--now", "--quiet", "-q", "--no-ask-password", "--runtime":
			continue
		}
		if strings.HasPrefix(w, "-") {
			if w == "-t" || w == "--type" || w == "-H" || w == "--host" || w == "-M" || w == "--machine" || w == "-p" || w == "--property" {
				if i+1 < len(args) {
					i++
				}
			}
			continue
		}
		if verb == "" {
			verb = w
			continue
		}
		units = append(units, w)
	}
	return verb, units, user
}

func (in Input) unitActive(unit string, user bool) (active bool, timed bool) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout(in.Config.ProbeTimeout))
	defer cancel()
	args := []string{"is-active", "--", unit}
	if user {
		args = append([]string{"--user"}, args...)
	}
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	var out []byte
	if err := PrepareChild(cmd); err != nil {
		return false, true
	}
	out, _ = cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return false, true
	}
	text := strings.TrimSpace(string(out))
	return text == "active" || text == "activating", false
}

func (in Input) decidePower(name string, argv []string) Outcome {
	host := in.Hostname
	if host == "" {
		host = "this-host"
	}
	o := in.danger("F", name, "this would power off or reboot "+host, "the command is aimed at the machine you are on", "type the hostname "+host+" to confirm", nil, name)
	o.Affected.Top = []string{host}
	o.Safer = host
	return o
}

func containsArg(argv []string, want string) bool {
	for _, w := range argv {
		if w == want {
			return true
		}
	}
	return false
}
