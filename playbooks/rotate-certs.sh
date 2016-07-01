#!/bin/bash
#### Rotate TLS certs with vault
set -e

# Log to stdout and file
log_file=/tmp/rotate.log
echo "" > "${log_file}"
log() {
    printf "[%s] %s\n" "$1" "$2"
    printf "[%s] %s\n" "$1" "$2" >> "${log_file}"
    if [[ $1 == "ERR" ]]; then exit 1; fi
}

log INFO "Beginning cert rotation..."
log INFO "Parsing options..."

## Options

# Defaults
common_name=$(hostname)
ttl=8760h
acl_path=rotate-certs

OPTS=$(getopt -n rotate-certs -l log-file:,common-name:,alt-names:,ip-sans:,ttl:,acl-path:,acl-token:,role:,vault-addr:,vault-cacert:,vault-token: -- "$0" "$@")
if [ $? -ne 0 ]; then
	  log ERR "Error parsing options."
fi
eval set -- "${OPTS}"

max=50
original_options=$*
while :; do
    if [[ $max -eq 0 ]]; then
        log DEBUG "Options were $original_options"
        log ERR "Infinite loop detected while parsing options!"
    fi
    max=$((max-1))

	  case "$1" in
	      --log-file) log_file="$2"; shift 2 ;;
	      --common-name)  common_name="$2"; shift 2;;
	      --alt-names)  alt_names="$2"; shift 2;;
	      --ip-sans)  ip_sans="$2"; shift 2;;
        --ttl)  ttl="$2"; shift 2;;
	      --acl-path)  acl_path="$2"; shift 2;;
	      --acl-token)  acl_token="$2"; shift 2;;
	      --role)  role="$2"; shift 2;;
	      --vault-addr)  vault_addr="$2"; shift 2;;
	      --vault-cacert)  vault_cacert="$2"; shift 2;;
	      --vault-token)  vault_token="$2"; shift 2;;
	      --) log INFO "Reached end of options"; shift; break;;
	  esac
done

log INFO "Parsed options."
log INFO "Validating options..."

# Required
[[ -z ${alt_names} ]] && log ERR "--alt-names must be provided"
[[ -z ${ip_sans} ]] && log ERR "--ip-sans must be provided"
[[ -z ${acl_token} ]] && log ERR "--acl-token must be provided"
[[ -z ${role} ]] && log ERR "--role must be provided"

# Optional
[[ -z ${log_file} ]] && log INFO "--log-file not provided, using ${log_file}"
[[ -z ${common_name} ]] && log INFO "common_name not provided, using ${common_name}"
[[ -z ${ttl} ]] && log INFO "ttl not provided, using ${ttl}"
[[ -z ${acl_path} ]] && log INFO "--acl-path not provided, using ${acl_path}"

# Environmental
if [[ -z ${vault_addr} ]]; then
    if [[ -z $VAULT_ADDR ]]; then
        vault_addr=https://vaul.service.consul:8200
        log INFO "--vault-addr and VAULT_ADDR not provided, using ${vault_addr}"
    else
        log INFO "--vault-addr not provided, using VAULT_ADDR environment variable"
        vault_addr=$VAULT_ADDR
    fi
fi

if [[ -z ${vault_cacert} ]]; then
    if [[ -z $VAULT_CACERT ]]; then
        log INFO "--vault-cacert and VAULT_CACERT not provided, none will be used"
    else
        log INFO "--vault-cacert not provided, using VAULT_CACERT environment variable"
        vault_cacert=$VAULT_CACERT
    fi
fi

if [[ -z ${vault_token} ]]; then
    if [[ -z $VAULT_TOKEN ]]; then
        log ERR "--vault-token or VAULT_TOKEN must be provided"
    else
        log INFO "--vault-token not provided, using VAULT_TOKEN environment variable"
        vault_token=$VAULT_TOKEN
    fi
fi

log INFO "Obtaining Consul lock..."
session_id=$(consul-cli kv-lock --behavior=release --ttl=10m --lock-delay=1m "${acl_token}")
log INFO "Got Consul lock!"

consul maint -enable -reason "rotating TLS certificates" > /dev/null

## Get new certificate

log INFO "Getting certificate..."

json=$(printf '{"common_name":"%s","alt_names":"%s","ip_sans":"%s","ttl":"%s"}' \
              "${common_name}" "${alt_names}" "${ip_sans}" "${ttl}")
curl_output=$(curl -1sS -X POST \
                   --cacert "${vault_cacert}" \
                   --connect-timeout 10 \
                   --max-time 20 \
                   -H "X-Vault-Token: ${vault_token}" \
                   -H "Content-Type: application/json"
                   -d "$json" \
                   "${vault_addr}/v1/pki/issue" > &1)

# Capture pem cert from vault output
# Write cert to file
log INFO $curl_output
exit 1

## Reboot services

services=("consul" "nginx-consul")
case "$role" in
	  worker)
        services=( ${services[@]} "docker")
        ;;
	  control)
        services=( ${services[@]} "docker" "kubelet" "nginx-mantlui" "marathon" "vault")
        ;;
	  edge)
        services=( ${services[@]} "traefik")
        ;;
	  kubeworker)
        services=( ${services[@]} "docker" "kubelet")
        ;;
	  *) log ERR "$(printf "Unsupported role '%s'\n" "$role")" ;;
esac

for service in "${services[@]}"; do
    if ! sudo systemctl reload "${service}"; then
        log INFO "$(printf "Service '%s' couldn't be reloaded, restarting..." "$service")"
        sudo systemctl restart "${service}"
    fi
done

## Clean up

consul-cli kv-unlock "$1" --session-id "${session_id}"
log INFO $(consul maint -disable)
