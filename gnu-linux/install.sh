#!/bin/bash
#
# Installation script for Pombo.
#

SRC_DIR=$(dirname "$(dirname "$(readlink -f "$0")")")
declare ARG_INSTALL_REQUIRED=0
declare INST_DIR=/usr/local/bin
[ -d ${INST_DIR} ] || INST_DIR=/usr/local/sbin

# Given a set of arguments, split single char flags apart
# E.g. "-vv -glt -- -bt --read-only myfile.txt" => "-v -v -g -l -t -bt --read-only myfile.txt"
split_flags() {
    declare STOPFLAG=0
    declare -a NEWARGS
    while [[ $# -gt 0 ]]; do
        if [[ $1 == '--' ]]; then
            STOPFLAG=1
        elif [[ $STOPFLAG -eq 0 && $1 =~ ^-([a-zA-Z0-9]*)$ ]]; then
            while IFS= read -r -n1 FLAG; do
                if [[ -n $FLAG ]]; then
                    NEWARGS+=("-${FLAG}")
                fi
            done <<< "${BASH_REMATCH[1]}"
        else
            NEWARGS+=("$1")
        fi
        shift
    done
    echo -n "${NEWARGS[@]}"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
        -i|--install-reqs)
            ARG_INSTALL_REQUIRED=1
            shift
            ;;
        *)
            die "Unexpected argument: $1"
            ;;
        esac
    done
}

check_root() {
    if [ $(id -ru) -ne 0 ]; then
        echo "! You need to have root rights !"
        exit 1
    fi
}

assert_required_packages() {
    echo "Shell script uses Python $(python --version)"
    PACKAGES=()
    which python3 >/dev/null 2>&1 || PACKAGES+=("python3")
    which traceroute >/dev/null 2>&1 || PACKAGES+=("traceroute")
    which ifconfig >/dev/null 2>&1 || PACKAGES+=("net-tools")
    which streamer >/dev/null 2>&1 || PACKAGES+=("streamer")
    which gpg2 >/dev/null 2>&1 || PACKAGES+=("gnupg2")
    dpkg -s python3-venv >/dev/null 2>&1 || PACKAGES+=("python3-venv")

    if [ ${#PACKAGES[@]} -ne 0 ]; then
        echo "The following required packages are missing:" >&2
        for cmd in "${PACKAGES[@]}"; do
            echo "  - $cmd" >&2
        done
        if [ $ARG_INSTALL_REQUIRED -eq 1 ]; then
            echo "Please install missing packages"
            sudo apt install -y "${PACKAGES[@]}"
        else
            echo "Please install missing packages or pass the -i|--install-reqs for the script to install them"
            exit 1
        fi
    fi
}

set_environment() {
    ok=0
    python3 -m venv /opt/pombo-venv || (ok=1 && echo "Error while creating venv")
    /opt/pombo-venv/bin/pip install packaging IPy mss requests || (ok=2 && echo "Error while installing python modules")
    /opt/pombo-venv/bin/python ${SRC_DIR}/tools/check-imports.py || (ok=3 && echo "Required python modules not loaded")
    return $ok
}

main() {
    echo ""
    echo "Installing (verbose) ..."
    [ -f /etc/pombo.conf ] && mv -fv /etc/pombo.conf /etc/pombo.conf.$(date '+%s')
    install -v ${SRC_DIR}/pombo.conf /etc
    echo "« chmod 600 /etc/pombo.conf »"
    chmod 600 /etc/pombo.conf
    install -v ${SRC_DIR}/pombo.py ${INST_DIR}/pombo
    echo "« chmod +x ${INST_DIR}/pombo »"
    chmod +x ${INST_DIR}/pombo

    if test -f /etc/crontab ; then
        # Retro-compatibility (version <= 0.0.9)
        if [ $(grep -c "/usr/local/bin/pombo" /etc/crontab) != 0 ] ; then
            echo "« sed -i '/usr/local/bin/pombo/d' /etc/crontab »"
            sed -i '\/usr\/local\/bin\/pombo/d' /etc/crontab
        fi
    fi

    [ -f /etc/cron.d/pombo ] && rm -fv /etc/cron.d/pombo
    # Launch Pombo on boot
    echo "« @reboot root sleep 10 && /opt/pombo-venv/bin/python ${INST_DIR}/pombo >>/etc/cron.d/pombo »"
    echo "@reboot root sleep 10 && /opt/pombo-venv/bin/python ${INST_DIR}/pombo" >>/etc/cron.d/pombo
    # Launch Pombo every 15 minutes
    echo "« */15 * * * * root /opt/pombo-venv/bin/python ${INST_DIR}/pombo >>/etc/cron.d/pombo »"
    echo "*/15 * * * * root /opt/pombo-venv/bin/python ${INST_DIR}/pombo" >>/etc/cron.d/pombo
    [ -f /var/local/pombo ] && rm -fv /var/local/pombo
    echo "Done."

    echo ""
    echo "Creating venv and installing dependencies ..."
    if set_environment; then
        echo "Done."
    fi

    cat <<EOM

    Thank you to use Pombo!
    Then you will need to:
        1 - to enable encryption, import your GnuPG keyID
        2 - tune options into /etc/pombo.conf
        3 - tune variables into pombo.php
        4 - copy pombo.php to your server(s) (both PHP versions 4 & 5 supported)
    And do not forget to write somewhere in security your computer Serial Number.

EOM
}

check_root
# shellcheck disable=SC2046
parse_args $(split_flags "$@")
assert_required_packages
main
exit 0
