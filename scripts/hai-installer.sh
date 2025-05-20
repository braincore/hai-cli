#!/bin/sh
# shellcheck shell=dash

# WARN: Cobbled together by sonnet-3.7 being fed uv's install script and a list
# of hai binaries.

set -u

APP_NAME="hai"
APP_VERSION="v1.6.0"  # Change this line to update the version
INSTALLER_BASE_URL="https://github.com"
ARTIFACT_DOWNLOAD_URL="${INSTALLER_BASE_URL}/braincore/hai-cli/releases/download/${APP_VERSION}"
PRINT_VERBOSE=${INSTALLER_PRINT_VERBOSE:-0}
PRINT_QUIET=${INSTALLER_PRINT_QUIET:-0}
NO_MODIFY_PATH=${HAI_NO_MODIFY_PATH:-0}

usage() {
    cat <<EOF
hai-installer.sh

The installer for hai-cli ${APP_VERSION}

This script detects what platform you're on and fetches an appropriate archive from
${ARTIFACT_DOWNLOAD_URL}
then unpacks the binaries and installs them to the first of the following locations

    \$XDG_BIN_HOME
    \$XDG_DATA_HOME/../bin
    \$HOME/.local/bin

It will then add that dir to PATH by adding the appropriate line to your shell profiles.

USAGE:
    hai-installer.sh [OPTIONS]

OPTIONS:
    -v, --verbose
            Enable verbose output

    -q, --quiet
            Disable progress output

        --no-modify-path
            Don't configure the PATH environment variable

    -h, --help
            Print help information
EOF
}

download_binary_and_run_installer() {
    downloader --check
    need_cmd uname
    need_cmd mktemp
    need_cmd chmod
    need_cmd mkdir
    need_cmd rm
    need_cmd tar
    need_cmd grep
    need_cmd cat

    for arg in "$@"; do
        case "$arg" in
            --help)
                usage
                exit 0
                ;;
            --quiet)
                PRINT_QUIET=1
                ;;
            --verbose)
                PRINT_VERBOSE=1
                ;;
            --no-modify-path)
                say "--no-modify-path has been deprecated; please set HAI_NO_MODIFY_PATH=1 in the environment"
                NO_MODIFY_PATH=1
                ;;
            *)
                OPTIND=1
                if [ "${arg%%--*}" = "" ]; then
                    err "unknown option $arg"
                fi
                while getopts :hvq sub_arg "$arg"; do
                    case "$sub_arg" in
                        h)
                            usage
                            exit 0
                            ;;
                        v)
                            PRINT_VERBOSE=1
                            ;;
                        q)
                            PRINT_QUIET=1
                            ;;
                        *)
                            err "unknown option -$OPTARG"
                            ;;
                        esac
                done
                ;;
        esac
    done

    get_architecture || return 1
    local _true_arch="$RETVAL"
    assert_nz "$_true_arch" "arch"

    # look up what archives support this platform
    local _artifact_name
    _artifact_name="$(select_archive_for_arch "$_true_arch")" || return 1
    local _arch
    local _zip_ext

    # destructure selected archive info into locals
    case "$_artifact_name" in 
        "hai-cli-${APP_VERSION#v}-linux-arm.tar.gz")
            _arch="linux-arm"
            _zip_ext=".tar.gz"
            ;;
        "hai-cli-${APP_VERSION#v}-linux-arm64.tar.gz")
            _arch="linux-arm64"
            _zip_ext=".tar.gz"
            ;;
        "hai-cli-${APP_VERSION#v}-linux-armv7.tar.gz")
            _arch="linux-armv7"
            _zip_ext=".tar.gz"
            ;;
        "hai-cli-${APP_VERSION#v}-linux-x86_64.tar.gz")
            _arch="linux-x86_64"
            _zip_ext=".tar.gz"
            ;;
        "hai-cli-${APP_VERSION#v}-macos-arm64.tar.gz")
            _arch="macos-arm64"
            _zip_ext=".tar.gz"
            ;;
        "hai-cli-${APP_VERSION#v}-macos-x86_64.tar.gz")
            _arch="macos-x86_64"
            _zip_ext=".tar.gz"
            ;;
        "hai-cli-${APP_VERSION#v}-windows-x86_64.zip")
            _arch="windows-x86_64"
            _zip_ext=".zip"
            ;;
        *)
            err "internal installer error: selected download $_artifact_name doesn't exist!?"
            ;;
    esac

    # download the archive
    local _url="$ARTIFACT_DOWNLOAD_URL/$_artifact_name"
    local _dir
    _dir="$(ensure mktemp -d)" || return 1
    local _file="$_dir/input$_zip_ext"

    say "downloading $APP_NAME ${APP_VERSION} ${_arch}" 1>&2
    say_verbose "  from $_url" 1>&2
    say_verbose "  to $_file" 1>&2

    ensure mkdir -p "$_dir"

    if ! downloader "$_url" "$_file"; then
      say "failed to download $_url"
      say "this may be a standard network error, but it may also indicate"
      say "that $APP_NAME's release process is not working. When in doubt"
      say "please feel free to open an issue!"
      exit 1
    fi

    # unpack the archive
    case "$_zip_ext" in
        ".zip")
            ensure unzip -q "$_file" -d "$_dir"
            ;;
        ".tar."*)
            ensure tar xf "$_file" -C "$_dir"
            ;;
        *)
            err "unknown archive format: $_zip_ext"
            ;;
    esac

    # Find the binary inside the extracted directory
    local _bin_dir
    _bin_dir="$(find "$_dir" -type d -name "hai-cli-${APP_VERSION#v}-${_arch}" -print -quit)"
    if [ -z "$_bin_dir" ]; then
        err "could not find the extracted directory in the archive"
    fi

    # Determine the binary name based on platform
    local _bin_name
    if [ "$_arch" = "windows-x86_64" ]; then
        _bin_name="hai.exe"
    else
        _bin_name="hai"
    fi

    # Check if the binary exists
    if [ ! -f "$_bin_dir/$_bin_name" ]; then
        err "could not find the binary in the extracted directory"
    fi

    install "$_bin_dir" "$_bin_name" "$_arch" "$@"
    local _retval=$?
    if [ "$_retval" != 0 ]; then
        return "$_retval"
    fi

    ignore rm -rf "$_dir"
    return 0
}

# Replaces $HOME with the variable name for display to the user,
# only if $HOME is defined.
replace_home() {
    local _str="$1"

    if [ -n "${HOME:-}" ]; then
        echo "$_str" | sed "s,$HOME,\$HOME,"
    else
        echo "$_str"
    fi
}

select_archive_for_arch() {
    local _true_arch="$1"
    local _archive

    case "$_true_arch" in 
        "aarch64-apple-darwin")
            _archive="hai-cli-${APP_VERSION#v}-macos-arm64.tar.gz"
            ;;
        "x86_64-apple-darwin")
            _archive="hai-cli-${APP_VERSION#v}-macos-x86_64.tar.gz"
            ;;
        "aarch64-unknown-linux-gnu" | "aarch64-unknown-linux-musl-static")
            _archive="hai-cli-${APP_VERSION#v}-linux-arm64.tar.gz"
            ;;
        "arm-unknown-linux-gnueabihf" | "arm-unknown-linux-musl-staticeabihf")
            _archive="hai-cli-${APP_VERSION#v}-linux-arm.tar.gz"
            ;;
        "armv7-unknown-linux-gnueabihf" | "armv7-unknown-linux-musl-staticeabihf")
            _archive="hai-cli-${APP_VERSION#v}-linux-armv7.tar.gz"
            ;;
        "x86_64-unknown-linux-gnu" | "x86_64-unknown-linux-musl-static")
            _archive="hai-cli-${APP_VERSION#v}-linux-x86_64.tar.gz"
            ;;
        "x86_64-pc-windows-msvc" | "x86_64-pc-windows-gnu")
            _archive="hai-cli-${APP_VERSION#v}-windows-x86_64.zip"
            ;;
        *)
            err "there isn't a download for your platform $_true_arch"
            ;;
    esac
    
    if [ -n "$_archive" ]; then
        echo "$_archive"
        return 0
    fi
    
    err "no compatible downloads were found for your platform $_true_arch"
}

install() {
    local _install_dir
    local _lib_install_dir
    local _receipt_install_dir
    local _env_script_path
    local _install_dir_expr
    local _env_script_path_expr
    local _force_install_dir
    local _install_layout="flat"
    local _shadowed_bins=""

    # Check if we're overriding the install directory
    if [ -n "${HAI_INSTALL_DIR:-}" ]; then
        _force_install_dir="$HAI_INSTALL_DIR"
    fi

    if [ -n "${_force_install_dir:-}" ]; then
        _install_dir="$_force_install_dir"
        _lib_install_dir="$_force_install_dir"
        _receipt_install_dir="$_install_dir"
        _env_script_path="$_force_install_dir/env"
        _install_dir_expr="$(replace_home "$_force_install_dir")"
        _env_script_path_expr="$(replace_home "$_force_install_dir/env")"
    fi
    
    if [ -z "${_install_dir:-}" ]; then
        # Install to $XDG_BIN_HOME
        if [ -n "${XDG_BIN_HOME:-}" ]; then
            _install_dir="$XDG_BIN_HOME"
            _lib_install_dir="$_install_dir"
            _receipt_install_dir="$_install_dir"
            _env_script_path="$XDG_BIN_HOME/env"
            _install_dir_expr="$(replace_home "$_install_dir")"
            _env_script_path_expr="$(replace_home "$_env_script_path")"
        fi
    fi
    
    if [ -z "${_install_dir:-}" ]; then
        # Install to $XDG_DATA_HOME/../bin
        if [ -n "${XDG_DATA_HOME:-}" ]; then
            _install_dir="$XDG_DATA_HOME/../bin"
            _lib_install_dir="$_install_dir"
            _receipt_install_dir="$_install_dir"
            _env_script_path="$XDG_DATA_HOME/../bin/env"
            _install_dir_expr="$(replace_home "$_install_dir")"
            _env_script_path_expr="$(replace_home "$_env_script_path")"
        fi
    fi
    
    if [ -z "${_install_dir:-}" ]; then
        # Install to $HOME/.local/bin
        if [ -n "${HOME:-}" ]; then
            _install_dir="$HOME/.local/bin"
            _lib_install_dir="$HOME/.local/bin"
            _receipt_install_dir="$_install_dir"
            _env_script_path="$HOME/.local/bin/env"
            _install_dir_expr='$HOME/.local/bin'
            _env_script_path_expr='$HOME/.local/bin/env'
        fi
    fi

    if [ -z "${_install_dir_expr:-}" ]; then
        err "could not find a valid path to install to!"
    fi

    # Fish shell env script path
    _fish_env_script_path="${_env_script_path}.fish"
    _fish_env_script_path_expr="${_env_script_path_expr}.fish"

    say "installing to $_install_dir"
    ensure mkdir -p "$_install_dir"

    # copy the binary to the install dir
    local _src_dir="$1"
    local _bin_name="$2"
    local _arch="$3"
    
    ensure cp "$_src_dir/$_bin_name" "$_install_dir"
    ensure chmod +x "$_install_dir/$_bin_name"
    say "  $_bin_name"

    say "hai installed! just run hai"

    # Avoid modifying the users PATH if they are managing their PATH manually
    case :$PATH:
      in *:$_install_dir:*) NO_MODIFY_PATH=1 ;;
         *) ;;
    esac

    if [ "0" = "$NO_MODIFY_PATH" ]; then
        add_install_dir_to_ci_path "$_install_dir"
        add_install_dir_to_path "$_install_dir_expr" "$_env_script_path" "$_env_script_path_expr" ".profile" "sh"
        exit1=$?
        shotgun_install_dir_to_path "$_install_dir_expr" "$_env_script_path" "$_env_script_path_expr" ".profile .bashrc .bash_profile .bash_login" "sh"
        exit2=$?
        add_install_dir_to_path "$_install_dir_expr" "$_env_script_path" "$_env_script_path_expr" ".zshrc .zshenv" "sh"
        exit3=$?
        # This path may not exist by default
        ensure mkdir -p "$HOME/.config/fish/conf.d"
        exit4=$?
        add_install_dir_to_path "$_install_dir_expr" "$_fish_env_script_path" "$_fish_env_script_path_expr" ".config/fish/conf.d/$APP_NAME.env.fish" "fish"
        exit5=$?

        if [ "${exit1:-0}" = 1 ] || [ "${exit2:-0}" = 1 ] || [ "${exit3:-0}" = 1 ] || [ "${exit4:-0}" = 1 ] || [ "${exit5:-0}" = 1 ]; then
            say ""
            say "To add $_install_dir_expr to your PATH, either restart your shell or run:"
            say ""
            say "    source $_env_script_path_expr (sh, bash, zsh)"
            say "    source $_fish_env_script_path_expr (fish)"
        fi
    fi

    _shadowed_bins="$(check_for_shadowed_bins "$_install_dir" "$_bin_name")"
    if [ -n "$_shadowed_bins" ]; then
        say "WARNING: The following commands are shadowed by other commands in your PATH:$_shadowed_bins"
    fi
}

check_for_shadowed_bins() {
    local _install_dir="$1"
    local _bin_name="$2"

    local _shadowed_bins=""
    if [ "$(command -v "$_bin_name")" != "$_install_dir/$_bin_name" ]; then
        _shadowed_bins="$_shadowed_bins $_bin_name"
    fi

    echo "$_shadowed_bins"
}

print_home_for_script() {
    local script="$1"

    local _home
    case "$script" in
        # zsh has a special ZDOTDIR directory, which if set
        # should be considered instead of $HOME
        .zsh*)
            if [ -n "${ZDOTDIR:-}" ]; then
                _home="$ZDOTDIR"
            else
                _home="$HOME"
            fi
            ;;
        *)
            _home="$HOME"
            ;;
    esac

    echo "$_home"
}

add_install_dir_to_ci_path() {
    # Attempt to do CI-specific rituals to get the install-dir on PATH faster
    local _install_dir="$1"

    # If GITHUB_PATH is present, then write install_dir to the file it refs.
    # After each GitHub Action, the contents will be added to PATH.
    if [ -n "${GITHUB_PATH:-}" ]; then
        ensure echo "$_install_dir" >> "$GITHUB_PATH"
    fi
}

add_install_dir_to_path() {
    # Edit rcfiles ($HOME/.profile) to add install_dir to $PATH
    local _install_dir_expr="$1"
    local _env_script_path="$2"
    local _env_script_path_expr="$3"
    local _rcfiles="$4"
    local _shell="$5"

    if [ -n "${HOME:-}" ]; then
        local _target
        local _home

        # Find the first file in the array that exists and choose
        # that as our target to write to
        for _rcfile_relative in $_rcfiles; do
            _home="$(print_home_for_script "$_rcfile_relative")"
            local _rcfile="$_home/$_rcfile_relative"

            if [ -f "$_rcfile" ]; then
                _target="$_rcfile"
                break
            fi
        done

        # If we didn't find anything, pick the first entry in the
        # list as the default to create and write to
        if [ -z "${_target:-}" ]; then
            local _rcfile_relative
            _rcfile_relative="$(echo "$_rcfiles" | awk '{ print $1 }')"
            _home="$(print_home_for_script "$_rcfile_relative")"
            _target="$_home/$_rcfile_relative"
        fi

        local _robust_line=". \"$_env_script_path_expr\""
        local _pretty_line="source \"$_env_script_path_expr\""

        # Add the env script if it doesn't already exist
        if [ ! -f "$_env_script_path" ]; then
            say_verbose "creating $_env_script_path"
            if [ "$_shell" = "sh" ]; then
                write_env_script_sh "$_install_dir_expr" "$_env_script_path"
            else
                write_env_script_fish "$_install_dir_expr" "$_env_script_path"
            fi
        else
            say_verbose "$_env_script_path already exists"
        fi

        # Check if the line is already in the rcfile
        if ! grep -F "$_robust_line" "$_target" > /dev/null 2>/dev/null && \
           ! grep -F "$_pretty_line" "$_target" > /dev/null 2>/dev/null
        then
            # If the script now exists, add the line to source it to the rcfile
            if [ -f "$_env_script_path" ]; then
                local _line
                if [ "$_shell" = "fish" ]; then
                    _line="$_pretty_line"
                else
                    _line="$_robust_line"
                fi
                say_verbose "adding $_line to $_target"
                # prepend an extra newline in case the user's file is missing a trailing one
                ensure echo "" >> "$_target"
                ensure echo "$_line" >> "$_target"
                return 1
            fi
        else
            say_verbose "$_install_dir already on PATH"
        fi
    fi
}

shotgun_install_dir_to_path() {
    # Edit rcfiles to add install_dir to $PATH (write to all provided files that exist)
    local _install_dir_expr="$1"
    local _env_script_path="$2"
    local _env_script_path_expr="$3"
    local _rcfiles="$4"
    local _shell="$5"

    if [ -n "${HOME:-}" ]; then
        local _found=false
        local _home

        for _rcfile_relative in $_rcfiles; do
            _home="$(print_home_for_script "$_rcfile_relative")"
            local _rcfile_abs="$_home/$_rcfile_relative"

            if [ -f "$_rcfile_abs" ]; then
                _found=true
                add_install_dir_to_path "$_install_dir_expr" "$_env_script_path" "$_env_script_path_expr" "$_rcfile_relative" "$_shell"
            fi
        done

        # Fall through to previous "create + write to first file in list" behavior
            if [ "$_found" = false ]; then
            add_install_dir_to_path "$_install_dir_expr" "$_env_script_path" "$_env_script_path_expr" "$_rcfiles" "$_shell"
        fi
    fi
}

write_env_script_sh() {
    # write this env script to the given path
    local _install_dir_expr="$1"
    local _env_script_path="$2"
    ensure cat <<EOF > "$_env_script_path"
#!/bin/sh
# add binaries to PATH if they aren't added yet
# affix colons on either side of \$PATH to simplify matching
case ":\${PATH}:" in
    *:"$_install_dir_expr":*)
        ;;
    *)
        # Prepending path in case a system-installed binary needs to be overridden
        export PATH="$_install_dir_expr:\$PATH"
        ;;
esac
EOF
}

write_env_script_fish() {
    # write this env script to the given path
    local _install_dir_expr="$1"
    local _env_script_path="$2"
    ensure cat <<EOF > "$_env_script_path"
if not contains "$_install_dir_expr" \$PATH
    # Prepending path in case a system-installed binary needs to be overridden
    set -x PATH "$_install_dir_expr" \$PATH
end
EOF
}

check_proc() {
    # Check for /proc by looking for the /proc/self/exe link
    # This is only run on Linux
    if ! test -L /proc/self/exe ; then
        err "fatal: Unable to find /proc/self/exe. Is /proc mounted? Installation cannot proceed without /proc."
    fi
}

get_bitness() {
    need_cmd head
    # Architecture detection without dependencies beyond coreutils.
    # ELF files start out "\x7fELF", and the following byte is
    #   0x01 for 32-bit and
    #   0x02 for 64-bit.
    local _current_exe_head
    _current_exe_head=$(head -c 5 /proc/self/exe )
    if [ "$_current_exe_head" = "$(printf '\177ELF\001')" ]; then
        echo 32
    elif [ "$_current_exe_head" = "$(printf '\177ELF\002')" ]; then
        echo 64
    else
        err "unknown platform bitness"
    fi
}

is_host_amd64_elf() {
    need_cmd head
    need_cmd tail
    # ELF e_machine detection without dependencies beyond coreutils.
    # Two-byte field at offset 0x12 indicates the CPU,
    # but we're interested in it being 0x3E to indicate amd64, or not that.
    local _current_exe_machine
    _current_exe_machine=$(head -c 19 /proc/self/exe | tail -c 1)
    [ "$_current_exe_machine" = "$(printf '\076')" ]
}

get_endianness() {
    local cputype=$1
    local suffix_eb=$2
    local suffix_el=$3

    # detect endianness without od/hexdump, like get_bitness() does.
    need_cmd head
    need_cmd tail

    local _current_exe_endianness
    _current_exe_endianness="$(head -c 6 /proc/self/exe | tail -c 1)"
    if [ "$_current_exe_endianness" = "$(printf '\001')" ]; then
        echo "${cputype}${suffix_el}"
    elif [ "$_current_exe_endianness" = "$(printf '\002')" ]; then
        echo "${cputype}${suffix_eb}"
    else
        err "unknown platform endianness"
    fi
}

get_architecture() {
    local _ostype
    local _cputype
    _ostype="$(uname -s)"
    _cputype="$(uname -m)"
    local _clibtype="gnu"

    if [ "$_ostype" = Linux ]; then
        if [ "$(uname -o)" = Android ]; then
            _ostype=Android
        fi
        if ldd --version 2>&1 | grep -q 'musl'; then
            _clibtype="musl-dynamic"
        else
            # Assume all other linuxes are glibc
            _clibtype="gnu"
        fi
    fi

    if [ "$_ostype" = Darwin ] && [ "$_cputype" = i386 ]; then
        # Darwin `uname -m` lies
        if sysctl hw.optional.x86_64 | grep -q ': 1'; then
            _cputype=x86_64
        fi
    fi

    if [ "$_ostype" = Darwin ] && [ "$_cputype" = x86_64 ]; then
        # Rosetta on aarch64
        if [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = "1" ]; then
            _cputype=aarch64
        fi
    fi

    if [ "$_ostype" = SunOS ]; then
        # Both Solaris and illumos presently announce as "SunOS" in "uname -s"
        # so use "uname -o" to disambiguate.
        if [ "$(/usr/bin/uname -o)" = illumos ]; then
            _ostype=illumos
        fi

        # illumos systems have multi-arch userlands, and "uname -m" reports the
        # machine hardware name; e.g., "i86pc" on both 32- and 64-bit x86
        # systems.  Check for the native (widest) instruction set on the
        # running kernel:
        if [ "$_cputype" = i86pc ]; then
            _cputype="$(isainfo -n)"
        fi
    fi

    case "$_ostype" in
        Android)
            _ostype=linux-android
            ;;
        Linux)
            check_proc
            _ostype=unknown-linux-$_clibtype
            _bitness=$(get_bitness)
            ;;
        FreeBSD)
            _ostype=unknown-freebsd
            ;;
        NetBSD)
            _ostype=unknown-netbsd
            ;;
        DragonFly)
            _ostype=unknown-dragonfly
            ;;
        Darwin)
            _ostype=apple-darwin
            ;;
        illumos)
            _ostype=unknown-illumos
            ;;
        MINGW* | MSYS* | CYGWIN* | Windows_NT)
            _ostype=pc-windows-gnu
            ;;
        *)
            err "unrecognized OS type: $_ostype"
            ;;
    esac

    case "$_cputype" in
        i386 | i486 | i686 | i786 | x86)
            _cputype=i686
            ;;
        xscale | arm)
            _cputype=arm
            if [ "$_ostype" = "linux-android" ]; then
                _ostype=linux-androideabi
            fi
            ;;
        armv6l)
            _cputype=arm
            if [ "$_ostype" = "linux-android" ]; then
                _ostype=linux-androideabi
            else
                _ostype="${_ostype}eabihf"
            fi
            ;;
        armv7l | armv8l)
            _cputype=armv7
            if [ "$_ostype" = "linux-android" ]; then
                _ostype=linux-androideabi
            else
                _ostype="${_ostype}eabihf"
            fi
            ;;
        aarch64 | arm64)
            _cputype=aarch64
            ;;
        x86_64 | x86-64 | x64 | amd64)
            _cputype=x86_64
            ;;
        mips)
            _cputype=$(get_endianness mips '' el)
            ;;
        mips64)
            if [ "$_bitness" -eq 64 ]; then
                # only n64 ABI is supported for now
                _ostype="${_ostype}abi64"
                _cputype=$(get_endianness mips64 '' el)
            fi
            ;;
        ppc)
            _cputype=powerpc
            ;;
        ppc64)
            _cputype=powerpc64
            ;;
        ppc64le)
            _cputype=powerpc64le
            ;;
        s390x)
            _cputype=s390x
            ;;
        riscv64)
            _cputype=riscv64gc
            ;;
        loongarch64)
            _cputype=loongarch64
            ;;
        *)
            err "unknown CPU type: $_cputype"
    esac

    # Detect 64-bit linux with 32-bit userland
    if [ "${_ostype}" = unknown-linux-gnu ] && [ "${_bitness}" -eq 32 ]; then
        case $_cputype in
            x86_64)
                # 32-bit executable for amd64 = x32
                if is_host_amd64_elf; then {
                    err "x32 linux unsupported"
                }; else
                    _cputype=i686
                fi
                ;;
            mips64)
                _cputype=$(get_endianness mips '' el)
                ;;
            powerpc64)
                _cputype=powerpc
                ;;
            aarch64)
                _cputype=armv7
                if [ "$_ostype" = "linux-android" ]; then
                    _ostype=linux-androideabi
                else
                    _ostype="${_ostype}eabihf"
                fi
                ;;
            riscv64gc)
                err "riscv64 with 32-bit userland unsupported"
                ;;
        esac
    fi

    # treat armv7 systems without neon as plain arm
    if [ "$_ostype" = "unknown-linux-gnueabihf" ] && [ "$_cputype" = armv7 ]; then
        if ensure grep '^Features' /proc/cpuinfo | grep -q -v neon; then
            # At least one processor does not have NEON.
            _cputype=arm
        fi
    fi

    _arch="${_cputype}-${_ostype}"

    RETVAL="$_arch"
}

say() {
    if [ "0" = "$PRINT_QUIET" ]; then
        echo "$1"
    fi
}

say_verbose() {
    if [ "1" = "$PRINT_VERBOSE" ]; then
        echo "$1"
    fi
}

err() {
    if [ "0" = "$PRINT_QUIET" ]; then
        local red
        local reset
        red=$(tput setaf 1 2>/dev/null || echo '')
        reset=$(tput sgr0 2>/dev/null || echo '')
        say "${red}ERROR${reset}: $1" >&2
    fi
    exit 1
}

need_cmd() {
    if ! check_cmd "$1"
    then err "need '$1' (command not found)"
    fi
}

check_cmd() {
    command -v "$1" > /dev/null 2>&1
    return $?
}

assert_nz() {
    if [ -z "$1" ]; then err "assert_nz $2"; fi
}

# Run a command that should never fail. If the command fails execution
# will immediately terminate with an error showing the failing
# command.
ensure() {
    if ! "$@"; then err "command failed: $*"; fi
}

# This is just for indicating that commands' results are being
# intentionally ignored. Usually, because it's being executed
# as part of error handling.
ignore() {
    "$@"
}

# This wraps curl or wget. Try curl first, if not installed,
# use wget instead.
downloader() {
    if check_cmd curl
    then _dld=curl
    elif check_cmd wget
    then _dld=wget
    else _dld='curl or wget' # to be used in error message of need_cmd
    fi

    if [ "$1" = --check ]
    then need_cmd "$_dld"
    elif [ "$_dld" = curl ]
    then curl -sSfL "$1" -o "$2"
    elif [ "$_dld" = wget ]
    then wget "$1" -O "$2"
    else err "Unknown downloader"   # should not reach here
    fi
}

download_binary_and_run_installer "$@" || exit 1

