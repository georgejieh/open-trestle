#!/usr/bin/env bash
# Install Open Trestle for the current user from a GitHub release.
#
#   curl -fsSL https://georgejieh.dev/open-trestle/install.sh | bash
#   bash install.sh [--version VERSION] [--uninstall]
#
# Environment: OPEN_TRESTLE_VERSION (a release, such as 0.1.0-alpha.1),
# OPEN_TRESTLE_INSTALL_ROOT, OPEN_TRESTLE_BIN_DIR, NO_COLOR. For testing a
# mirror: OPEN_TRESTLE_BASE_URL (files at BASE/vVERSION/NAME) and
# OPEN_TRESTLE_API_URL (a GitHub release list).
#
# Everything is inside one function that the last line calls, so a download
# cut short inside it runs nothing. Nothing reads standard input.

open_trestle_install() {
    set -u
    set -o pipefail

    local repository="georgejieh/open-trestle"
    local base_url="${OPEN_TRESTLE_BASE_URL:-https://github.com/$repository/releases/download}"
    local api_url="${OPEN_TRESTLE_API_URL:-https://api.github.com/repos/$repository/releases?per_page=10}"
    local semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
    local version="${OPEN_TRESTLE_VERSION:-}" uninstall=false

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --uninstall) uninstall=true ;;
            --version)
                [ "$#" -ge 2 ] || { echo "install.sh: --version needs a value" >&2; return 2; }
                version="$2"; shift ;;
            --version=*) version="${1#--version=}" ;;
            -h|--help)
                echo "usage: install.sh [--version VERSION] [--uninstall]"
                return 0 ;;
            *) echo "install.sh: unknown option $1 (usage: install.sh [--version VERSION] [--uninstall])" >&2; return 2 ;;
        esac
        shift
    done

    local bold="" dim="" green="" yellow="" red="" reset=""
    local ok="✓" wait="…" bad="✗" dot="·"
    if [ "${TERM:-}" = dumb ]; then
        ok="[ok]" wait="[..]" bad="[x]" dot="-"
    fi
    if [ -t 1 ] && [ -z "${NO_COLOR+set}" ] && [ "${TERM:-}" != dumb ]; then
        bold=$'\033[1m' dim=$'\033[2m' green=$'\033[32m' yellow=$'\033[33m' red=$'\033[31m' reset=$'\033[0m'
    fi
    say() { printf '%s\n' "$*"; }
    step() { printf '  %s%s%s %s\n' "$yellow" "$wait" "$reset" "$*"; }
    done_step() { printf '  %s%s%s %s\n' "$green" "$ok" "$reset" "$*"; }
    fail() {
        printf '  %s%s%s %s\n' "$red" "$bad" "$reset" "$*" >&2
        return 1
    }

    say "${bold}Open Trestle $dot install${reset}"

    case "$(uname -s)" in
        Linux) ;;
        Darwin) fail "macOS is not supported yet. Open Trestle runs on Linux and Windows."; return 1 ;;
        *) fail "This installer is for Linux; on Windows, run in PowerShell: irm https://georgejieh.dev/open-trestle/install.ps1 | iex"; return 1 ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "Releases are built for amd64 (x86_64) only, and this machine is $(uname -m). Build from source instead: https://github.com/$repository/blob/main/docs/install.md"; return 1 ;;
    esac

    case "${HOME:-}" in
        /*) ;;
        *) fail "HOME is not set to an absolute path."; return 1 ;;
    esac
    local data="$HOME/.local/share"
    case "${XDG_DATA_HOME:-}" in /*) data="$XDG_DATA_HOME" ;; esac
    local root="${OPEN_TRESTLE_INSTALL_ROOT:-$data/open-trestle}"
    local bin="${OPEN_TRESTLE_BIN_DIR:-$HOME/.local/bin}"
    case "$root" in /*) ;; *) fail "OPEN_TRESTLE_INSTALL_ROOT must be an absolute path."; return 1 ;; esac
    case "$bin" in /*) ;; *) fail "OPEN_TRESTLE_BIN_DIR must be an absolute path."; return 1 ;; esac
    root="${root%/}" bin="${bin%/}"

    # An install folder is one this script made: a version name holding
    # bin/trestle and the archive's README.txt.
    is_install() {
        [ -d "$1" ] && [ ! -L "$1" ] && [[ "$(basename "$1")" =~ $semver ]] \
            && [ -f "$1/bin/trestle" ] && head -n 1 "$1/README.txt" 2>/dev/null | grep -q '^Open Trestle '
    }
    our_link() {
        [ -L "$1" ] && case "$(readlink "$1")" in "$root"/*) true ;; *) false ;; esac
    }

    if [ "$uninstall" = true ]; then
        local removed=false name entry
        for name in trestle trestled; do
            if our_link "$bin/$name"; then rm -f "$bin/$name" && removed=true; fi
        done
        if [ -L "$root/current" ]; then rm -f "$root/current" && removed=true; fi
        for entry in "$root"/* "$root"/.download-*; do
            if is_install "$entry" || { [ -d "$entry" ] && case "$(basename "$entry")" in .download-*) true ;; *) false ;; esac; }; then
                rm -rf "$entry" && removed=true
            fi
        done
        rm -f "$root/install.log"
        rmdir "$root" 2>/dev/null || true
        if [ "$removed" = true ]; then
            done_step "Removed Open Trestle from $root and its links in $bin."
        else
            done_step "Nothing to remove: no install by this script was found in $root."
        fi
        say "  Kept your setup and usage records (~/.local/state/open-trestle),"
        say "  saved keys (~/.config/open-trestle/credentials) and the scanner"
        say "  cache (~/.cache/open-trestle, safe to delete)."
        return 0
    fi

    local tool
    for tool in tar gzip sha256sum mktemp uname; do
        command -v "$tool" >/dev/null 2>&1 || { fail "$tool is required and was not found."; return 1; }
    done
    local fetcher=""
    if command -v curl >/dev/null 2>&1; then fetcher=curl
    elif command -v wget >/dev/null 2>&1; then fetcher=wget
    else fail "curl or wget is required and neither was found."; return 1
    fi
    # curl holds the default GitHub addresses, redirects included, to HTTPS;
    # a test mirror may be served from this machine.
    local https_only=false
    [ -z "${OPEN_TRESTLE_BASE_URL:-}${OPEN_TRESTLE_API_URL:-}" ] && https_only=true
    fetch() {
        if [ "$fetcher" = curl ]; then
            if [ "$https_only" = true ]; then
                curl -fsSL --proto '=https' --retry 2 -o "$2" "$1" </dev/null
            else
                curl -fsSL --retry 2 -o "$2" "$1" </dev/null
            fi
        else
            wget -q -O "$2" "$1" </dev/null
        fi
    }

    local program
    for program in trestle trestled; do
        if { [ -e "$bin/$program" ] || [ -L "$bin/$program" ]; } && ! our_link "$bin/$program"; then
            fail "$bin/$program already exists and was not made by this installer. Move it away and run the installer again. Nothing was changed."
            return 1
        fi
    done

    mkdir -p "$root" && chmod go-w "$root" || { fail "Cannot create $root."; return 1; }
    local log="$root/install.log"
    : > "$log" || { fail "Cannot write $log."; return 1; }
    local staging
    staging="$(mktemp -d "$root/.download-XXXXXX")" || { fail "Cannot create a download folder in $root."; return 1; }
    # shellcheck disable=SC2064
    trap "rm -rf '$staging'" EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # run LABEL CMD...: CMD's output goes to the log; on failure its tail is shown.
    run() {
        local label="$1"; shift
        printf '==> %s\n' "$label" >> "$log"
        if "$@" </dev/null >> "$log" 2>&1; then return 0; fi
        fail "$label failed. Last lines of $log:"
        tail -n 15 "$log" | sed 's/^/      /' >&2
        return 1
    }

    if [ -z "$version" ]; then
        step "Finding the latest release"
        run "Reading the release list" fetch "$api_url" "$staging/releases.json" || return 1
        version="$(grep -o '"tag_name": *"v[^"]*"' "$staging/releases.json" | head -n 1 | sed 's/.*"v//; s/"$//')"
        [ -n "$version" ] || { fail "No release was found at $api_url."; return 1; }
        done_step "Latest release: v$version."
    fi
    version="${version#v}"
    [[ "$version" =~ $semver ]] || { fail "$version is not a release version (such as 0.1.0-alpha.1)."; return 1; }

    reports_version() {
        local info
        info="$("$1" build-info 2>>"$log" </dev/null)" || return 1
        case "$info" in *"\"version\":\"$version\""*'"source_bound":true'*) ;; *) return 1 ;; esac
        printf '%s' "$info" | sed -n 's/.*"source_revision":"\([0-9a-f]\{12\}\).*/\1/p'
    }

    local name="open-trestle-$version-linux-amd64"
    local revision previous=""
    [ -L "$root/current" ] && previous="$(readlink "$root/current")"
    if [ "$previous" = "$version" ] && is_install "$root/$version" && revision="$(reports_version "$root/$version/bin/trestle")"; then
        done_step "Open Trestle $version is already installed (source revision $revision)."
    else
        local archive="$name.tar.gz"
        step "Downloading Open Trestle $version"
        run "Downloading $archive" fetch "$base_url/v$version/$archive" "$staging/$archive" || return 1
        run "Downloading SHA256SUMS" fetch "$base_url/v$version/SHA256SUMS" "$staging/SHA256SUMS" || return 1
        local expected actual
        expected="$(awk -v n="$archive" '$2 == n || $2 == "*" n { print $1 }' "$staging/SHA256SUMS")"
        actual="$(sha256sum "$staging/$archive" | awk '{ print $1 }')"
        if ! [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || [ "$expected" != "$actual" ]; then
            fail "$archive does not match its SHA-256 in SHA256SUMS. Nothing was changed."
            return 1
        fi
        done_step "Checked the SHA-256 of $archive against SHA256SUMS."

        mkdir "$staging/x" && run "Unpacking $archive" tar -xzf "$staging/$archive" -C "$staging/x" --no-same-owner || return 1
        local new="$staging/x/$name"
        local helper="$new/libexec/open-trestle/open-trestle-scan-helper"
        if ! [ -f "$new/bin/trestle" ] || ! [ -f "$new/bin/trestled" ] || ! [ -f "$helper" ] || [ -L "$helper" ]; then
            fail "$archive does not hold the expected programs. Nothing was changed."
            return 1
        fi
        chmod -R go-w "$new"
        # The program refuses a helper that anyone can write, that has a
        # set-ID bit, or that is owned by anyone other than you or root.
        local owner mode
        read -r owner mode < <(stat -c '%u %a' "$helper")
        if { [ "$owner" != "$(id -u)" ] && [ "$owner" != 0 ]; } || (( 8#$mode & 07222 )); then
            fail "The secret scan helper has owner $owner and mode $mode, which Open Trestle refuses. Nothing was changed."
            return 1
        fi
        if ! revision="$(reports_version "$new/bin/trestle")"; then
            fail "The downloaded trestle does not run or does not report version $version. Nothing was changed."
            tail -n 15 "$log" | sed 's/^/      /' >&2
            return 1
        fi
        done_step "Unpacked and checked: trestle build-info reports $version (source revision $revision)."

        if [ -e "$root/$version" ] || [ -L "$root/$version" ]; then
            mv "$root/$version" "$staging/replaced" || { fail "Cannot move the old $root/$version aside."; return 1; }
        fi
        mv "$new" "$root/$version" || { fail "Cannot move the new version into $root."; return 1; }
        ln -s "$version" "$staging/current" && mv -fT "$staging/current" "$root/current" \
            || { fail "Cannot switch $root/current to $version."; return 1; }
    fi

    mkdir -p "$bin" || { fail "Cannot create $bin."; return 1; }
    for program in trestle trestled; do
        ln -sfn "$root/current/bin/$program" "$bin/$program" || { fail "Cannot link $bin/$program."; return 1; }
    done
    if ! reports_version "$bin/trestle" >/dev/null; then
        if [ -n "$previous" ] && [ "$previous" != "$version" ] && is_install "$root/$previous"; then
            ln -sfn "$previous" "$staging/current" && mv -fT "$staging/current" "$root/current"
            fail "trestle $version did not start from $bin. Kept $previous."
        else
            fail "trestle $version did not start from $bin."
        fi
        return 1
    fi
    local entry
    for entry in "$root"/*; do
        if [ "$entry" != "$root/$version" ] && is_install "$entry"; then
            rm -rf "$entry"
        fi
    done
    if [ -n "$previous" ] && [ "$previous" != "$version" ]; then
        done_step "Replaced $previous with $version."
    fi
    done_step "Installed in $root/$version and linked trestle and trestled in $bin."

    local next="trestle init"
    case ":${PATH:-}:" in
        *":$bin:"*)
            local found
            found="$(command -v trestle 2>/dev/null || true)"
            if [ -n "$found" ] && [ "$found" != "$bin/trestle" ]; then
                say "  Note: $found comes before $bin on your PATH, so trestle runs that one."
                next="$bin/trestle init"
            fi
            ;;
        *)
            say "  $bin is not on your PATH. Add it, then open a new terminal:"
            case "$(basename "${SHELL:-sh}")" in
                zsh) say "    echo 'export PATH=\"$bin:\$PATH\"' >> ~/.zshrc" ;;
                fish) say "    fish_add_path $bin" ;;
                *) say "    echo 'export PATH=\"$bin:\$PATH\"' >> ~/.bashrc" ;;
            esac
            next="$bin/trestle init"
            ;;
    esac
    say ""
    say "${bold}Next, inside the Git repository you want reviewed:${reset} $next"
}

open_trestle_install "$@"
