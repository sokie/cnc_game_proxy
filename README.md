# Cnc Online Proxy

A Windows DLL library that enables **Red Alert 3, Tiberium Wars, and Kane's Wrath,Command & Conquer: Generals, Command & Conquer: Generals Zero Hour** to connect to custom multiplayer servers by proxying and redirecting game traffic.

## Features

- Redirect game connections to custom server backends
- SSL/TLS interception for legacy game protocols
- DNS redirection for GameSpy endpoints
- Decryption logging for research and debugging
- Configurable via JSON or INI files

## Supported Servers

| Server | Description |
|--------|-------------|
| [CnC-Online](https://cnc-online.net/) | Community-run servers for C&C games |
| [RA3 Battle.net](https://ra3battle.net/) | Community-run RA3 server (Red Alert 3 1.12 only) |
| [Kirov Server Emulator](https://github.com/sokie/kirov-server-emulator) | Self-hosted server emulator for RA3 |

## Installation

1. Build the DLL or download from releases
2. Place `winmm.dll` and the other files in the appropriate folder:
  - For RA3 release files go to `Red Alert 3\Data\`
  - For KW release files go to `Command Conquer 3 Kanes Wrath\RetailExe\1.3\`
  - For TW release files go to `Command Conquer 3 Tiberium Wars\RetailExe\1.10\`
  - For Generals & ZH release files go in the main folder (eg. next to `Generals.exe` )
4. Configure `config.json` and place in game folder

If you currently use Tacitus from CncOnline, rename `dsound.dll` to `dsound.dll.bkp`

## Configuration

Copy `config.json.example` to `config.json` and modify as needed.

### Config for CnC-Online

```json
{
    "debug": {
        "showConsole": false,
        "createLog": false,
        "logDecryption": false
    },
    "patches": {
        "SSL": true
    },
    "proxy": {
        "enable": false
    },
    "hostnames": {
        "host": "http.server.cnc-online.net",
        "login": "login.server.cnc-online.net",
        "gpcm": "gpcm.server.cnc-online.net",
        "peerchat": "peerchat.server.cnc-online.net",
        "master": "master.server.cnc-online.net",
        "natneg": "natneg.server.cnc-online.net",
        "stats": "gamestats.server.cnc-online.net",
        "sake": "sake.server.cnc-online.net",
        "server": "server.cnc-online.net"
    }
}
```

### Config for RA3 Battle.net

Red Alert 3 **1.12 only**.

Copy `config.ra3bn.json.example` to `config.json`. Requires the
[RA3BattleNet client](https://www.ra3battle.net/) to be installed.

```json
{
    "ra3bn": { "delegate": true },
    "proxy": { "enable": false }
}
```

RA3BN moves most GameSpy services onto its own transports, which hostname redirection
cannot reach. So we load the RA3BattleNet client's `NativeDll.dll` and delegate
connectivity to it, keeping our own logging and diagnostics.

It is loaded from its own installed path and never copied, since it resolves game
assets relative to that location. We find it via the registry, falling back to
`%APPDATA%\RA3BattleNet\contents\NativeDll.dll`. Set `ra3bn.clientDll` to override.

**You must launch 1.12.** If your install also has `RA3_1.13.game`, `RA3.exe` will
start 1.13 by default and we will refuse to load their client (it only supports 1.12,
and would terminate the game on any other build). Launch with:

```
RA3.exe -runver 1.12
```

Place `winmm.dll` and the boost DLLs in `Red Alert 3\Data\`, next to the game
executable, and `config.json` in `Red Alert 3\`: the game's working directory is the
folder above `Data`.

Running their launcher at the same time is safe: their entry point takes a
per-process mutex, so whichever arrives second stands down instead of double-patching.

| Key | Default | Description |
|---|---|---|
| `ra3bn.delegate` | false | Load the installed RA3BattleNet client |
| `ra3bn.clientDll` | "" | Full path to their `NativeDll.dll`. Empty autodetects |
| `ra3bn.logFolder` | "" | Where their DLL writes its log. Empty uses their client's `logs` folder |
| `ra3bn.waitSeconds` | 120 | How long to wait for the game window before giving up |

If the game is not RA3 1.12, or their client is not installed, we log the reason and
carry on without it: their address table would otherwise terminate the game on an
unsupported build.

#### Wine / Proton / Linux

This works where the RA3BattleNet launcher does not, because it skips the part that
breaks: their launcher is .NET plus WebView2 and injects with EasyHook. `NativeDll.dll`
needs none of that, importing only system libraries, and we load it in-process from our
`winmm.dll` override.

**Their installer usually has not run**, so autodetection (registry, then `%APPDATA%`)
finds nothing. Point `ra3bn.clientDll` at the DLL yourself. Copy the whole
`RA3BattleNet` folder from a Windows install, not just the DLL, since it loads maps,
fonts and UI from `contents\data\` relative to itself.

```json
{
    "ra3bn": {
        "delegate": true,
        "clientDll": "Z:\\home\\you\\RA3BattleNet\\contents\\NativeDll.dll"
    },
    "proxy": { "enable": false }
}
```

Path notes:

- JSON needs **doubled backslashes**.
- `Z:` is Wine's mapping of the Linux root, so `/home/you/x` becomes `Z:\\home\\you\\x`.
- A path inside the prefix works too:
  `"C:\\users\\you\\AppData\\Roaming\\RA3BattleNet\\contents\\NativeDll.dll"`.
- `%APPDATA%` and other environment variables are expanded, so
  `"%APPDATA%\\RA3BattleNet\\contents\\NativeDll.dll"` is valid.
- If you did run their installer under Wine, leave `clientDll` empty: the registry
  lookup will find it.

Launch the game with `-runver 1.12` as above. On failure our log lists every path that
was tried, so you can see what to set.

Untested by us on Wine: the most likely snag is their HTTPS API, since they read the
Windows root certificate store (`CertOpenSystemStoreW`) and a Wine prefix may have no
CA certificates. If login works but stats, lobbies or maps do not, check their log at
`<client folder>\logs\NativeDll.dll.txt` for TLS errors, and install CA certs into the
prefix (`winetricks cacert` or copy the host bundle).

### Config for Kirov Server Emulator

```json
{
    "debug": {
        "showConsole": true,
        "createLog": true,
        "logDecryption": false
    },
    "patches": {
        "SSL": true
    },
    "proxy": {
        "enable": true,
        "destinationPort": 18800,
        "secure": false
    },
    "hostnames": {
        "host": "localhost",
        "login": "localhost",
        "gpcm": "localhost",
        "peerchat": "localhost",
        "master": "localhost",
        "natneg": "localhost",
        "stats": "localhost",
        "sake": "localhost",
        "server": "localhost"
    }
}
```

When connecting to another PC on your network, you need to add a line to your hosts file `c:\Windows\System32\drivers\etc\hosts` with their IP and a name like `192.168.68.123 my_cool_pc`. If you connect through VPN such as Hamachi, add the hamachi IP of the other PC.
Then you need to add that to your config file as so `"login": "my_cool_pc",` and all the other lines.

## Configuration Reference

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| debug | showConsole | true | Show debug console window |
| debug | createLog | true | Write logs to file |
| debug | logDecryption | false | Log decrypted peerchat/master server traffic |
| debug | logLevelConsole | 2 | Console log level (0-5) |
| debug | logLevelFile | 1 | File log level (0-5) |
| patches | SSL | true | Enable SSL certificate patching |
| patches | AuthKey | true | Bypass the GameSpy auth certificate check |
| ra3bn | delegate | false | RA3 Battle.net: load the installed RA3BattleNet client (RA3 1.12 only) |
| ra3bn | clientDll | "" | Full path to their `NativeDll.dll`. Empty autodetects |
| ra3bn | logFolder | "" | Where their DLL writes its log. Empty uses their client's `logs` folder |
| ra3bn | waitSeconds | 120 | How long to wait for the game window before giving up |
| proxy | enable | true | Enable the local SSL proxy (listens on port 18840) |
| proxy | destinationPort | 18840 | Port to forward traffic to on `hostnames.login` |
| proxy | listenPort | 18840 | Port that our proxy listens on. `18840` for RA3, `18760` for KW, `18310` for TW |
| proxy | secure | false | Use SSL for proxy forwarding connection |
| game | gameKey | "" | GameSpy encryption key, only needed for `logDecryption` |
| game | peerchatPort | 0 | Port peerchat listens on. `0` tries 6667 then falls back to 16667 |

Hostname keys: `host`, `login`, `gpcm`, `peerchat`, `master`, `natneg`, `stats`, `sake`,
`server`, `register`, `website`, `tos`. Servers that split the GameSpy browser roles
across hosts can also set `available` and `ms1` (both default to `master`) and
`natneg2` / `natneg3` (both default to `natneg`).


Log levels: `0=trace, 1=debug, 2=info, 3=warning, 4=error, 5=fatal`

When `proxy.enable` is true, the game's FESL connections are redirected to `localhost:listenPort` where the local proxy intercepts them and forwards to `hostnames.login` on `proxy.destinationPort`.

## Research & Debugging

Enable `logDecryption` to inspect decrypted game traffic:

```json
{
    "debug": {
        "logDecryption": true
    },
    "game": {
        "gameKey": "YOUR_GAME_KEY"
    }
}
```

This allows you to see:
- Peerchat (IRC-based) game lobby communication
- Master server list queries and responses

## Building

### Prerequisites

- Visual Studio 2019 or later
- [vcpkg](https://github.com/microsoft/vcpkg) package manager

### Dependencies

Install dependencies via vcpkg:

```bash
vcpkg install boost:x86-windows detours:x86-windows
```

### OpenSSL 1.0.2u (Manual Build Required)

Cnc uses a legacy SSL implementation that requires **OpenSSL 1.0.2u**. This version is deprecated and not available in vcpkg, so it must be built manually.

1. Download OpenSSL 1.0.2u source from [openssl.org/source/old](https://www.openssl.org/source/old/1.0.2/)
2. Build for x86 (32-bit) Windows
3. Copy the built libraries to your `vcpkg_installed/x86-windows` directory:
   - `lib/libeay32.lib`
   - `lib/ssleay32.lib`
   - `include/openssl/*`

### Compile

Open `ra3-proxy.sln` in Visual Studio and build the solution.

## Why SSL Patching & Proxy?

### SSL Certificate Validation Patch

When Cnc connects to the login server, it validates the server's SSL certificate against a hardcoded public key embedded in the game executable. Other community servers solve this by patching the executable to replace the original key with their own.

This project takes a different approach: instead of modifying the game executable, we patch the certificate validation at runtime to accept any SSL certificate. This is implemented in `ra3-proxy/patch/RA3/PatchSSL.cpp` and is based on [fesl.ea.com certificate verification remover](https://aluigi.altervista.org/patches/fesl.lpatch) by Aluigi.

### SSL Proxy for Legacy Ciphers

Cnc games use an extremely outdated SSL implementation with cipher suites that modern servers no longer support due to security vulnerabilities. Requiring server operators to enable these insecure ciphers would be a poor solution.

Instead, this project includes a local SSL proxy (`ra3-proxy/patch/RA3/ProxySSL.cpp`) that:

1. Accepts connections from the game using the legacy insecure ciphers
2. Terminates the SSL locally
3. Forwards the traffic to the actual server either in plain text or over a modern secure connection

This allows the games to connect to modern server implementations without requiring those servers to support deprecated cryptography.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [xan105/CnC-Online](https://github.com/xan105/CnC-Online/) - For a lot of the proxy code and implementation.
- [Ra3-Battlenet](https://ra3battle.net/) community for being nice and helpful.
