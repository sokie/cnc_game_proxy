# RA3 Online Proxy

A Windows DLL library that enables **Red Alert 3** to connect to custom multiplayer servers by proxying and redirecting game traffic.

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
| [Kirov Server Emulator](https://github.com/sokie/kirov-server-emulator) | Self-hosted server emulator for RA3 |

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

Red Alert 3 uses a legacy SSL implementation that requires **OpenSSL 1.0.2u**. This version is deprecated and not available in vcpkg, so it must be built manually.

1. Download OpenSSL 1.0.2u source from [openssl.org/source/old](https://www.openssl.org/source/old/1.0.2/)
2. Build for x86 (32-bit) Windows
3. Copy the built libraries to your `vcpkg_installed/x86-windows` directory:
   - `lib/libeay32.lib`
   - `lib/ssleay32.lib`
   - `include/openssl/*`

### Compile

Open `ra3-proxy.sln` in Visual Studio and build the solution.

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

### Config for Kirov Server Emulator

```json
{
    "debug": {
        "showConsole": true,
        "createLog": true,
        "logDecryption": true
    },
    "patches": {
        "SSL": true
    },
    "proxy": {
        "enable": true,
        "destinationPort": 18800,
        "secure": false
    },
    "game": {
        "gameKey": "YOUR_GAME_KEY"
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

## Configuration Reference

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| debug | showConsole | true | Show debug console window |
| debug | createLog | true | Write logs to file |
| debug | logDecryption | false | Log decrypted peerchat/master server traffic |
| debug | logLevelConsole | 2 | Console log level (0-5) |
| debug | logLevelFile | 1 | File log level (0-5) |
| patches | SSL | true | Enable SSL certificate patching |
| proxy | enable | true | Enable the local SSL proxy (listens on port 18840) |
| proxy | destinationPort | 18840 | Port to forward traffic to on `hostnames.login` |
| proxy | secure | false | Use SSL for proxy forwarding connection |
| game | gameKey | "" | GameSpy encryption key |

Log levels: `0=trace, 1=debug, 2=info, 3=warning, 4=error, 5=fatal`

When `proxy.enable` is true, the game's FESL connections are redirected to `localhost:18840` where the local proxy intercepts them and forwards to `hostnames.login` on `proxy.destinationPort`.

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

## Installation

1. Build the DLL or download from releases
2. Place `winmm.dll` in the game/Data/ directory
3. Configure `config.json` and place in game folder

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [xan105/CnC-Online](https://github.com/xan105/CnC-Online/) - For a lot of the proxy code and implementation.
- [Ra3-Battlenet](https://ra3battle.net/) community for being nice and helpful.
