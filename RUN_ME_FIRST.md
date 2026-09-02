# Start XploitAtlas

This folder is the complete project. Keep its files together.

## Windows

1. Install a working Python 3.11 or newer from [python.org](https://www.python.org/downloads/windows/). Enable the Python launcher when the installer offers it.
2. Right-click the downloaded ZIP and choose **Extract All**.
3. Open the extracted folder containing `START_WINDOWS.bat`, `start.py`, and `static/`.
4. Double-click **START_WINDOWS.bat**.
5. Visit [http://127.0.0.1:8787](http://127.0.0.1:8787).

You do not need Visual Studio Code, Node.js, npm, pip packages, an API key, or a database server for normal use. Python must be installed; it is not bundled in this source download.

Keep the terminal open. The background scheduler runs in that process, not in the browser. Closing the browser is fine; closing the terminal stops the app and updates.

The launcher tests registered Python installations and then interpreters on PATH. It skips candidates that cannot import their standard library, SQLite, or TLS support. It does not repair Python, change system settings, or guarantee compatibility with every Python version.

### Windows hides the file extension

The launcher may appear as **START_WINDOWS**, with type **Windows Batch File**. It is not named `start window.bat`.

### Python reports a missing encodings module

The selected Python installation cannot load its standard library. The launcher checks for this before starting.

To list available Python installations in Command Prompt:

```bat
py -0p
```

If Python 3.12 is installed and healthy, open Command Prompt in the extracted project folder and run:

```bat
py -3.12 -E start.py
```

Use a version actually installed and working. Versions below 3.11 are unsupported. To check the launcher's choice without running the server:

```bat
START_WINDOWS.bat --check-python
```

### start.py is missing

Extract the **whole** ZIP. Downloading only the batch file is not sufficient. Open the folder containing both `START_WINDOWS.bat` and `start.py`.

### The browser cannot connect

Keep the terminal open and check the address printed there. Do not open `static/index.html` directly; the interface needs the local Python server.

If another copy is using port 8787, stop that copy with **Ctrl+C**, or use another port:

```bat
START_WINDOWS.bat --port 8788
```

Then visit [http://127.0.0.1:8788](http://127.0.0.1:8788).

## Linux or macOS

Open a terminal in the extracted project folder:

```bash
python3 --version
python3 start.py
```

Python 3.11 or newer is required. Visit [http://127.0.0.1:8787](http://127.0.0.1:8787).

## First run and saved data

The catalog starts empty until real providers respond. Allow several minutes and use **Sources** to check progress or failures. No substitute dataset is loaded during an outage.

New observations are saved under `runtime/`. Restarting the same installation preserves them. Downloading a new copy does not automatically migrate another installation's data; back up the old runtime before deliberately reusing it via `--data-dir`. Never publish runtime files, database exports, credentials, or private inventory.

Saved observations can be viewed without automatic refresh:

```bash
python3 start.py --no-sync
```

This does not supply records to a new empty installation. Package queries and explicit enrichment may still contact their providers.

## Optional Docker deployment

With Docker installed, run from the extracted project folder:

```bash
docker compose up --build -d
```

The configuration publishes only to localhost and stores observations in a named volume. The host and Docker must remain running for updates. `docker compose down` stops the service and retains that volume.

## More information

[Project overview](README.md) · [Technical guide](docs/TECHNICAL_GUIDE.md) · [Security boundaries](SECURITY.md) · [MIT license](LICENSE)
