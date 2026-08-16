# Glossary

Plain-language definitions of every term used while building this tool, each tied to
a real file in this repo. Grows as we go. If a term shows up in conversation and
isn't here, that's a bug — say so.

---

## Environment & packaging

**Interpreter**
The `python` program itself — the thing that reads your `.py` file and runs it.
There can be several on one machine. `/usr/bin/python3` and
`.venv/bin/python` are two different interpreters with different libraries
installed. Which one runs your code decides which imports work.

**Virtual environment (venv)**
A private folder holding one interpreter and its own set of installed libraries,
isolated from the rest of your computer. Ours is `.venv/`. It exists so that
installing `androguard` for this project can't break some other project that
needs a different version. It is a *folder*, not a running process — "activating"
it just puts its `bin/` directory first on your `PATH`.

**Package (Python sense)**
A folder containing an `__init__.py` file. That file is what tells Python "this
folder is importable as a unit." `src/mobsec_scan/` is a package;
`src/mobsec_scan/detectors/` is a package nested inside it.

**Package (distribution sense)**
A thing you can `pip install`, e.g. `androguard`. Same English word, different
meaning. Context tells you which. Confusing, but universal.

**Module**
A single `.py` file that can be imported. `config.py` is a module. Its full name
inside our package is `mobsec_scan.config` — the dots follow the folders.

**`pyproject.toml`**
The declaration of what this project *is*: its name, version, what libraries it
needs, and what commands it provides. `pip` reads this file to know what to do.
Before it existed, this repo was "some Python files in a folder." After it, the
repo is an installable tool.

**Dependency**
A library your code needs in order to run. Ours are listed under `dependencies`
in `pyproject.toml`.

**Optional dependency / extra**
A dependency only *some* features need. Declared under
`[project.optional-dependencies]`. `androguard` is in our `scan` extra, so
`pip install -e '.'` skips it and `pip install -e '.[scan]'` includes it.

**Editable install (`pip install -e .`)**
Installs the project by pointing at your source folder instead of copying it.
Result: you edit `cli.py` and the change is live immediately, no reinstall.
A normal (non-editable) install copies the files, so edits do nothing until you
reinstall. The `-e` is why we can develop at all.

**Entry point / console script**
A named terminal command that a package provides. Ours is declared as
`mobsec = "mobsec_scan.cli:app"` in `pyproject.toml`, which reads as:
"make a command called `mobsec` that runs the thing named `app` inside the
module `mobsec_scan.cli`." Installing the package creates the `mobsec` command.

**`sys.path`**
The ordered list of folders Python searches when you write `import something`.
First match wins. If a module isn't in any folder on `sys.path`, you get
`ModuleNotFoundError` — that error means "I looked in these places and didn't
find it," not "this library doesn't exist."

**`.pth` file**
A one-line text file in the install directory whose content is a folder path.
Python reads it at startup and adds that folder to `sys.path`. Our editable
install created one containing the path to `src/`. This is the entire mechanism
by which `import mobsec_scan` works from anywhere.

---

## Program structure

**CLI (command-line interface)**
The set of commands, arguments and flags your tool accepts. Ours lives in
`cli.py`: `mobsec scan`, `mobsec batch`, `--log-level`, and so on.

**Subcommand**
A command nested under the main one, like `scan` in `mobsec scan app.apk`.
Same pattern as `git commit` or `pip install`.

**Orchestrator**
Code whose job is coordinating other code rather than doing the work itself.
`run_batch_analysis.py` is one: it doesn't detect anything, it loops over APKs
and calls the detectors that do.

**Detector**
In this project, one security check. We have four. Each answers one research
question about an APK.

**Contract (informal)**
An agreement about how to call something and what you get back. Ours:
`check(apk, dex_list, dx=None) -> dict`. Every detector follows it, which is why
the orchestrator can call them all in a loop without special-casing any of them.

**Uniform interface**
The benefit of a shared contract: the caller treats different things
identically. Adding a fifth detector requires zero changes to the orchestrator.

---

## Configuration

**Configuration**
Values that change *what* the program does without changing its code — which
detectors run, where files get written.

**`config.yaml`**
Our configuration file. YAML is a text format for nested key-value data; the
indentation creates the nesting.

**Hardcoded**
A value written directly into the source code. The opposite of configured.
`ACTIVE_RQS` in `run_batch_analysis.py` was hardcoded configuration — you had to
edit Python to change it.

**Environment variable**
A value living in your shell rather than in a file, readable by any program you
run. `GEMINI_API_KEY` will be one. Used for secrets, because they must not be
committed to git.

**`.env` file**
A local file of environment variables, loaded at startup by `python-dotenv`.
Listed in `.gitignore` so it never reaches GitHub. `.env.example` is the
committed template showing which keys are needed, with the values blank.

**Absolute vs relative path**
Absolute starts from the root of the disk: `/Users/you/project/results`. It
means the same thing everywhere. Relative doesn't: `results` means
"a folder called results *inside wherever I currently am*."

**Working directory (cwd)**
The folder your terminal is sitting in when you run a command. Relative paths
are interpreted against it, which is why the same command can behave differently
depending on where you type it.

**Project root**
The top folder of this repo. `find_project_root()` in `config.py` locates it by
walking upward looking for `config.yaml`, so commands work from any
subdirectory. Same trick `git` uses with the `.git` folder.

---

## Output & errors

**stdout / stderr**
Two separate output channels every program has. `stdout` is the *result* — what
the program was asked to produce. `stderr` is the *commentary* — progress and
warnings. Keeping them separate is what lets `mobsec scan app.apk > report.txt`
save a clean report while you still watch progress on screen.

**Redirection (`>`)**
`command > file.txt` sends stdout into a file instead of the screen. stderr is
unaffected and still displays.

**Logging**
Structured, leveled messages (DEBUG / INFO / WARNING / ERROR) instead of bare
`print`. Levels let you turn detail up or down without editing code.

**Exception**
Python's error object. `ModuleNotFoundError` is one. Uncaught, it stops the
program and prints a traceback.

**Traceback**
The list of function calls leading to an error. Read it **bottom-up**: the last
line is the actual error, the lines above show how execution got there.

**`try` / `except`**
Run risky code; if a specific error occurs, handle it instead of crashing. Used
in `detectors/__init__.py` to turn a bare `ModuleNotFoundError` into a message
that names the missing extra and the command to install it.
