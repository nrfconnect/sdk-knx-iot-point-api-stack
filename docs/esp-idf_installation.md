# Installing ESP-IDF to a custom location with eim

This howto installs Espressif ESP-IDF and its toolchains into a dedicated
development directory using the ESP-IDF Installation Manager (eim), instead of
the default location under your home directory. It is written for a fresh
installation.

Throughout this document the development directory you choose is held in the
shell variable `ESP32_DEVELOPMENT_DIR`. It is set in the first code block of
step 1, with `/data/Develop/ESP32` as the example, so every command below can be
copied as it stands. Set it again in each new shell, or export it from your
shell profile.

## Why not install into the home directory

ESP-IDF is the SDK plus its toolchains (compilers, OpenOCD, cmake, ninja) and a
Python environment. This is shared development tooling, not per-user data. By
default eim installs the tools and download cache under `~/.espressif`, which
places several gigabytes of build tooling inside a user home directory.

Installing into a dedicated development directory instead has clear advantages:

- It is tooling, not user data, so it does not belong in a home directory.
- The home directory stays small and simple to back up. The toolchain can always
  be re-fetched, so it does not need backing up.
- The toolchain can live on a larger or shared development volume.
- The location is reproducible and machine-wide, so every project and user can
  point at the same install.

## Target layout

```text
${ESP32_DEVELOPMENT_DIR}/
  EIM/          the eim installer binary and its config
  ESP-IDF/      the ESP-IDF SDK checkout
  Tools/        toolchains, OpenOCD, cmake, ninja, python environment
  Downloads/    eim download cache
```

|Directory|Usage|
|---|---|
|`EIM`|The eim installer binary, its `eim_config.toml`, and the install log|
|`ESP-IDF`|The ESP-IDF SDK checkout, under a per-version subdirectory (for example `v6.1/esp-idf`)|
|`Tools`|Toolchains, OpenOCD, cmake, ninja, the Python environment, and the activation scripts|
|`Downloads`|eim download cache for the tool archives|

Several versions can live side by side. Each one gets its own subdirectory under
`ESP-IDF` and its own activation script under `Tools`, so installing a newer
version does not disturb an older one.

## Prerequisites

- git, plus the base build prerequisites for your operating system. See the
  official Espressif setup pages for the required system packages.
- curl and unzip, to fetch and extract the eim binary.

## 1. Get the eim CLI

Set the development directory first, then download the CLI build of eim from the
`espressif/idf-im-ui` GitHub releases and extract it into
`${ESP32_DEVELOPMENT_DIR}/EIM`. Use the CLI build (not the GUI build) for a
headless install, and pick the asset that matches your platform.

```bash
export ESP32_DEVELOPMENT_DIR="/data/Develop/ESP32"

mkdir -p "${ESP32_DEVELOPMENT_DIR}/EIM" && cd "${ESP32_DEVELOPMENT_DIR}/EIM"
curl -fL -o eim-cli-linux-x64.zip \
    https://github.com/espressif/idf-im-ui/releases/latest/download/eim-cli-linux-x64.zip
unzip -o eim-cli-linux-x64.zip
./eim --version
```

Check the asset names on the release page before downloading. They change
between releases, and the archive above is only the current Linux x86-64 name.

## 2. Write the eim config

Write `${ESP32_DEVELOPMENT_DIR}/EIM/eim_config.toml`. Every path is set under the
development directory, so nothing is written to the home directory. The four
fields that otherwise default under `~/.espressif` are `esp_idf_json_path`,
`tool_download_folder_name`, `tool_install_folder_name` and
`activation_script_path_override`. Set all four explicitly.

The heredoc below expands `${ESP32_DEVELOPMENT_DIR}` while it writes the file, so
the config ends up holding absolute paths:

```bash
cat > "${ESP32_DEVELOPMENT_DIR}/EIM/eim_config.toml" << EOF
path = "${ESP32_DEVELOPMENT_DIR}/ESP-IDF"
esp_idf_json_path = "${ESP32_DEVELOPMENT_DIR}/Tools"
tool_download_folder_name = "${ESP32_DEVELOPMENT_DIR}/Downloads"
tool_install_folder_name = "${ESP32_DEVELOPMENT_DIR}/Tools"
target = ["esp32c5", "esp32c6", "esp32s3"]
idf_versions = ["v6.1"]
tools_json_file = "tools/tools.json"
config_file_save_path = "${ESP32_DEVELOPMENT_DIR}/EIM/eim_config.toml"
non_interactive = true
wizard_all_questions = false
mirror = "https://github.com"
idf_mirror = "https://github.com"
pypi_mirror = "https://pypi.org/simple"
recurse_submodules = true
install_all_prerequisites = false
skip_prerequisites_check = false
cleanup = false
python_env_folder_name = "python"
activation_script_path_override = "${ESP32_DEVELOPMENT_DIR}/Tools"
python_version_override = "python313"

[idf_features_per_version]
"v6.1" = ["core", "gdbgui", "pytest", "ci", "docs", "ide"]

[idf_tools_per_version]
"v6.1" = ["xtensa-esp-elf-gdb", "riscv32-esp-elf-gdb", "xtensa-esp-elf", "esp-clang", "esp-clang-libs", "riscv32-esp-elf", "esp32ulp-elf", "openocd-esp32", "ninja", "esp-rom-elfs", "cmake"]
EOF
```

Notes:

- `target`: list only the SoCs you build for. The values above (ESP32-C5,
  ESP32-C6, ESP32-S3) are an example set. Add or remove targets as needed.
- `idf_versions` and both version-keyed tables must use the same version key
  (here `v6.1`). To install a different version, change all three.
- `config_file_save_path` should point at the config's own location, so an eim
  re-save does not scatter copies elsewhere.
- `python_version_override` is optional and names the interpreter eim should
  build the environment from. It must match a Python actually present on the
  host, otherwise eim picks one itself and the resulting environment is not the
  version written here. Verify the result in step 4 rather than trusting this
  field.
- eim REWRITES this file during the install. It adds fields of its own (for
  example `idf_path` and `config_file`) and reconciles the feature and tool lists
  with what the selected version actually needs, so the installed tool set can be
  larger than the list above. Keep the rewritten file, do not revert it. Editing
  the rewritten config by hand and running the install again is the supported way
  to change or extend an existing installation.

## 3. Run the install

```bash
cd "${ESP32_DEVELOPMENT_DIR}/EIM"
./eim install --config "${ESP32_DEVELOPMENT_DIR}/EIM/eim_config.toml"
```

The `install` subcommand runs non-interactively when the config sets
`non_interactive = true`. This step clones ESP-IDF and downloads the toolchains,
so it takes a while and needs several gigabytes of free space.

## 4. Verify the install went to the right place

```bash
ls "${ESP32_DEVELOPMENT_DIR}/ESP-IDF"      # SDK checkout
ls "${ESP32_DEVELOPMENT_DIR}/Tools"        # toolchains, cmake, ninja, python
ls "${ESP32_DEVELOPMENT_DIR}/Downloads"    # download cache
ls -la ~/.espressif                        # must NOT contain the SDK or toolchains
```

Confirm the toolchains are under `Tools` and that `~/.espressif` was not
populated with the SDK or tools.

Check which Python the environment was actually built from, since
`python_version_override` is only a request:

```bash
"${ESP32_DEVELOPMENT_DIR}/Tools/python/v6.1/venv/bin/python" --version
```

If an earlier ESP-IDF or eim installation left a `~/.espressif` directory, it is
no longer used by this setup and can be removed to reclaim space, once you have
confirmed it holds nothing you still need:

```bash
rm -rf ~/.espressif
```

## 5. Activate the environment

eim writes activation and deactivation scripts under the tools directory, named
after the installed version (for example `activate_idf_v6.1.sh` and
`deactivate_idf_v6.1.sh`, plus `.fish` variants of both). The exact command is
printed at the end of the install. Source the activation script in each shell
that builds firmware, then confirm `idf.py` is available:

```bash
source "${ESP32_DEVELOPMENT_DIR}/Tools/activate_idf_v6.1.sh"
idf.py --version
```

Leave the environment again with:

```bash
source "${ESP32_DEVELOPMENT_DIR}/Tools/deactivate_idf_v6.1.sh"
```

The script refuses to run when it is executed instead of sourced, because it has
to modify the current shell.

### idf.py is a shell function, not a program on the PATH

This layout differs from a default ESP-IDF install in one way that matters for
scripting. The activation script does NOT put `$IDF_PATH/tools` on the `PATH`.
Instead it defines `idf.py` as a shell function that calls the environment's
Python with `$IDF_PATH/tools/idf.py`, falling back to an alias in shells that do
not allow a dot in a function name. The same applies to `esptool.py`,
`otatool.py` and `parttool.py`.

Two consequences follow:

- A child process does not inherit a shell function, so a build script that is
  executed rather than sourced will not find `idf.py`, even with the environment
  active. Resolve the command inside the script instead:

  ```bash
  if command -v idf.py > /dev/null 2>&1; then
      idf_cmd="idf.py"
  elif [[ -n "${IDF_PYTHON_ENV_PATH}" && -n "${IDF_PATH}" ]]; then
      idf_cmd="${IDF_PYTHON_ENV_PATH}/bin/python ${IDF_PATH}/tools/idf.py"
  else
      echo "Error: No ESP-IDF environment is active!" >&2
      exit 1
  fi
  ```

- Do NOT fall back to `$IDF_PATH/export.sh` with this layout. It expects the
  default tools location, so it deactivates the environment set up here and
  fails with a message that a tool such as `esp-rom-elfs` has no installed
  versions.

The variables the activation script exports are the reliable interface for
scripts and IDEs: `IDF_PATH`, `IDF_TOOLS_PATH`, `IDF_PYTHON_ENV_PATH`,
`ESP_IDF_VERSION`, `IDF_VERSION`, `ESP_ROM_ELF_DIR`, `OPENOCD_SCRIPTS`,
`ESP_CLANG_LIBS_PATH` and `IDF_COMPONENT_LOCAL_STORAGE_URL`, the last one
pointing the ESP-IDF component manager at the local tools directory. Running the
activation script with `-e` prints all of them as name and value pairs, and that
call works even when the script is executed rather than sourced.

## 6. Optional: shell aliases

Typing the full activation path each time is tedious. Append short aliases to
`~/.bash_aliases`. The heredoc expands the development directory, so the aliases
hold absolute paths and keep working in shells where
`ESP32_DEVELOPMENT_DIR` is not set:

```bash
cat >> ~/.bash_aliases << EOF
alias esp-idf-activate='source "${ESP32_DEVELOPMENT_DIR}/Tools/activate_idf_v6.1.sh"'
alias esp-idf-deactivate='source "${ESP32_DEVELOPMENT_DIR}/Tools/deactivate_idf_v6.1.sh"'
EOF
```

Then reload with `source ~/.bash_aliases` (or open a new shell) and use
`esp-idf-activate` / `esp-idf-deactivate`.
