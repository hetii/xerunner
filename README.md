# xebuild

A NAND image builder for the Xbox 360.

    src/xebuild/boards/     every console there is, and the flash fitted to it
    tests/xebuild/          the tests

Run the tests with `python3 -m unittest discover -s tests -t .`, after either
`pip install -e .` or with `src` on `PYTHONPATH`.

## Where each file comes from

A build takes each file from the first of these places that has it. The per build
directory is the one `-d` names, `data/` when it is not given; the dump is the
`nanddump.bin` in it; the release is the directory `-f` names.

| What | Looked for in, in order |
|---|---|
| `smc.bin` | the per build directory; the dump |
| `kv.bin` | the per build directory; the dump |
| the SMC settings block | `smc_config.bin`, then `config.bin`, then `config_raw.bin` in the per build directory; the dump |
| XeLL (`xell-gggggg.bin`, on JTAG `xell-2f.bin`) | the per build directory; the release's `bin/`; the directory the release is in |
| `payload.bin`, `freeboot.bin` (JTAG) | the release's `bin/`; the copies built into the program |
| the firmware files the release's list names | the release directory; its system update container; the dump; `common/`. A copy counts only where its CRC32 is the list's; a name ending in `p` is also tried with `1` and `2` behind it, outside the container. A file listed with no CRC32 is looked for only in the release directory and the dump |
| `crl.bin`, `dae.bin` | the per build directory; the release's system update container (not under `nosusecurity`); the dump (not under `nosecurity`) |
| `extended.bin`, `secdata.bin`, `fcrt.bin` | the per build directory; the dump (not under `nosecurity`). `extended.bin` and `secdata.bin` found nowhere are made up clean |
| `MobileB.dat` to `MobileJ.dat` | the per build directory; the dump (not under `nomobile`) |
| `Statistics.settings`, `Manufacturing.data` | the per build directory; the dump |
| `fuses.bin` (JTAG, glitch2m) | the per build directory, taken only at 0x60 bytes; the lines built into the program |
| the CPU key | `-p`; `cpukey.txt` in the per build directory; `cpukey` in `options.ini`. A key file that fails its check is said and passed over |
| the 1BL key | `-b`; `1blkey.txt` in the directory the tool runs in (in ini mode its only source); `1blkey` in `options.ini`. A key file that fails its check is said and passed over |
| the console | `-c`; a file named after it in the per build directory (`trinity`, `trinity.txt`, ...); `type` in `options.ini` |
| each option | the command line; `options.ini` in the per build directory |

## Known divergences from xeBuild

This is a reimplementation of xeBuild v1.21.810, and the original, run frozen, is what it
is held against. Where the original is **certainly wrong** -- its own usage, or its own
code, says what was meant -- the fault is not copied. Each one is described in full where
the code makes the decision:

- **Every mode's command line is read by argparse.** The descriptions, examples and
  legends are the original's words, the layout around them argparse's; `-h` is `-?`'s
  alias, and a refusal is argparse's own sentence with exit status 2. So `-s -noenter`
  keeps the `-noenter` (the original steps past the word after `-s`, 0x419FB8), a
  switch it does not know is refused (the original takes `-x` for the image's name),
  a switch short of its word is refused (`-d -noenter`), and client says one sentence
  for `-s` beside `-reboot` in either order. -- `cli/command.py`
- **`update -nowrite`, `-noava`, `-noreeb`, `-clean` do not eat the word after them.** The
  original's handlers skip it too (`add ebx, 1` at 0x404F10 and beside), so
  `-noava -noreeb` reboots. -- `cli/command.py`, `parse_update`
- **`client -bp` patches the block its offset names.** The original always starts at
  block 0 (0x407CC9 divides the remainder), and every patch lands on the flash header.
  -- `client/client.py`, `_binary_patch`
- **`client -e <dir>` joins the directory and `system.manifest` as paths.** The original
  concatenates them, so `-e su` looks for `susystem.manifest`, while its own update mode
  passes `17559\` with the separator on. -- `client/sysdata.py`, `avatar_items`
- **`client -i <dir>` writes all six files into the directory.** The original puts
  `nanddump.bin` and `options.ini` in it and runs the directory's name into the other four
  -- `gotfuses.txt`, `got1BL_pub.bin` and the rest, beside it -- where a build, which
  reads one directory, cannot find them. -- `client/client.py`, `_info`
- **A dae.bin or fcrt.bin that will not decrypt goes in as it stands.** The original
  decrypts it in place, finds the hash wrong, says "Skipping encryption" -- and writes what
  the failed decryption left, which is neither the file handed in nor anything a console
  reads. It warns and builds, and so does this. -- `build/security.py`, `taken_beside`
  and `fcrt`
- **A block whose number is written the other controller's way is kept where it lies.**
  On small-block flash the original calls a block "mixed controller" when its number,
  read the way the other controller writes it, is its own position -- and then does not
  copy it at all, so its place stays erased and whatever it held is lost (for crl.bin,
  the console's own sealing parameters). The rule also hits correct blocks at 0x101,
  0x202 and 0x303 whose sequence byte happens to match. Here the block's data is kept,
  with the original's warning given for exactly the blocks it would have dropped. None of
  the 260 dumps held here has such a block. -- `image/order.py`, `mixed_controller`
- **`-o gpufan=0` leaves the settings block passing its own checksum.** The original
  writes the value and does not recompute the block's head, as it does for `cpufan=0`,
  so its block fails its own sum. -- `image/settings.py`, `set_fan`
- **An SMC of nothing but 0x00 or 0xFF is refused unless `smcnocheck` is given.** The
  original has no test for it and stops most such files only by chance, but on a glitch
  image zeros have no reset limit, which it reads as "glitch hack found", and it builds
  an image that gives the console no SMC at all. -- `build/build.py`, `_check_smc`
- **A settings block found too near the end of its file is refused.** Where fewer than
  0x400 bytes follow a sound head, the original skips the copy (0x429A26) and builds with
  a buffer nothing was written to; its own raw branch refuses the same shortfall with
  "extracting config did not work, not enough data to copy!", and so does this.
  -- `image/settings.py`, `SmcConfig.found_in`
- **A number outside its range, or not a number, is refused.** The original leaves a fan
  speed or temperature outside its range unused ("out of range ... not using"), clamps
  `cfldv` to 32 -- `cfldv=288` passes silently as 32 -- and writes `-o cputemp=abc`
  through as whatever it makes of it. A value nobody asked for is a fault nobody can see
  afterwards. So is a `[rawpatch]` offset in a file list that is not a number: the
  original reads `f0000` as 0 and writes the file over the flash header. --
  `config/base.py`, `check_number`; `release/recipe.py`, `Recipe.raw_patches`
- **`client`: a failed action is not followed by `-s` or `-reboot`.** The original says
  "avatar data skipped, unable to load data!" (or "compatibility data skipped") and
  still shuts the console down or reboots it; a reboot takes DashLaunch's server out of
  memory before the failure can be put right. Here the run stops with the error and
  the console is left as it is. -- `client/client.py`, `run_client`
- **With no `-d` the per-build directory is `data/`.** The original says "you did not
  specify per build directory! Using 17559/" and looks for the console's files in the
  release's own directory, where there are none; this says "Using ./data/", where
  J-Runner keeps them. `-d 17559` gives the original's choice. -- `build/build.py`,
  `build_image`
- **A dump with no CF behind its chain is refused.** It is what a flash read after
  `glitch.ecc` was written looks like. The original warns "could not find a non-zero CF
  LDV to use, setting it to 1 but that may be incorrect!", takes a static pairing and
  builds -- measured on such a read of a console whose LDV is 13. Here: "this flash
  keeps no CF slot behind its chain, so its LDV and pairing cannot be read."
  -- `chain/chain.py`, `Chain._opened_slots`
- **An `-a` patch that is missing, or not a whole number of words, is refused.** The
  original skips it ("... not found, skipping") and builds without it. One that does not
  fit the patch set's 0x4000 bytes is skipped with an error here too, as there.
  -- `build/build.py`, `Build._with_addons`
- **`client` takes one action per run, in any order.** The original refuses a second
  action with "option flag %s on command line but option was already set!" -- except
  `-keys` and `-p`, which it lets in after another action and runs, dropping the first
  without a word: `-e su/ -keys` dumps the keys and sends no avatar data, `-r out.bin -p`
  updates the patches and reads nothing. Here each of those is refused as well, with the
  same sentence. -- `cli/command.py`, `parse_client`
- **A MAC address is taken in three written forms and no other:** `002248F10102`,
  `00:22:48:F1:01:02` and `00-22-48-F1-01-02`, the same in options.ini and after `-o`.
  The original refuses the dashes on the command line, garbles them in options.ini
  ("invalid length macid '00:-2:2-:48:...'") and builds without the address, and takes
  forms like `0022:48F1:0102`. -- `config/options.py`, `OptionsConfig.macid`
- **A kv.bin that is neither 0x4000 nor 0x3FF0 bytes is refused.** The original says
  "kv.bin is not the correct size! Skipping verification and encryption!" and writes the
  file into the image unsealed, which gives the console a keyvault it cannot open.
  -- `image/keyvault.py`, `Keyvault.handed_in`
- **`update` leaves the rest of the Manufacturing.data and Statistics.settings blocks
  erased.** The console hands over 0x80 and 0x400 bytes; the original copies them into
  0x1000 buffers it never clears and writes those whole, so the rest is whatever its
  heap last held -- the text of the release's file list, an HMAC pad -- and differs from
  run to run. -- `update/update.py`, `BuildUpdate._console_statistics`
- **A message's level is what it means, not whether the original needs `-v` for it.**
  The levels, shown from INFO up unless `-v` is given:
  - DEBUG: the ordinary path.
  - INFO: progress, results, and a file the user added being taken.
  - WARNING: input dropped, replaced or corrected.
  - ERROR: something failed and the result lacks it or is flawed, but the run goes on.
  - CRITICAL: the run ends.

  So some lines the original keeps for `-v` show by default, e.g. "keyvault decrypt
  failed, discarding" and "dualboot setting ignored!". -- `cli/command.py`, and each
  message where it happens
- **"dualboot setting ignored!" is said for either XeLL button.** The original drops a
  `dualboot` that is the same button as `xellbutton` or `xellbutton2` (0x42B2B0), but says
  so only for the first (0x426769); for the second the setting disappears without a word.
  -- `build/build.py`, `boot_options`
- **A `config_raw.bin` is read.** The original keeps the settings block in a buffer of
  0x400 bytes (0x429803), and its raw branch copies eight pages into it, 0x1000 bytes
  (0x4298C4): it dies after "extracting config raw" -- measured with the dump's own
  block. This takes the block's 0x400 bytes from its two pages. -- `image/settings.py`,
  `SmcConfig.found_in`
