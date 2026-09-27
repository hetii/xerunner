# xebuild

A NAND image builder for the Xbox 360.

    src/xebuild/boards/     every console there is, and the flash fitted to it
    tests/xebuild/          the tests

Run the tests with `python3 -m unittest discover -s tests -t .`, after either
`pip install -e .` or with `src` on `PYTHONPATH`.

## Known divergences from xeBuild

This is a reimplementation of xeBuild v1.21.810, and the original, run frozen, is what it
is held against. Where the original is **certainly wrong** -- its own usage, or its own
code, says what was meant -- the fault is not copied. Each one is described in full where
the code makes the decision:

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
