"""The original's command line, read into the settings a build takes."""

import io
import os
import shutil
import tempfile
import unittest
import contextlib

from xebuild.cli import main
from xebuild.config import BuildConfig
from xebuild.cli.command import parse_build


class ReadingACommandLine(unittest.TestCase):

    def refused(self, argv):
        """What argparse says when it refuses a line: its exit, status 2, on stdout."""
        with (contextlib.redirect_stdout(io.StringIO()),
              self.assertRaises(SystemExit) as ended):
            parse_build(argv)
        self.assertEqual(ended.exception.code, 2)

    def test_every_switch_lands_on_the_setting_of_the_same_meaning(self):
        settings = parse_build([
            "-t", "glitch2", "-c", "jasper256",
            "-p", "7E5068DBB3FD03F04E367028D475EEC2",
            "-b", "DD88AD0C9ED669E7B56794FB68563EFA", "-d", "data", "-f", "17559",
            "-i", "flash", "-r", "WB", "-a", "xl_usb", "-a", "hvFixKeys",
            "-8", "a.bin,0x10;b.bin,0x20", "-noenter", "-norandom", "-v", "out.bin",
        ])
        self.assertEqual(settings, {
            "image_type": "glitch2", "console": "jasper256",
            "cpu_key": "7E5068DBB3FD03F04E367028D475EEC2",
            "one_bl_key": "DD88AD0C9ED669E7B56794FB68563EFA",
            "per_build": "data", "data": "17559", "firmware_ext": "flash",
            "section_ext": "WB", "append": ("xl_usb", "hvFixKeys"),
            "raw_patches": "a.bin,0x10;b.bin,0x20", "no_enter": True,
            "no_random": True, "verbose": 1, "out": "out.bin",
        })

    def test_an_option_list_is_split_and_a_bare_name_is_true(self):
        """The usage's own example, and repeated `-o` counts as much as one list."""
        settings = parse_build([
            "-o", "macid=00:22:48:F1:01:02;gameregion=0x00FF;nomobile",
            "-o", "patchsmc=false",
        ])
        self.assertEqual(settings, {"macid": "00:22:48:F1:01:02",
                                    "gameregion": "0x00FF", "nomobile": True,
                                    "patchsmc": "false"})

    def test_what_it_reads_is_a_configuration_that_takes_it(self):
        settings = parse_build(["-t", "jtag", "-c", "falcon", "-o",
                                "cygnos;xellbutton=power;cfldv=10"])
        config = BuildConfig(**settings)
        self.assertEqual((config.image_type.name, config.console_name), ("jtag",
                                                                          "falcon"))
        self.assertTrue(config.cygnos)
        self.assertEqual((config.xellbutton, config.cfldv), ("power", 10))

    def test_the_first_bare_word_names_the_image_and_a_later_one_is_ignored(self):
        """Measured: `one.bin two.bin` builds one.bin, and warns of the other."""
        with self.assertLogs("xebuild.cli.command", "WARNING") as said:
            settings = parse_build(["-t", "retail", "one.bin", "two.bin"])
        self.assertEqual(settings["out"], "one.bin")
        self.assertEqual(len(said.output), 1)
        self.assertIn("excess parameters", said.output[0])

    def test_s_takes_the_next_word_only_when_it_is_not_a_switch(self):
        """`-s -noenter` makes the name up and keeps the switch."""
        self.assertEqual(parse_build(["-s", "hash.txt"]), {"sha_file": "hash.txt"})
        self.assertEqual(parse_build(["-s", "-noenter"]),
                         {"sha_file": True, "no_enter": True})
        self.assertEqual(parse_build(["-t", "retail", "-s"]),
                         {"image_type": "retail", "sha_file": True})

    def test_a_verbose_level_is_taken_for_v(self):
        """So a J-Runner that asks for `-v2` still runs."""
        for word in ("-v", "-v0", "-v1", "-v2"):
            with self.subTest(word=word):
                self.assertEqual(parse_build([word]), {"verbose": 1})

    def test_help_ends_the_program_before_the_rest_is_read(self):
        with (contextlib.redirect_stdout(io.StringIO()) as out,
              self.assertRaises(SystemExit) as ended):
            parse_build(["-noenter", "-?", "-t", "nonsense"])
        self.assertEqual(ended.exception.code, 0)
        self.assertIn("examples:", out.getvalue())

    def test_a_line_argparse_does_not_take_is_refused(self):
        for argv in ([], ["-t"], ["-d", "-noenter"], ["-x"], ["-verbose"],
                     ["-o", "nonsense=1"], ["-o", "cpu_key=00"]):
            with self.subTest(argv=argv):
                self.refused(argv)


class ExtractModeSLine(unittest.TestCase):
    """`xeBuild extract <switch> <input NAND image>`, and nothing of build mode's."""

    def run_main(self, argv):
        """The exit status and all that was printed; argparse ends help and a refusal
        with an exit of its own."""
        with (contextlib.redirect_stdout(io.StringIO()) as out,
              contextlib.redirect_stderr(io.StringIO()) as err):
            try:
                code = main(argv)
            except SystemExit as ended:
                code = ended.code
        return code, out.getvalue() + err.getvalue()

    def test_its_usage_is_its_own(self):
        code, said = self.run_main(["extract", "-?"])
        self.assertEqual(code, 0)
        self.assertIn("xeBuild extract", said)
        self.assertIn("<input NAND image>", said)

    def test_a_build_switch_or_no_image_is_refused_with_that_usage(self):
        for argv in (["extract", "-t", "retail", "x.bin"], ["extract", "-v"]):
            with self.subTest(argv=argv):
                code, said = self.run_main(argv)
                self.assertEqual(code, 2)
                self.assertIn("xeBuild extract", said)

    def test_a_file_of_no_flash_s_length_is_not_a_dump(self):
        where = tempfile.mkdtemp(prefix="xebuild-cli-")
        self.addCleanup(shutil.rmtree, where, ignore_errors=True)
        path = os.path.join(where, "nanddump.bin")
        with open(path, "wb") as handle:
            handle.write(bytes(0x1000))
        # A refusal ends the run, so it is logged CRITICAL.
        with self.assertLogs("xebuild", "CRITICAL") as said:
            code, _ = self.run_main(["extract", "-noenter", path])
        self.assertEqual(code, 1)
        self.assertIn("Loading dump failed", "\n".join(said.output))

if __name__ == "__main__":
    unittest.main()
