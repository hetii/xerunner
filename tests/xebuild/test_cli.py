"""The original's command line, read into the settings a build takes."""

import io
import os
import shutil
import tempfile
import unittest
import contextlib

from xebuild.cli import main, parse
from xebuild.config import BuildConfig
from xebuild.cli.command import UsageError


class ReadingACommandLine(unittest.TestCase):

    def test_every_switch_lands_on_the_setting_of_the_same_meaning(self):
        mode, settings, _flags = parse([
            "-t", "glitch2", "-c", "jasper256",
            "-p", "7E5068DBB3FD03F04E367028D475EEC2",
            "-b", "DD88AD0C9ED669E7B56794FB68563EFA", "-d", "data", "-f", "17559",
            "-i", "flash", "-r", "WB", "-a", "xl_usb", "-a", "hvFixKeys",
            "-8", "a.bin,0x10;b.bin,0x20", "-noenter", "-norandom", "-v", "out.bin",
        ])
        self.assertEqual(mode, "build")
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
        _mode, settings, _flags = parse([
            "-o", "macid=00:22:48:F1:01:02;gameregion=0x00FF;nomobile",
            "-o", "patchsmc=false",
        ])
        self.assertEqual(settings, {"macid": "00:22:48:F1:01:02",
                                    "gameregion": "0x00FF", "nomobile": True,
                                    "patchsmc": "false"})

    def test_what_it_reads_is_a_configuration_that_takes_it(self):
        _mode, settings, _flags = parse(["-t", "jtag", "-c", "falcon", "-o",
                                         "cygnos;xellbutton=power;cfldv=10"])
        config = BuildConfig(**settings)
        self.assertEqual((config.image_type.name, config.console_name), ("jtag",
                                                                          "falcon"))
        self.assertTrue(config.cygnos)
        self.assertEqual((config.xellbutton, config.cfldv), ("power", 10))

    def test_s_takes_the_next_word_whatever_it_is(self):
        """`-s -noenter` loses the switch, as the original's does, and makes a name."""
        self.assertEqual(parse(["-s", "hash.txt"])[1], {"sha_file": "hash.txt"})
        self.assertEqual(parse(["-s", "-noenter"])[1], {"sha_file": True})
        self.assertEqual(parse(["-t", "retail", "-s"])[1],
                         {"image_type": "retail", "sha_file": True})

    def test_the_verbose_level_is_its_third_character(self):
        self.assertEqual(parse(["-v2"])[1], {"verbose": 2})
        self.assertEqual(parse(["-v0"])[1], {})
        self.assertEqual(parse(["-verbose"])[1], {})

    def test_a_mode_word_goes_first_and_build_is_the_default(self):
        self.assertEqual(parse(["build", "-t", "retail"])[0], "build")
        self.assertEqual(parse(["update", "-t", "retail"])[0], "update")

    def test_help_stops_the_line_where_it_stands(self):
        _mode, settings, flags = parse(["-noenter", "-?", "-t", "jtag"])
        self.assertTrue(flags["help"])
        self.assertEqual(settings, {"no_enter": True})

    def test_what_the_original_answers_with_its_usage_is_refused(self):
        for argv in ([], ["-t"], ["-x"], ["-o", "nonsense=1"], ["-o", "cpu_key=00"]):
            with self.subTest(argv=argv), self.assertRaises(UsageError):
                parse(argv)


class ExtractModeSLine(unittest.TestCase):
    """`xeBuild extract <switch> <input NAND image>`, and nothing of build mode's."""

    def run_main(self, argv):
        with (contextlib.redirect_stdout(io.StringIO()) as out,
              contextlib.redirect_stderr(io.StringIO()) as err):
            code = main(argv)
        return code, out.getvalue() + err.getvalue()

    def test_its_usage_is_its_own(self):
        code, said = self.run_main(["extract", "-?"])
        self.assertEqual(code, 0)
        self.assertIn("extract <switch> <input NAND image>", said)

    def test_a_build_switch_or_no_image_is_refused_with_that_usage(self):
        for argv in (["extract", "-t", "retail", "x.bin"], ["extract", "-v"]):
            with self.subTest(argv=argv):
                code, said = self.run_main(argv)
                self.assertEqual(code, 2)
                self.assertIn("extract <switch>", said)

    def test_a_file_of_no_flash_s_length_is_not_a_dump(self):
        where = tempfile.mkdtemp(prefix="xebuild-cli-")
        self.addCleanup(shutil.rmtree, where, ignore_errors=True)
        path = os.path.join(where, "nanddump.bin")
        with open(path, "wb") as handle:
            handle.write(bytes(0x1000))
        code, said = self.run_main(["extract", "-noenter", path])
        self.assertEqual(code, 1)
        self.assertIn("Loading dump failed", said)

if __name__ == "__main__":
    unittest.main()
