"""What a configuration guarantees to whatever reads it.

Two kinds of test. The shape ones say which mode carries which settings and, just as
importantly, which it does not: a client run has no release directory and an extract run
has no console, and a class that quietly grew one would be a class carrying another
mode's switches. The value ones say what a setter accepts and what it refuses, because
the promise this package makes is that a configuration which exists is already valid.

Scratch goes on the ramdisk. Nothing here writes more than a few hundred bytes, but the
rule is the rule: a test that writes to the disk for no reason is a test that wears it.
"""

import os
import shutil
import tempfile
import unittest

from xebuild.config.base import BaseConfig
from xebuild.config.network import NetworkConfig
from xebuild.config.options import OptionsConfig
from xebuild.config.release import ReleaseConfig
from xebuild.config import BuildConfig, ClientConfig, ExtractConfig, UpdateConfig

OPTIONS = sorted(set(OptionsConfig()) - set(BaseConfig()))
SWITCHES = ("nodvd", "olddvd", "cygnos", "demon", "nomobile", "smcnocheck", "noremap",
            "noecdremap", "nandmu", "nosecurity", "nosusecurity", "patchsmc",
            "smcnoeject", "smcnoblink")
NUMBERS = ("cputemp", "gputemp", "edramtemp", "overcputemp", "overgputemp",
           "overedramtemp", "cpufan", "gpufan", "cfldv", "avregion", "gameregion",
           "dvdregion")
BUTTONS = ("xellbutton", "xellbutton2", "dualboot")
TEMPERATURES = ("cputemp", "gputemp", "edramtemp", "overcputemp", "overgputemp",
                "overedramtemp")
BYTES = ("macid", "dvdkey")


def a_directory(case):
    """A directory that is there, removed when the class is done with it.

    Where it lands is `tests/__init__.py`'s business, not this file's.
    """
    where = tempfile.mkdtemp(prefix="xebuild-config-")
    case.addClassCleanup(shutil.rmtree, where, ignore_errors=True)
    return where


class WhatEachModeCarries(unittest.TestCase):
    """The settings of one mode do not leak into another."""

    def test_every_mode_has_the_two_that_are_universal(self):
        for klass in (BuildConfig, UpdateConfig, ClientConfig, ExtractConfig):
            with self.subTest(mode=klass.__name__):
                self.assertEqual(set(BaseConfig()) - set(klass()), set())

    def test_the_base_holds_nothing_but_those_two(self):
        self.assertEqual(sorted(BaseConfig()), ["no_enter", "verbose"])

    def test_only_the_modes_that_read_a_release_have_its_four(self):
        four = set(ReleaseConfig()) - set(BaseConfig())
        self.assertEqual(sorted(four),
                         ["append", "data", "firmware_ext", "section_ext"])
        for klass in (BuildConfig, UpdateConfig):
            with self.subTest(mode=klass.__name__):
                self.assertEqual(four - set(klass()), set())
        for klass in (ClientConfig, ExtractConfig):
            with self.subTest(mode=klass.__name__):
                self.assertEqual(four & set(klass()), set())

    def test_only_the_modes_that_reach_a_console_know_an_address(self):
        one = set(NetworkConfig()) - set(BaseConfig())
        self.assertEqual(sorted(one), ["address"])
        for klass in (UpdateConfig, ClientConfig):
            self.assertEqual(one - set(klass()), set())
        for klass in (BuildConfig, ExtractConfig):
            self.assertEqual(one & set(klass()), set())

    def test_only_build_mode_carries_the_options(self):
        for klass in (UpdateConfig, ClientConfig, ExtractConfig):
            with self.subTest(mode=klass.__name__):
                self.assertEqual(set(OPTIONS) & set(klass()), set())
        self.assertEqual(set(OPTIONS) - set(BuildConfig()), set())

    def test_the_two_meanings_of_the_same_switch_are_two_settings(self):
        """`-d` is read in build mode and written in update mode."""
        self.assertIn("per_build", BuildConfig())
        self.assertNotIn("per_build", UpdateConfig())
        self.assertIn("dump_to", UpdateConfig())
        self.assertNotIn("dump_to", BuildConfig())

    def test_a_mode_refuses_another_mode_s_setting(self):
        for klass, foreign in ((ExtractConfig, "console"), (ClientConfig, "data"),
                               (UpdateConfig, "image_type"), (BuildConfig, "address")):
            with (self.subTest(mode=klass.__name__, setting=foreign),
                  self.assertRaises(ValueError)):
                klass(**{foreign: "whatever"})

    def test_a_setting_that_is_no_setting_at_all(self):
        with self.assertRaises(ValueError):
            BuildConfig(banana=1)


class TheUniversalTwo(unittest.TestCase):

    def test_verbosity_has_three_levels(self):
        for level in (0, 1, 2):
            self.assertEqual(BuildConfig(verbose=level).verbose, level)
        for wrong in (3, -1, "loud"):
            with self.subTest(level=wrong), self.assertRaises(ValueError):
                BuildConfig(verbose=wrong)

    def test_waiting_for_the_enter_key_is_a_yes_or_no(self):
        self.assertFalse(BuildConfig().no_enter)
        self.assertTrue(BuildConfig(no_enter=True).no_enter)
        self.assertFalse(BuildConfig(no_enter="false").no_enter)
        with self.assertRaises(ValueError):
            BuildConfig(no_enter="maybe")


class WhatBuildModeTakes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.where = a_directory(cls)

    def test_the_eleven_image_types_arrive_as_the_kind_they_name(self):
        """`-t` resolves through `imagetypes`, as `-c` resolves through `boards`."""
        eleven = ("retail", "jtag", "glitch2m", "glitch2", "glitch", "devkit16",
                  "devkit", "testkit16", "testkit", "devgl16", "devgl")
        for kind in eleven:
            with self.subTest(kind=kind):
                self.assertEqual(BuildConfig(image_type=kind).image_type.name, kind)
        self.assertEqual(BuildConfig(image_type="DevGL16").image_type.name, "devgl16")
        with self.assertRaises(ValueError):
            BuildConfig(image_type="banana")

    def test_retail_when_nobody_says(self):
        self.assertEqual(BuildConfig().image_type.name, "retail")

    def test_a_console_arrives_as_the_console_it_names(self):
        made = BuildConfig(console="jasper256")
        self.assertEqual(made.console.name, "jasperbb")
        self.assertFalse(made.bigffs)
        self.assertTrue(BuildConfig(console="jasperbigffs").bigffs)
        with self.assertRaises(ValueError):
            BuildConfig(console="banana")

    def test_no_console_until_one_is_named(self):
        self.assertIsNone(BuildConfig().console)
        self.assertFalse(BuildConfig().bigffs)

    def test_a_key_arrives_as_sixteen_bytes(self):
        for field in ("cpu_key", "one_bl_key"):
            with self.subTest(field=field):
                key = "00112233445566778899aabbccddeeff"
                made = BuildConfig(**{field: key})
                self.assertEqual(getattr(made, field), bytes.fromhex(key))
                self.assertIsNone(getattr(BuildConfig(), field))
                for wrong in ("ff", "zz" * 16, b"\x00" * 15):
                    with self.assertRaises(ValueError):
                        BuildConfig(**{field: wrong})

    def test_a_directory_that_is_read_has_to_be_there(self):
        made = BuildConfig(data=self.where, per_build=self.where)
        self.assertEqual(made.data, self.where)
        self.assertEqual(made.per_build, self.where)
        for field in ("data", "per_build"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                BuildConfig(**{field: os.path.join(self.where, "nothing-here")})

    def test_a_directory_nobody_named_is_nobody_s_business_yet(self):
        self.assertIsNone(BuildConfig().data)
        self.assertIsNone(BuildConfig().per_build)

    def test_a_trailing_separator_is_not_part_of_the_name(self):
        self.assertEqual(BuildConfig(data=self.where + "/").data, self.where)

    def test_the_sha_file_is_a_name_or_a_yes(self):
        self.assertIsNone(BuildConfig().sha_file)
        self.assertIs(BuildConfig(sha_file=True).sha_file, True)
        self.assertEqual(BuildConfig(sha_file="image.sha").sha_file, "image.sha")
        with self.assertRaises(ValueError):
            BuildConfig(sha_file="  ")

    def test_raw_patches_arrive_as_a_name_and_an_offset(self):
        made = BuildConfig(raw_patches="my.bin,0x12345;other.bin,4096")
        self.assertEqual(made.raw_patches, (("my.bin", 0x12345), ("other.bin", 4096)))
        self.assertEqual(BuildConfig(raw_patches=[("a.bin", 16)]).raw_patches,
                         (("a.bin", 16),))
        self.assertEqual(BuildConfig().raw_patches, ())
        for wrong in ("my.bin", "my.bin,", "my.bin,zz", ",0x10"):
            with self.subTest(patch=wrong), self.assertRaises(ValueError):
                BuildConfig(raw_patches=wrong)

    def test_an_extension_is_one_word(self):
        for field in ("firmware_ext", "section_ext"):
            with self.subTest(field=field):
                self.assertEqual(getattr(BuildConfig(**{field: "rgh"}), field), "rgh")
                for wrong in ("a b", "a/b", "a;b", "  "):
                    with self.assertRaises(ValueError):
                        BuildConfig(**{field: wrong})

    def test_drawing_no_nonces_is_a_yes_or_no(self):
        self.assertFalse(BuildConfig().no_random)
        self.assertTrue(BuildConfig(no_random=True).no_random)
        with self.assertRaises(ValueError):
            BuildConfig(no_random="maybe")


class TheOptions(unittest.TestCase):

    def test_there_are_thirty_one(self):
        self.assertEqual(len(OPTIONS), 31)
        self.assertEqual(
            set(OPTIONS), set(SWITCHES) | set(NUMBERS) | set(BUTTONS) | set(BYTES)
        )

    def test_a_switch_is_set_or_not(self):
        for name in SWITCHES:
            with self.subTest(option=name):
                self.assertFalse(BuildConfig()[name])
                self.assertTrue(BuildConfig(**{name: True})[name])
                self.assertTrue(BuildConfig(**{name: "true"})[name])
                self.assertFalse(BuildConfig(**{name: "false"})[name])
                with self.assertRaises(ValueError):
                    BuildConfig(**{name: "maybe"})

    def test_a_number_is_decimal_unless_it_says_otherwise(self):
        for name, good in (("cputemp", "60"), ("overedramtemp", "0x50"),
                           ("avregion", "0x300"), ("gameregion", "255"),
                           ("dvdregion", "2"), ("cpufan", "0x40")):
            with self.subTest(option=name):
                self.assertEqual(BuildConfig(**{name: good})[name], int(good, 0))
                for wrong in ("abc", "", True, "-5"):
                    with self.assertRaises(ValueError):
                        BuildConfig(**{name: wrong})

    def test_what_nothing_given_means(self):
        """0 leaves a temperature or the game region alone, as the original's 0 does;
        a fan and the other two regions write 0 when asked, so nothing is None."""
        for name in (*TEMPERATURES, "gameregion"):
            with self.subTest(option=name):
                self.assertEqual(BuildConfig()[name], 0)
        for name in ("cpufan", "gpufan", "avregion", "dvdregion", "cfldv"):
            with self.subTest(option=name):
                self.assertIsNone(BuildConfig()[name])

    def test_a_temperature_is_forty_to_a_hundred_and_twenty_or_nothing(self):
        """Measured: 39 and 121 are left unused by the original, 40 and 120 written."""
        for name in TEMPERATURES:
            with self.subTest(option=name):
                for good in (0, 40, 120):
                    self.assertEqual(BuildConfig(**{name: good})[name], good)
                for wrong in (1, 39, 121, 256):
                    with self.assertRaises(ValueError):
                        BuildConfig(**{name: wrong})

    def test_the_fan_speeds_are_forty_to_a_hundred_or_auto(self):
        """Measured: 1 to 39 and past 100 are left unused by the original, 0 is auto."""
        for name in ("cpufan", "gpufan"):
            with self.subTest(option=name):
                for good in (0, 40, 100):
                    self.assertEqual(BuildConfig(**{name: good})[name], good)
                for wrong in (1, 39, 101, 256, -1):
                    with self.assertRaises(ValueError):
                        BuildConfig(**{name: wrong})

    def test_the_regions_fit_their_fields(self):
        self.assertEqual(BuildConfig(avregion=0xFFFFFFFF).avregion, 0xFFFFFFFF)
        self.assertEqual(BuildConfig(dvdregion=0).dvdregion, 0)
        for name, wrong in (("avregion", 0x100000000), ("dvdregion", 0x100000000),
                            ("gameregion", 0x10000)):
            with self.subTest(option=name), self.assertRaises(ValueError):
                BuildConfig(**{name: wrong})

    def test_a_negative_number_is_refused_wherever_one_is_taken(self):
        """Measured: the original turns away `-o cputemp=-5` and every one like it."""
        for name in NUMBERS:
            with self.subTest(option=name), self.assertRaises(ValueError):
                BuildConfig(**{name: "-5"})

    def test_cfldv_is_one_to_thirty_two(self):
        for good in (1, 32, "0x10"):
            with self.subTest(given=good):
                self.assertEqual(BuildConfig(cfldv=good).cfldv, int(str(good), 0))
        for wrong in (33, 99, -10):
            with self.subTest(given=wrong), self.assertRaises(ValueError):
                BuildConfig(cfldv=wrong)

    def test_a_value_outside_a_range_is_refused_and_never_replaced(self):
        """Neither wrapped into the range nor moved to the nearest end of it.

        The original does both: it takes `cfldv` modulo 256 first, so `=288` passes
        silently as 32, `=300` is reported as 44 and `=256` becomes zero; and what
        survives that it clamps, so `=200` builds an image for 32 with nothing to say
        the caller asked for something else. A value nobody asked for is a fault that
        leaves no trace, so every one of these is turned away instead.
        """
        for given in (33, 200, 256, 288, 300, 999):
            with self.subTest(given=given), self.assertRaises(ValueError):
                BuildConfig(cfldv=given)
        for name in ("cpufan", "gpufan"):
            for given in (101, 256, -1):
                with (self.subTest(option=name, given=given),
                      self.assertRaises(ValueError)):
                    BuildConfig(**{name: given})

    def test_zero_is_no_ldv_at_all_rather_than_an_ldv_of_zero(self):
        """Measured, and it is why the original refuses `-o cfldv=0`.

        Its own messages spell the rule out: "LDV was already set to %d", else
        "setting LDV from image to %d", else 0 for a devkit or testkit image and 1 with
        a warning for anything else. So nothing supplied is `None` here, and what to
        make of nothing belongs to the build that knows the image type and the dump.
        """
        self.assertIsNone(BuildConfig().cfldv)
        for wrong in (0, "0"):
            with self.subTest(given=wrong), self.assertRaises(ValueError):
                BuildConfig(cfldv=wrong)

    def test_a_button_is_one_of_thirteen(self):
        thirteen = ("power", "eject", "remopower", "remox", "winbutton", "wirelessx",
                    "kiosk", "wiredx", "wiredxb1", "wiredxb2", "wiredxb3", "wiredxf1",
                    "wiredxf2")
        for name in BUTTONS:
            with self.subTest(option=name):
                for button in thirteen:
                    self.assertEqual(BuildConfig(**{name: button})[name], button)
                self.assertEqual(BuildConfig(**{name: "POWER"})[name], "power")
                with self.assertRaises(ValueError):
                    BuildConfig(**{name: "banana"})

    def test_no_button_unless_something_names_one(self):
        """A build takes the eject button for none -- see `Build`'s boot flags."""
        self.assertIsNone(BuildConfig().xellbutton)
        self.assertIsNone(BuildConfig().xellbutton2)
        self.assertIsNone(BuildConfig().dualboot)

    def test_a_mac_address_is_six_bytes_however_it_is_written(self):
        # The original takes `:` and refuses `-`; a dash reads as a colon here.
        wanted = bytes.fromhex("002248F10102")
        for written in ("00:22:48:F1:01:02", "002248F10102", "00-22-48-f1-01-02"):
            with self.subTest(written=written):
                self.assertEqual(BuildConfig(macid=written).macid, wanted)
        self.assertIsNone(BuildConfig().macid)
        for wrong in ("0022", "zz" * 6, "00:22:48:F1:01"):
            with self.assertRaises(ValueError):
                BuildConfig(macid=wrong)

    def test_a_dvd_key_is_sixteen(self):
        self.assertEqual(BuildConfig(dvdkey="AB" * 16).dvdkey, bytes.fromhex("AB" * 16))
        self.assertIsNone(BuildConfig().dvdkey)
        for wrong in ("ABCD", "ZZ" * 16):
            with self.assertRaises(ValueError):
                BuildConfig(dvdkey=wrong)


class TheIni(unittest.TestCase):
    """`options.ini` sets what it names, and the command line beats it."""

    @classmethod
    def setUpClass(cls):
        cls.where = a_directory(cls)
        cls.ini = os.path.join(cls.where, "options.ini")
        with open(cls.ini, "w") as handle:
            handle.write(
                "; a comment\n"
                "type = trinity\n"
                "rev = 9199\n"
                "1blkey = DD88AD0C9ED669E7B56794FB68563EFA\n"
                "cpukey =\n"                      # blank: not set
                "patchsmc = true\n"
                "nomobile = false\n"
                "cfldv = 12\n"
                "xellbutton = power   ; trailing comment\n"
            )

    def test_it_sets_what_it_names(self):
        made = BuildConfig(ini=self.ini)
        self.assertEqual(made.console.name, "trinity")
        self.assertEqual(made.section_ext, "9199")
        self.assertEqual(made.one_bl_key.hex().upper(),
                         "DD88AD0C9ED669E7B56794FB68563EFA")
        self.assertTrue(made.patchsmc)
        self.assertFalse(made.nomobile)
        self.assertEqual(made.cfldv, 12)
        self.assertEqual(made.xellbutton, "power")

    def test_nodvd_on_the_command_line_clears_the_ini_s_button(self):
        """The ini's settings go first and the command line's after, each `nodvd` or
        `olddvd` before `xellbutton`; either clears the button (0x42698E). Measured."""
        self.assertIsNone(BuildConfig(ini=self.ini, nodvd=True).xellbutton)
        self.assertIsNone(BuildConfig(ini=self.ini, olddvd=True).xellbutton)
        self.assertEqual(BuildConfig(ini=self.ini, nodvd=False).xellbutton, "power")
        self.assertEqual(
            BuildConfig(ini=self.ini, nodvd=True, xellbutton="remox").xellbutton,
            "remox")

    def test_the_ini_s_addons_follow_the_command_line_s_and_repeat_nothing(self):
        """Colon-separated, after `-a`, a name of four characters or fewer passed
        over, and one already there -- in any case -- dropped. Measured (0x427340)."""
        ini = os.path.join(self.where, "addons.ini")
        with open(ini, "w") as handle:
            handle.write("addon = nohdd:abc:NOFCRT:nohdd\n")
        self.assertEqual(BuildConfig(ini=ini).append, ("nohdd", "NOFCRT"))
        self.assertEqual(BuildConfig(ini=ini, append=("nofcrt", "nolan")).append,
                         ("nofcrt", "nolan", "nohdd"))
        self.assertEqual(BuildConfig(ini=ini, append="nolan").append,
                         ("nolan", "nohdd", "NOFCRT"))

    def test_a_blank_value_sets_nothing(self):
        self.assertIsNone(BuildConfig(ini=self.ini).cpu_key)

    def test_the_command_line_beats_it(self):
        made = BuildConfig(ini=self.ini, patchsmc=False, console="corona",
                           one_bl_key="11" * 16, cfldv=1)
        self.assertFalse(made.patchsmc)
        self.assertEqual(made.console.name, "corona")
        self.assertEqual(made.one_bl_key, bytes.fromhex("11" * 16))
        self.assertEqual(made.cfldv, 1)

    def test_what_it_does_not_name_keeps_its_default(self):
        self.assertEqual(BuildConfig(ini=self.ini).image_type.name, "retail")
        self.assertFalse(BuildConfig(ini=self.ini).nandmu)

    def test_a_value_it_cannot_hold_is_refused_like_any_other(self):
        bad = os.path.join(self.where, "bad.ini")
        with open(bad, "w") as handle:
            handle.write("cpufan = 500\n")
        with self.assertRaises(ValueError):
            BuildConfig(ini=bad)

    def test_only_build_mode_reads_one(self):
        self.assertFalse(hasattr(UpdateConfig, "settings_in_ini"))


class WhatUpdateModeTakes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.where = a_directory(cls)

    def test_a_directory_that_is_written_need_not_exist(self):
        where = os.path.join(self.where, "not-yet")
        self.assertEqual(UpdateConfig(dump_to=where).dump_to, where)
        self.assertIsNone(UpdateConfig().dump_to)

    def test_but_it_cannot_be_a_file(self):
        name = os.path.join(self.where, "a-file")
        with open(name, "w") as handle:
            handle.write("x")
        with self.assertRaises(ValueError):
            UpdateConfig(dump_to=name)

    def test_an_address_is_four_numbers(self):
        self.assertEqual(UpdateConfig(address="192.168.2.100").address,
                         "192.168.2.100")
        self.assertIsNone(UpdateConfig().address)
        for wrong in ("192.168.2", "192.168.2.999", "console.local", "1.2.3.4.5"):
            with self.subTest(address=wrong), self.assertRaises(ValueError):
                UpdateConfig(address=wrong)

    def test_the_four_things_it_can_be_told_not_to_do(self):
        for field in ("no_write", "no_avatar", "clean", "no_reboot"):
            with self.subTest(field=field):
                self.assertFalse(UpdateConfig()[field])
                self.assertTrue(UpdateConfig(**{field: True})[field])
                with self.assertRaises(ValueError):
                    UpdateConfig(**{field: "maybe"})


class WhatClientModeTakes(unittest.TestCase):

    def test_the_eleven_actions(self):
        eleven = ("info", "read", "write", "avatar", "compatibility", "patches",
                  "read-blocks", "write-blocks", "erase-block", "binary-patch", "keys")
        for action in eleven:
            with self.subTest(action=action):
                self.assertEqual(ClientConfig(action=action).action, action)
        self.assertIsNone(ClientConfig().action)
        with self.assertRaises(ValueError):
            ClientConfig(action="banana")

    def test_its_numbers_are_hexadecimal_with_or_without_the_prefix(self):
        """Its own legend says so: "<b> = hexadecimal block number"."""
        for field in ("block", "length", "offset"):
            with self.subTest(field=field):
                self.assertEqual(ClientConfig(**{field: "2b0"})[field], 0x2B0)
                self.assertEqual(ClientConfig(**{field: "0x2b0"})[field], 0x2B0)
                self.assertEqual(ClientConfig(**{field: 16})[field], 16)
                self.assertIsNone(ClientConfig()[field])
                with self.assertRaises(ValueError):
                    ClientConfig(**{field: "zz"})

    def test_the_two_that_stack_with_anything(self):
        made = ClientConfig(action="read", shutdown=True, reboot=True)
        self.assertTrue(made.shutdown)
        self.assertTrue(made.reboot)
        self.assertFalse(ClientConfig().shutdown)
        self.assertFalse(ClientConfig().reboot)

    def test_a_file_and_a_directory_are_names_and_nothing_more(self):
        made = ClientConfig(file="dump.bin", directory="collected")
        self.assertEqual(made.file, "dump.bin")
        self.assertEqual(made.directory, "collected")
        self.assertIsNone(ClientConfig().file)
        with self.assertRaises(ValueError):
            ClientConfig(file="   ")


class WhatExtractModeTakes(unittest.TestCase):

    def test_an_image_and_the_two_universal_settings(self):
        made = ExtractConfig(image="nanddump.bin", verbose=2, no_enter=True)
        self.assertEqual(made.image, "nanddump.bin")
        self.assertEqual(sorted(made), ["image", "no_enter", "verbose"])
        self.assertIsNone(ExtractConfig().image)
        with self.assertRaises(ValueError):
            ExtractConfig(image="  ")


class TheDoorIsTheOnlyWayIn(unittest.TestCase):

    def test_a_setter_checks_whenever_it_is_used(self):
        """Not only at construction: the property is the door either way."""
        made = BuildConfig()
        with self.assertRaises(ValueError):
            made.image_type = "banana"
        self.assertEqual(made.image_type.name, "retail")
        made.image_type = "glitch2"
        self.assertEqual(made.image_type.name, "glitch2")

    def test_a_configuration_is_a_dict_of_what_it_holds(self):
        made = BuildConfig(console="trinity", verbose=1)
        self.assertIsInstance(made, dict)
        self.assertEqual(made["verbose"], 1)
        self.assertIs(made["console"], made.console)


if __name__ == "__main__":
    unittest.main()
