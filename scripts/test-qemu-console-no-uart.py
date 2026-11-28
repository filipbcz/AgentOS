"""Synthetic inventory rejection tests; genuine proof comes only from QEMU."""
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location("console_runner",Path(__file__).with_name("qemu-console-no-uart.py"))
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class InventoryTests(unittest.TestCase):
    def test_legacy_keyboard_without_uart(self):
        runner.verify_hardware('bus: isa.0\n  dev: i8042, id ""\n  dev: isa-debugcon, id ""\n')
    def test_uart_or_missing_controller_rejected(self):
        for tree in ('bus: isa.0\n',
                     '  dev: i8042, id ""\n  dev: isa-serial, id ""\n',
                     '  dev: i8042, id ""\n  dev: pci-serial, id ""\n',
                     '  dev: i8042, id ""\n  dev: pci-serial-4x, id ""\n'):
            with self.subTest(tree=tree),self.assertRaises(ValueError):
                runner.verify_hardware(tree)


if __name__=="__main__":unittest.main()
