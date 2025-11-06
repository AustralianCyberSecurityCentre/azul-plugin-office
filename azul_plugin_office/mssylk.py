"""Microsoft Office SYLK files (.slk) parser.

Symbolic Link files are csv like text files used as an interchange format
in very early versions of Excel.  It supports Excel 4.0 macros and so can
be used as an attack vector.

Office versions as recent as 2016 still support the format.
"""

import pprint
import re

import click


class Sylk(object):
    """Parses Microsoft Office .slk files for malicious cells."""

    HEADER_MAGIC = b"ID;P"
    # eg. C;K33;EEXEC("cmd.exe /c @echo off&pi^n^g 54 -n 5")
    MACRO_PAT = re.compile(b";E([A-Z]{3,})\\|?\\(?([^A-Z].+?)\\)?\\r")
    URL_PAT = re.compile(r'(https?://[^\'"\)\(\r\n\\]+)')

    def __init__(self, handle=None, content=None):
        """Parse the supplied file contents as a .slk file.

        Either handle or content can be supplied but not both.

        @param handle: File-like object to read from.
        @param content: Byte string of file content.
        """
        self._functions = None
        self._commands = None
        self._normalised = None
        self._urls = None
        self._is_sylk = None

        if content and handle:
            raise Exception("Specify only one of handle or content")

        if handle:
            # try to break early
            self.content = handle.read(1024)
            if not self.is_sylk:
                return
            self.content += handle.read()
        else:
            self.content = content

    @property
    def is_sylk(self):
        """Test for header and the first few lines have semicolons."""
        if self._is_sylk is not None:
            return self._is_sylk

        if self.content.startswith(Sylk.HEADER_MAGIC) and all([b";" in ln for ln in self.content.split(b"\r")[:10]]):
            self._is_sylk = True
        else:
            self._is_sylk = False
        return self._is_sylk

    @property
    def functions(self):
        """List of macro function calls."""
        if self._functions is not None:
            return self._functions

        self._parse()
        return self._functions

    @property
    def commands(self):
        """List of dicts containing known execution commands."""
        if self._commands is not None:
            return self._commands

        self._parse()
        return self._commands

    @property
    def normalised(self):
        """List of normalised command strings."""
        if self._normalised is not None:
            return self._normalised

        self._parse()
        return self._commands

    @property
    def urls(self):
        """Any url-like strings extracted from commands."""
        if self._urls is not None:
            return self._urls

        self._parse()
        return self.urls

    def _parse(self):
        self._functions = set()
        self._commands = []
        self._normalised = []
        self._urls = []
        for m in Sylk.MACRO_PAT.findall(self.content):
            # .slk can use full ansi char set but not unicode
            macro = m[0].decode("latin-1")
            param = m[1].decode("latin-1")
            self._functions.add(macro)
            # some commands contain trailing cell info
            param = param.rsplit("!", 1)[0]
            url = Sylk.URL_PAT.findall(param)
            if macro in ("CMD", "EXEC", "MSEXCEL"):
                self._commands.append({"function": macro, "param": param})
                self._normalised.append(self._normalise(param))
                # try once normalised
                if not url:
                    url = Sylk.URL_PAT.findall(self._normalise(param))
            for u in url:
                self._urls.append(u)

    def _normalise(self, cmd):
        return (
            cmd.replace("^", "")
            .replace("''", "'")
            .replace('\\"', '"')
            .replace("\\'", "'")
            .replace("\\\\", "\\")
            .strip("\"'")
            .rstrip("\"'")
            .lower()
        )


@click.command()
@click.argument("filename", nargs=-1)
def main(filename: tuple[str]):
    """Process the list of files, printing metadata to stdout."""
    for f in filename:
        print("-" * 30)
        print(f)
        print("-" * 30)
        try:
            s = Sylk(open(f, "rb"))
            if not s.is_sylk:
                print("Not SYLK (.slk)")
                continue
            print("SYLK File (.slk)")
            print("Macro Functions:")
            pprint.pprint(s.functions)
            print("Commands:")
            for x in [(c["function"], c["param"]) for c in s.commands]:
                print("%s: %s" % x)
            print("Normalised Commands:")
            for x in s.normalised:
                print(x)
            print("URL Patterns:")
            pprint.pprint(s.urls)

        except Exception as ex:
            print(ex)
