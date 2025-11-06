import os
import sys
from datetime import datetime

from azul_runner.test_utils import FileManager

from azul_plugin_office.rtfinfo import RtfParser

sys.path.append("azul_plugin_office/tests")

PATH = os.path.dirname(__file__) + "/../data"


def test_invalid_content():
    """
    Test on a buffer that is not rtf format.
    """
    r = RtfParser(buf=b"asdjkhfkjhdfsakljhdfaskjdfhlasf")
    assert not r.info_group


def test_example_rtf():
    """
    Test extracting properties on simple benign RTF document.
    """
    # Benign simple RTF
    fm = FileManager()
    b = fm.download_file_bytes("da1a54dd97017f37502b1e40a1b5001e0e7fd177a68aecf808a02df1daa47b9f")

    r = RtfParser(b)
    info = r.info_group
    assert info["author"] == [b"Vb1"]
    assert info["creatim"] == [datetime(2015, 7, 16, 15, 15)]
    assert info["doccomm"] == [b"This is a test RTF file"]
    assert info["keywords"] == [b"test, example, foobar"]
    assert info["printim"] == [datetime(1, 1, 1, 0, 0)]
    assert info["revtim"] == [datetime(2020, 4, 7, 9, 39)]
    assert info["subject"] == [b"Hello World"]
    assert info["title"] == [b"Test File"]
