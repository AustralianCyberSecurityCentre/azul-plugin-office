"""MIME HTML (.mhtml and single webpage .doc) Parsing.

A library to parse MHTML formatted files (.mht).

These are mime encoded files with a main html body and zero or more mime parts
for embedded/linked content.

It is used by MS Word when saving documents to 'Single Web Page' and by
Internet Explorer to save off web pages/sites as a single archive file.
"""

import email
import re
from datetime import datetime

HEADER_DEPTH = 200


class Parser(object):
    """A Simple MIME HTML Parser."""

    def __init__(self, content):
        """Create a parser for the supplied byte string."""
        self.content = content

    def is_mhtml(self):
        """Return True if the content in MIME HTML format."""
        # Check we have the right MIME headers but without
        # Some of the RFC822 mail ones
        # Note: Internet Explorer web archives reuse (From: Subject: Date:)
        return (
            b"MIME-Version: " in self.content[:HEADER_DEPTH]
            and b"Content-Type: " in self.content[:HEADER_DEPTH]
            and not re.search(b"(Received:|To:|Cc:)", self.content[:HEADER_DEPTH])
        )

    def is_mhtml_doc(self):
        """Return True if the content is a word document saved in MHTML format."""
        return self.is_mhtml() and b"<o:DocumentProperties>" in self.content

    def is_mhtml_web(self):
        """Return True if the content is a saved webpage/site in MHTML format."""
        # Probably need to do this smarter
        # Just check for saving application for now
        return self.is_mhtml() and b"Saved by Microsoft Internet Explorer" in self.content[:HEADER_DEPTH]

    @property
    def document_properties(self):
        """Return a dict of any MHTML document properties/summary."""
        res = {}
        for prop, func in [
            ("Author", str),
            ("Template", str),
            ("LastAuthor", str),
            ("Revision", int),
            ("TotalTime", int),
            ("LastPrinted", ts_to_dt),
            ("Created", ts_to_dt),
            ("LastSaved", ts_to_dt),
            ("Pages", int),
            ("Words", int),
            ("Characters", int),
            ("Company", str),
            ("Lines", int),
            ("Paragraphs", int),
            ("CharactersWithSpaces", int),
            ("Version", str),
        ]:
            m = re.search(
                "<o:{0}>(.*)</o:{0}>".format(prop).encode("utf-8"),
                self.content,
            )
            if m:
                res[prop] = func(m.group(1).decode("utf-8"))
            # title appears to be stored in html tags, if at all
            m = re.search(b"<title>(.*)</title>", self.content)
            if m:
                res["Title"] = m.group(1).decode("utf-8")
        return res

    @property
    def mime_parts(self):
        """Return an iterator of mime parts/messages stored in this mthml file."""
        return email.message_from_string(self.content.decode("utf-8")).walk()


def ts_to_dt(ts):
    """Convert the expected data timestamp to a datetime object."""
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
