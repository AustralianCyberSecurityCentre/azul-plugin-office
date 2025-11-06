"""Extract metadata from rtf (Rich Text Format) documents.

Note: this borrows very, very heavily from the implementation RTF reader
which features in the Microsoft "Word2007RTFSpec9.docx".
"""

from __future__ import print_function

import datetime
import sys

ecOK = 0  # Everything's fine!
ecStackUnderflow = 1  # Unmatched '}'
ecStackOverflow = 2  # Too many '{' - memory exhausted
ecUnmatchedBrace = 3  # RTF ended during an open group.
ecInvalidHex = 4  # invalid hex character found in data
ecBadTable = 5  # RTF table (sym or prop) not valid
ecAssertion = 6  # Assertion failure
ecEndOfFile = 7  # End of file reached while reading RTF
ecInvalidKeyword = 8  # Invalid keyword
ecInvalidParam = 9  # Invalid parameter

# useful for printing

# reader destination
rdsNorm = b"normal"
rdsSkip = b"skip"
# destinations for the info group
rdsInfo = b"info"
rdsTitle = b"title"
rdsSubject = b"subject"
rdsAuthor = b"author"
rdsManager = b"manager"
rdsCompany = b"company"
rdsOperator = b"operator"
rdsCategory = b"category"
rdsKeywords = b"keywords"
rdsComment = b"comment"
rdsVersion = b"version"
rdsDoccomm = b"doccomm"
rdsHlinkbase = b"Hlinkbase"
rdsBuptim = b"buptim"
rdsColortbl = b"colortbl"
rdsComment = b"comment"
rdsCreatim = b"creatim"
rdsDoccomm = b"doccomm"
rdsFontbl = b"fonttbl"
rdsFooter = b"footer"
rdsFooterf = b"footerf"
rdsFooterl = b"footerl"
rdsFooterr = b"footerr"
rdsFootnote = b"footnote"
rdsFtncn = b"ftncn"
rdsFtnsep = b"ftnsep"
rdsFtnsepc = b"ftnsepc"
rdsHeader = b"header"
rdsHeaderf = b"headerf"
rdsHeaderl = b"headerl"
rdsHeaderr = b"headerr"
rdsInfo = b"info"
rdsKeywords = b"keywords"
rdsOperator = b"operator"
rdsPict = b"pict"
rdsPrintim = b"printim"
rdsPrivate1 = b"private1"
rdsRevtim = b"revtim"
rdsRxe = b"rxe"
rdsStylesheet = b"stylesheet"
rdsSubject = b"subject"
rdsTc = b"tc"
rdsTxe = b"txe"
rdsXe = b"xe"


# reader internal state
risNorm = 0
risBin = 1
risHex = 2

# property types
ipropBold = 0
ipropItalic = 1
ipropUnderline = 2
ipropLeftInd = 3
ipropRightInd = 4
ipropFirstInd = 5
ipropCols = 6
ipropPgnX = 7
ipropPgnY = 8
ipropXaPage = 9
ipropYaPage = 10
ipropXaLeft = 11
ipropXaRight = 12
ipropYaTop = 13
ipropYaBottom = 14
ipropPgnStart = 15
ipropSbk = 16
ipropPgnFormat = 17
ipropFacingp = 18
ipropLandscape = 19
ipropJust = 20
ipropPard = 21
ipropPlain = 22
ipropSectd = 23
ipropYr = 24
ipropMo = 25
ipropDy = 26
ipropHr = 27
ipropMin = 28
ipropSec = 29
ipropNofpages = 30
ipropNofwords = 31
ipropNofchars = 32
ipropNofcharsws = 33
ipropVersion = 34
ipropVern = 35
ipropId = 36
ipropEdmins = 37
ipropMax = 38

ipfnBin = 0
ipfnHex = 1
ipfnSkipDest = 2

idestPict = 0
idestSkip = 1

kwdChar = 0
kwdDest = 1
kwdProp = 2
kwdSpec = 3

actnSpec = 0
actnByte = 1
actnWord = 2

propChp = 0
propPap = 1
propSep = 2
propDop = 3
propDateTime = 4  # custom field - writes to the current state's datetime_parts
propInfoGroup = 5  # custom field - for whole-of-document information
#               writes to the global document's info field

sbkNon = 0
sbkCol = 1
sbkEvn = 2
sbkOdd = 3
sbkPg = 4

pgDec = 0
pgURom = 1
pgLRom = 2
pgULtr = 3
pgLLtr = 4

justL = 0
justR = 1
justC = 2
justF = 3


class Prop:
    """Represents an RTF property."""

    def __init__(self, actn, prop, offset):
        """Define the property."""
        self.actn = actn
        self.prop = prop
        self.offset = offset


class ControlWord:
    """Represents an RTF keyword."""

    def __init__(self, default, always_use_default, role, index):
        """Define the keyword."""
        self.default = default
        self.always_use_default = always_use_default
        self.role = role
        self.index = index


CONTROL_WORD_TABLE = {
    # keyword      dflt    fPassDflt   kwd         idx
    b"b": ControlWord(1, False, kwdProp, ipropBold),
    b"u": ControlWord(1, False, kwdProp, ipropUnderline),
    b"i": ControlWord(1, False, kwdProp, ipropItalic),
    b"li": ControlWord(0, False, kwdProp, ipropLeftInd),
    b"ri": ControlWord(0, False, kwdProp, ipropRightInd),
    b"fi": ControlWord(0, False, kwdProp, ipropFirstInd),
    b"cols": ControlWord(1, False, kwdProp, ipropCols),
    b"sbknone": ControlWord(sbkNon, True, kwdProp, ipropSbk),
    b"sbkcol": ControlWord(sbkCol, True, kwdProp, ipropSbk),
    b"sbkeven": ControlWord(sbkEvn, True, kwdProp, ipropSbk),
    b"sbkodd": ControlWord(sbkOdd, True, kwdProp, ipropSbk),
    b"sbkpage": ControlWord(sbkPg, True, kwdProp, ipropSbk),
    b"pgnx": ControlWord(0, False, kwdProp, ipropPgnX),
    b"pgny": ControlWord(0, False, kwdProp, ipropPgnY),
    b"pgndec": ControlWord(pgDec, True, kwdProp, ipropPgnFormat),
    b"pgnucrm": ControlWord(pgURom, True, kwdProp, ipropPgnFormat),
    b"pgnlcrm": ControlWord(pgLRom, True, kwdProp, ipropPgnFormat),
    b"pgnucltr": ControlWord(pgULtr, True, kwdProp, ipropPgnFormat),
    b"pgnlcltr": ControlWord(pgLLtr, True, kwdProp, ipropPgnFormat),
    b"qc": ControlWord(justC, True, kwdProp, ipropJust),
    b"ql": ControlWord(justL, True, kwdProp, ipropJust),
    b"qr": ControlWord(justR, True, kwdProp, ipropJust),
    b"qj": ControlWord(justF, True, kwdProp, ipropJust),
    b"paperw": ControlWord(12240, False, kwdProp, ipropXaPage),
    b"paperh": ControlWord(15480, False, kwdProp, ipropYaPage),
    b"margl": ControlWord(1800, False, kwdProp, ipropXaLeft),
    b"margr": ControlWord(1800, False, kwdProp, ipropXaRight),
    b"margt": ControlWord(1440, False, kwdProp, ipropYaTop),
    b"margb": ControlWord(1440, False, kwdProp, ipropYaBottom),
    b"pgnstart": ControlWord(1, True, kwdProp, ipropPgnStart),
    b"facingp": ControlWord(1, True, kwdProp, ipropFacingp),
    b"landscape": ControlWord(1, True, kwdProp, ipropLandscape),
    b"par": ControlWord(0, False, kwdChar, b"\x0a"),
    b"\0x0a": ControlWord(0, False, kwdChar, b"\x0a"),
    b"\0x0d": ControlWord(0, False, kwdChar, b"\x0a"),
    b"tab": ControlWord(0, False, kwdChar, b"\x09"),
    # FUTURE: figure out how to handle this character
    b"ldblquote": ControlWord(0, False, kwdChar, b'"'),
    b"rdblquote": ControlWord(0, False, kwdChar, b'"'),
    b"bin": ControlWord(0, False, kwdSpec, ipfnBin),
    b"*": ControlWord(0, False, kwdSpec, ipfnSkipDest),
    b"'": ControlWord(0, False, kwdSpec, ipfnHex),
    b"author": ControlWord(0, False, kwdDest, rdsAuthor),
    # NOTE: this isn't strictly correct for RTF (ie. annotation authors)
    b"atnauthor": ControlWord(0, False, kwdDest, rdsAuthor),
    b"tnauthor": ControlWord(0, False, kwdDest, rdsAuthor),
    b"buptim": ControlWord(0, False, kwdDest, rdsBuptim),
    b"colortbl": ControlWord(0, False, kwdDest, rdsColortbl),
    b"comment": ControlWord(0, False, kwdDest, rdsComment),
    b"creatim": ControlWord(0, False, kwdDest, rdsCreatim),
    b"doccomm": ControlWord(0, False, kwdDest, rdsDoccomm),
    b"fonttbl": ControlWord(0, False, kwdDest, rdsFontbl),
    b"footer": ControlWord(0, False, kwdDest, rdsFooter),
    b"footerf": ControlWord(0, False, kwdDest, rdsFooterf),
    b"footerl": ControlWord(0, False, kwdDest, rdsFooterl),
    b"footerr": ControlWord(0, False, kwdDest, rdsFooterr),
    b"footnote": ControlWord(0, False, kwdDest, rdsFootnote),
    b"ftncn": ControlWord(0, False, kwdDest, rdsFtncn),
    b"ftnsep": ControlWord(0, False, kwdDest, rdsFtnsep),
    b"ftnsepc": ControlWord(0, False, kwdDest, rdsFtnsepc),
    b"header": ControlWord(0, False, kwdDest, rdsHeader),
    b"headerf": ControlWord(0, False, kwdDest, rdsHeaderf),
    b"headerl": ControlWord(0, False, kwdDest, rdsHeaderl),
    b"headerr": ControlWord(0, False, kwdDest, rdsHeaderr),
    b"info": ControlWord(0, False, kwdDest, rdsInfo),
    b"keywords": ControlWord(0, False, kwdDest, rdsKeywords),
    b"operator": ControlWord(0, False, kwdDest, rdsOperator),
    b"pict": ControlWord(0, False, kwdDest, rdsPict),
    b"printim": ControlWord(0, False, kwdDest, rdsPrintim),
    b"private1": ControlWord(0, False, kwdDest, rdsPrivate1),
    b"revtim": ControlWord(0, False, kwdDest, rdsRevtim),
    b"rxe": ControlWord(0, False, kwdDest, rdsRxe),
    b"stylesheet": ControlWord(0, False, kwdDest, rdsStylesheet),
    b"subject": ControlWord(0, False, kwdDest, rdsSubject),
    b"tc": ControlWord(0, False, kwdDest, rdsTc),
    b"title": ControlWord(0, False, kwdDest, rdsTitle),
    b"txe": ControlWord(0, False, kwdDest, rdsTxe),
    b"xe": ControlWord(0, False, kwdDest, rdsXe),
    b"{": ControlWord(0, False, kwdChar, b"{"),
    b"}": ControlWord(0, False, kwdChar, b"}"),
    b"\\": ControlWord(0, False, kwdChar, b"\\"),
    # datetime control words
    b"yr": ControlWord(0, False, kwdProp, ipropYr),
    b"mo": ControlWord(0, False, kwdProp, ipropMo),
    b"dy": ControlWord(0, False, kwdProp, ipropDy),
    b"hr": ControlWord(0, False, kwdProp, ipropHr),
    b"min": ControlWord(0, False, kwdProp, ipropMin),
    b"sec": ControlWord(0, False, kwdProp, ipropSec),
    # info group - things which write to whole of document info
    b"nofpages": ControlWord(0, False, kwdProp, ipropNofpages),
    b"nofwords": ControlWord(0, False, kwdProp, ipropNofwords),
    b"nofchars": ControlWord(0, False, kwdProp, ipropNofchars),
    b"nofcharsws": ControlWord(0, False, kwdProp, ipropNofcharsws),
    b"version": ControlWord(0, False, kwdProp, ipropVersion),
    b"vern": ControlWord(0, False, kwdProp, ipropVern),
    b"id": ControlWord(0, False, kwdProp, ipropId),
    b"edmins": ControlWord(0, False, kwdProp, ipropEdmins),
}
# CONTROL_WORD_TABLE.update(rtfinfo_dest_control_words.control_words)

# RTF parser tables
# Property descriptions
properties = [
    Prop(actnByte, propChp, ("chp", "fBold")),  # ipropBold
    Prop(actnByte, propChp, ("chp", "fItalic")),  # ipropItalic
    Prop(actnByte, propChp, ("chp", "fUnderline")),  # ipropUnderline
    Prop(actnWord, propPap, ("pap", "xaLeft")),  # ipropLeftInd
    Prop(actnWord, propPap, ("pap", "xaRight")),  # ipropRightInd
    Prop(actnWord, propPap, ("pap", "xaFirst")),  # ipropFirstInd
    Prop(actnWord, propSep, ("sep", "cCols")),  # ipropCols
    Prop(actnWord, propSep, ("sep", "xaPgn")),  # ipropPgnX
    Prop(actnWord, propSep, ("sep", "yaPgn")),  # ipropPgnY
    Prop(actnWord, propDop, ("dop", "xaPage")),  # ipropXaPage
    Prop(actnWord, propDop, ("dop", "yaPage")),  # ipropYaPage
    Prop(actnWord, propDop, ("dop", "xaLeft")),  # ipropXaLeft
    Prop(actnWord, propDop, ("dop", "xaRight")),  # ipropXaRight
    Prop(actnWord, propDop, ("dop", "yaTop")),  # ipropYaTop
    Prop(actnWord, propDop, ("dop", "yaBottom")),  # ipropYaBottom
    Prop(actnWord, propDop, ("dop", "pgnStart")),  # ipropPgnStart
    Prop(actnByte, propSep, ("sep", "sbk")),  # ipropSbk
    Prop(actnByte, propSep, ("sep", "pgnFormat")),  # ipropPgnFormat
    Prop(actnByte, propDop, ("dop", "fFacingp")),  # ipropFacingp
    Prop(actnByte, propDop, ("dop", "fLandscape")),  # ipropLandscape
    Prop(actnByte, propPap, ("pap", "just")),  # ipropJust
    Prop(actnSpec, propPap, 0),  # ipropPard
    Prop(actnSpec, propChp, 0),  # ipropPlain
    Prop(actnSpec, propSep, 0),  # ipropSectd
    Prop(actnWord, propDateTime, ("datetime", "year")),  # ipropYr
    Prop(actnWord, propDateTime, ("datetime", "month")),  # ipropMo
    Prop(actnWord, propDateTime, ("datetime", "day")),  # ipropDy
    Prop(actnWord, propDateTime, ("datetime", "hour")),  # ipropHr
    Prop(actnWord, propDateTime, ("datetime", "minute")),  # ipropMin
    Prop(actnWord, propDateTime, ("datetime", "second")),  # ipropSec
    Prop(actnWord, propInfoGroup, ("infogroup", "nofpages")),  # ipropNofpages
    Prop(actnWord, propInfoGroup, ("infogroup", "nofwords")),  # ipropNofwords
    Prop(actnWord, propInfoGroup, ("infogroup", "nofchars")),  # ipropNofchars
    Prop(actnWord, propInfoGroup, ("infogroup", "nofcharsws")),  # ipropNofcharsws
    Prop(actnWord, propInfoGroup, ("infogroup", "version")),  # ipropVersion
    Prop(actnWord, propInfoGroup, ("infogroup", "vern")),  # ipropVern
    Prop(actnWord, propInfoGroup, ("infogroup", "id")),  # ipropId
    Prop(actnWord, propInfoGroup, ("infogroup", "edmins")),  # ipropEdmins
    # new stuff goes here!
]


class RtfParserError(Exception):
    """Context for parsing errors."""

    error_messages = {
        ecOK: "Everything's fine!",
        ecStackUnderflow: "Unmatched '}'",
        ecStackOverflow: "Too many '{' - memory exhausted",
        ecUnmatchedBrace: "RTF ended during an open group.",
        ecInvalidHex: "invalid hex character found in data",
        ecBadTable: "RTF table (sym or prop) not valid",
        ecAssertion: "Assertion failure",
        ecEndOfFile: "End of file reached while reading RTF",
        ecInvalidKeyword: "Invalid keyword",
        ecInvalidParam: "Invalid parameter",
    }

    def __init__(self, ec, msg=None):
        """Wrap the parsing error code and message as an exception."""
        Exception.__init__(self)
        self.ec = ec
        self._str = "%s" % self.error_messages[ec]
        self.msg = msg

        if msg:
            self._str = "%s (%s)" % (self.error_messages[ec], self.msg)

    def __str__(self):
        """Return the exception message as human readable str."""
        return self._str


DEBUG = False


def debug(*args, **kwargs):
    """Print debug log if enabled."""
    if DEBUG:
        print(*args, **kwargs)


class RtfParserState:
    """Encapsulates parser state."""

    def __init__(self, chp=None, pap=None, sep=None, dop=None, rds=rdsNorm, ris=risNorm):
        """Create a copy of the parser's current state."""
        self.chp = chp
        if chp is None:
            self.chp = {}
        self.pap = pap
        if pap is None:
            self.pap = {}
        self.sep = sep
        if sep is None:
            self.sep = {}
        self.dop = dop
        if dop is None:
            self.dop = {}
        self.rds = rds
        self.ris = ris
        self.char_buf = []
        self.destinations = {self.rds: []}
        self.datetime_parts = {}


class RtfParser:
    """RTF format parser."""

    def __init__(self, buf):
        """Create a parser for the supplied byte string buf."""
        self.buf = buf
        self.saved_reader_state_stack = []

        # "globals"
        self.group_depth = 0

        self.state = RtfParserState()

        self.fSkipDestIfUnk = False
        self.lParam = 0
        self.cbBin = 0

        # initialise our storage mechanisms for destinations
        self.destinations = {}
        self.info_group = {}

        # to handle badly formed documents? or is this my parser?
        self.hit_sane_end_of_file = False
        self.slack = []

        # for statistics generations statistics
        self.keywords = {}

        self.parse()

        # fix up our info group so that it is pretty for external users
        info_group_destinations = [
            b"author",
            b"category",
            b"comment",
            b"company",
            b"creatim",
            b"doccomm",
            b"keywords",
            b"linkbase",
            b"linkval",
            b"manager",
            b"operator",
            b"printim",
            b"propname",
            b"revtim",
            b"subject",
            b"title",
        ]

        for igd in info_group_destinations:
            if igd in self.destinations:
                self.info_group[igd.decode("utf-8")] = self.destinations[igd]

    def push_state(self):
        """Save relevant info on a linked list of SAVE structures."""
        # snapshot internal state
        if self.hit_sane_end_of_file:
            return
        self.saved_reader_state_stack.append(self.state)
        self.group_depth += 1
        s = RtfParserState(
            self.state.chp, self.state.pap, self.state.sep, self.state.dop, self.state.rds, self.state.ris
        )
        self.state = s

    def pop_state(self):
        """Restore from last saved state."""
        if self.hit_sane_end_of_file:
            return
        if len(self.saved_reader_state_stack) <= 0:
            if not self.hit_sane_end_of_file:
                self.hit_sane_end_of_file = True
            return

        s = self.saved_reader_state_stack.pop()
        self.group_depth -= 1
        if self.state.rds != s.rds:
            self.end_group_action(self.state.rds)

        # finally, restore previous state
        self.state = s

    def end_group_action(self, dest):
        """Call this when a change of group changes the destination."""
        # force a change of state
        if dest not in self.state.destinations:
            self.state.destinations[dest] = []
        if len(self.state.char_buf):
            self.state.destinations[dest].append(b"".join(self.state.char_buf))

        # handle the case where we might have been building a datetime
        if len(self.state.datetime_parts):
            year = self.state.datetime_parts.get("year", 0)
            month = self.state.datetime_parts.get("month", 0)
            day = self.state.datetime_parts.get("day", 0)
            hour = self.state.datetime_parts.get("hour", 0)
            minute = self.state.datetime_parts.get("minute", 0)
            second = self.state.datetime_parts.get("second", 0)
            if dest not in self.destinations:
                self.destinations[dest] = []
            if year and month and day:
                d = datetime.datetime(year, month, day, hour, minute, second)
            else:
                d = datetime.datetime.fromordinal(1)
            self.destinations[dest].append(d)

        # merge with document destination content
        for dest, content in self.state.destinations.items():
            if dest not in self.destinations:
                self.destinations[dest] = []
            self.destinations[dest].extend(content)

    def change_dest(self, dest):
        """Save current destination and change to dest."""
        # save off current buffer to current destination then clear it
        if self.state.rds not in self.state.destinations:
            self.state.destinations[self.state.rds] = []
        self.state.destinations[self.state.rds].append(b"".join(self.state.char_buf))

        debug("changing dest (%s) to %s" % (self.state.rds, dest))
        self.state.rds = dest

    def parse_char(self, c):
        """Accumulate the char."""
        if type(c) is not bytes:
            raise Exception("Unexpected char type: %s" % type(c))

        if self.state.ris == risBin and (self.cbBin - 1) <= 0:
            self.state.ris = risNorm

        self.state.char_buf.append(c)

    def apply_prop_change(self, prop, val):
        """Apply the specified property value."""
        if self.state.rds == rdsSkip:
            return
        if properties[prop].prop == propDop:
            pb = self.state.dop
        elif properties[prop].prop == propSep:
            pb = self.state.sep
        elif properties[prop].prop == propPap:
            pb = self.state.pap
        elif properties[prop].prop == propChp:
            pb = self.state.chp
        elif properties[prop].prop == propDateTime:
            pb = self.state.datetime_parts
        elif properties[prop].prop == propInfoGroup:
            pb = self.info_group
        else:
            if properties[prop].actn != actnSpec:
                raise RtfParserError(ecBadTable, msg="properties[prop].actn=%s" % properties[prop].actn)

        if properties[prop].actn == actnByte:
            field = properties[prop].offset[1]
            pb[field] = val
        elif properties[prop].actn == actnWord:
            field = properties[prop].offset[1]
            pb[field] = val
        elif properties[prop].actn == actnSpec:
            self.parse_special_property(prop, val)

    def parse_special_property(self, iprop, val):
        """Parse the specified property value."""
        if iprop == ipropPard:
            self.state.pap = dict()
        elif iprop == ipropPlain:
            self.state.pap = dict()
        elif iprop == ipropSectd:
            self.state.pap = dict()
        else:
            raise RtfParserError(ecBadTable, msg="iprop=%s" % iprop)

    def parse_special_keyword(self, ipfn):
        """Parse the specified keyword."""
        # if we're skipping and it is not the \bin keyword
        if self.state.rds == rdsSkip and ipfn != ipfnBin:
            return  # ecOK

        if ipfn == ipfnBin:
            self.state.ris = risBin
            self.cbBin = self.lParam
        elif ipfn == ipfnSkipDest:
            debug("---- skipping destination!")
            self.fSkipDestIfUnk = True
        elif ipfn == ipfnHex:
            self.state.ris = risHex
        else:
            raise RtfParserError(ecBadTable)

    def translate_keyword(self, keyword, param, fParam):
        """Translate the specified keyword."""
        cw = CONTROL_WORD_TABLE.get(keyword, None)
        if cw is None:
            # keyword not found
            debug("---- kw %s not found!" % keyword)

            if self.fSkipDestIfUnk:
                # this is an unknown destination and we've been told to skip it
                # set the destination to "skip".
                # note that the 'else' to this is to continue using the current
                # destination.
                self.state.rds = rdsSkip

            # regardless, we have now 'correctly' processed this unknown
            # destination. set fSkipDestIfUnk to False (ie. wait for another \*).
            self.fSkipDestIfUnk = False
            return
        else:
            # found the keyword - use kwd and idx to determine what to do with it
            debug("---- kw %s (%s), %s, %d" % (keyword, param, fParam, cw.role))
            self.fSkipDestIfUnk = False
            if cw.role == kwdProp:
                if cw.always_use_default or not fParam:
                    param = cw.default
                self.apply_prop_change(cw.index, param)
            elif cw.role == kwdChar:
                self.parse_char(cw.index)
            elif cw.role == kwdDest:
                self.change_dest(cw.index)
            elif cw.role == kwdSpec:
                self.parse_special_keyword(cw.index)
            else:
                raise RtfParserError(ecBadTable)

    def parse_rtf_keyword(self, buf, offset):
        """Parse the keyword at the given offset."""
        fParam = False
        fNeg = False
        param = 0
        keyword = []
        parameter = []

        max_keyword_len = 30 + 1
        max_param_len = 20 + 1

        if offset + 1 == len(buf):
            raise RtfParserError(ecEndOfFile)

        # move beyond the '\\' char
        i = offset + 1
        # grab next char as a byte string
        c = buf[i : i + 1]

        if not c.isalpha():
            # a control symbol; no delimiter
            keyword.append(c)
            self.translate_keyword(b"".join(keyword), 0, fParam)
            return i

        while len(keyword) < max_keyword_len and i + 1 < len(buf):
            if c.isalpha():
                keyword.append(c)
                i += 1
                c = buf[i : i + 1]
            else:
                break

        debug("parse_rtf_keyword[0x%02x]: keyword '%s' (broke on 0x%02x)" % (offset, b"".join(keyword), ord(c)))

        if len(keyword) > max_keyword_len:
            raise RtfParserError(ecInvalidKeyword, msg="offset=%d" % i)

        if c == b"-":
            fNeg = True
            if (i + 1) >= len(buf):
                raise RtfParserError(ecEndOfFile, msg="offset=%d" % i)

        if c.isdigit():
            # a digit after the control means we have a parameter

            fParam = True
            while len(parameter) < max_param_len and c.isdigit() and i + 1 < len(buf):
                parameter.append(c)
                i += 1
                c = buf[i : i + 1]

            if len(b"".join(parameter)) >= max_param_len:
                raise RtfParserError(ecInvalidParam, msg="parameter=%s" % b"".join(parameter))

            param = int(b"".join(parameter))
            debug("param: %d" % param)

            if fNeg:
                param = -param

        if c != b" ":
            i -= 1

        # build keyword histogram
        if b"".join(keyword) not in self.keywords:
            self.keywords[b"".join(keyword)] = 0
        self.keywords[b"".join(keyword)] += 1

        self.translate_keyword(b"".join(keyword), param, fParam)
        return i

    # look at page 38-40 all apart from \info and \datetimes
    def parse(self):
        """Parse the current RTF buffer."""
        # ch = c in python speak
        cNibble = 2
        b = 0

        # loop through our buffer
        i = 0
        while i < len(self.buf):
            # debug("%x" % i)
            c = self.buf[i : i + 1]

            # rough approximation of slace
            if self.hit_sane_end_of_file:
                self.slack.append(c)
                i += 1
                continue

            if self.group_depth < 0:
                raise RtfParserError(ecStackUnderflow, msg="offset=%x" % i)

            # if we're handling binary data, handle it directly
            if self.state.ris == risBin:
                self.parse_char(c)
            else:
                if c == b"{":
                    debug("depth=%02d @ %x" % (self.group_depth, i))
                    self.push_state()
                elif c == b"}":
                    debug("depth=%02d @ %x" % (self.group_depth, i))
                    try:
                        self.pop_state()
                    except RtfParserError:
                        raise
                elif c == b"\\":
                    i = self.parse_rtf_keyword(self.buf, i)
                elif c == b"\r":
                    i += 1
                    continue
                elif c == b"\n":
                    i += 1
                    continue
                else:
                    if self.state.ris == risNorm:
                        self.parse_char(c)
                    else:
                        debug("parsing hex data?")
                        # parsing hex data
                        if self.state.ris != risHex:
                            debug("unknown state (%s) not norm or hex!" % self.state.ris)
                            raise (RtfParserError(ecAssertion))
                        b = b << 4
                        if c.isdigit():
                            # treat b as int.
                            b += ord(c) - ord("0")
                        else:
                            if c.islower():
                                if ord(c) < ord("a") or ord(c) > ord("f"):
                                    msg = "char=%s; offset=%x" % (c, i)
                                    raise RtfParserError(ecInvalidHex, msg=msg)
                                b += ord(c) - ord("a") + 10
                            else:
                                if ord(c) < ord("A") or ord(c) > ord("F"):
                                    msg = "char=%s; offset=%x" % (c, i)
                                    raise RtfParserError(ecInvalidHex, msg=msg)
                                b += ord(c) - ord("A") + 10
                        b &= 0xFF
                        cNibble -= 1
                        if not cNibble:
                            self.parse_char(bytes([b]))
                            cNibble = 2
                            b = 0
                            self.state.ris = risNorm

            # keep our index movin'
            i += 1
        if self.group_depth < 0:
            raise RtfParserError(ecStackUnderflow, msg="offset=%x" % i)
        if self.group_depth > 0:
            raise RtfParserError(ecUnmatchedBrace, msg="offset=%x" % i)

        # fix up slack
        self.slack = b"".join(self.slack)


def main(filepath):
    """Parse the RTF given by filepath and print extracted info."""
    buf = open(filepath, "rb").read()
    rtf_parser = RtfParser(buf)
    print(rtf_parser.info_group)


if __name__ == "__main__":
    main(sys.argv[1])
