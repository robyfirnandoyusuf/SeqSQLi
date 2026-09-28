#!/usr/bin/env python3
"""Build an editable CISC-style DOCX from the Korean Markdown draft.

This intentionally uses only the Python standard library so the draft can be
regenerated without installing document-generation packages.
"""

from __future__ import annotations

import re
import zipfile
import argparse
from html import escape
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "SeqSQLi_CISC-W26_conference_draft_ko.md"
OUTPUT = ROOT / "docs" / "SeqSQLi_CISC-W26_conference_draft_ko.docx"
CISC_TEMPLATE = False

NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def clean_inline(text: str) -> str:
    text = re.sub(r"!\[[^]]*]\([^)]+\)", "", text)
    text = re.sub(r"\[([^]]+)]\([^)]+\)", r"\1", text)
    text = text.replace("**", "").replace("`", "")
    text = text.replace("\\(", "").replace("\\)", "")
    return text.strip()


def run(text: str, *, size: int = 18, bold: bool = False,
        font: str = "휴먼명조", italic: bool = False) -> str:
    props = [
        f'<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" '
        f'w:eastAsia="{escape(font)}"/>',
        f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>',
    ]
    if bold:
        props.append("<w:b/><w:bCs/>")
    if italic:
        props.append("<w:i/><w:iCs/>")
    return (
        "<w:r><w:rPr>" + "".join(props) + "</w:rPr>"
        f'<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'
    )


def paragraph(text: str = "", *, align: str = "both", size: int = 18,
              bold: bool = False, before: int = 0, after: int = 80,
              line: int = 300, first_line: int = 180,
              keep_next: bool = False, font: str = "휴먼명조") -> str:
    if CISC_TEMPLATE and size == 18:
        size = 19
        line = max(line, 310)
    keep = "<w:keepNext/>" if keep_next else ""
    if first_line > 0:
        indent = f'<w:ind w:firstLine="{first_line}"/>'
    elif first_line < 0:
        indent = f'<w:ind w:hanging="{-first_line}"/>'
    else:
        indent = ""
    ppr = (
        f"<w:pPr>{keep}<w:jc w:val=\"{align}\"/>"
        f'<w:spacing w:before="{before}" w:after="{after}" '
        f'w:line="{line}" w:lineRule="auto"/>{indent}</w:pPr>'
    )
    return f"<w:p>{ppr}{run(clean_inline(text), size=size, bold=bold, font=font)}</w:p>"


def heading(text: str, level: int) -> str:
    if level == 2:
        return paragraph(text, align="left", size=21, bold=True, before=180,
                         after=70, line=260, first_line=0, keep_next=True)
    return paragraph(text, align="left", size=19, bold=True, before=120,
                     after=50, line=250, first_line=0, keep_next=True)


def table(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    ncols = max(len(row) for row in rows)
    width = 4620
    cell_width = max(500, width // ncols)
    out = [
        "<w:tbl><w:tblPr><w:tblW w:w=\"4620\" w:type=\"dxa\"/>"
        "<w:tblLayout w:type=\"fixed\"/><w:tblBorders>"
        "<w:top w:val=\"single\" w:sz=\"6\" w:color=\"000000\"/>"
        "<w:left w:val=\"nil\"/><w:bottom w:val=\"single\" w:sz=\"6\" w:color=\"000000\"/>"
        "<w:right w:val=\"nil\"/><w:insideH w:val=\"single\" w:sz=\"3\" w:color=\"808080\"/>"
        "<w:insideV w:val=\"nil\"/></w:tblBorders>"
        "<w:tblCellMar><w:top w:w=\"30\" w:type=\"dxa\"/><w:left w:w=\"40\" w:type=\"dxa\"/>"
        "<w:bottom w:w=\"30\" w:type=\"dxa\"/><w:right w:w=\"40\" w:type=\"dxa\"/>"
        "</w:tblCellMar></w:tblPr>"
    ]
    for ridx, row in enumerate(rows):
        out.append("<w:tr>")
        for value in row:
            out.append(
                f'<w:tc><w:tcPr><w:tcW w:w="{cell_width}" w:type="dxa"/></w:tcPr>'
                f'<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:before="0" '
                f'w:after="0" w:line="220" w:lineRule="auto"/></w:pPr>'
                f'{run(clean_inline(value), size=(17 if CISC_TEMPLATE else 15), bold=(ridx == 0), font="휴먼명조")}'
                "</w:p></w:tc>"
            )
        out.append("</w:tr>")
    out.append("</w:tbl>")
    return "".join(out)


def image_paragraph(rid: str, name: str, width_emu: int, height_emu: int) -> str:
    return f'''<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:before="40" w:after="30"/></w:pPr>
    <w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"
      xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">
      <wp:extent cx="{width_emu}" cy="{height_emu}"/><wp:docPr id="1" name="{escape(name)}"/>
      <a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
        <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
          <pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
            <pic:nvPicPr><pic:cNvPr id="0" name="{escape(name)}"/><pic:cNvPicPr/></pic:nvPicPr>
            <pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>
            <pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{width_emu}" cy="{height_emu}"/></a:xfrm>
              <a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>
          </pic:pic>
        </a:graphicData>
      </a:graphic>
    </wp:inline></w:drawing></w:r></w:p>'''


def state_equation() -> str:
    """Return the state definition as a native, editable Word equation."""
    return '''<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:before="60" w:after="60"/></w:pPr>
    <m:oMathPara><m:oMathParaPr><m:jc m:val="center"/></m:oMathParaPr><m:oMath>
      <m:sSub><m:e><m:r><m:t>s</m:t></m:r></m:e><m:sub><m:r><m:t>t</m:t></m:r></m:sub></m:sSub>
      <m:r><m:t xml:space="preserve"> = [φ(</m:t></m:r>
      <m:sSub><m:e><m:r><m:t>p</m:t></m:r></m:e><m:sub><m:r><m:t>t</m:t></m:r></m:sub></m:sSub>
      <m:r><m:t xml:space="preserve">) ‖ ι ‖ onehot(</m:t></m:r>
      <m:sSub><m:e><m:r><m:t>a</m:t></m:r></m:e><m:sub><m:r><m:t>t−1</m:t></m:r></m:sub></m:sSub>
      <m:r><m:t xml:space="preserve">) ‖ </m:t></m:r>
      <m:f><m:num><m:r><m:t>t</m:t></m:r></m:num><m:den><m:r><m:t>T</m:t></m:r></m:den></m:f>
      <m:r><m:t xml:space="preserve">] ∈ </m:t></m:r>
      <m:sSup><m:e><m:r><m:t>ℝ</m:t></m:r></m:e><m:sup><m:r><m:t>67</m:t></m:r></m:sup></m:sSup>
    </m:oMath></m:oMathPara></w:p>'''


def one_column_break() -> str:
    if CISC_TEMPLATE:
        return '''<w:p><w:pPr><w:spacing w:before="80"/><w:sectPr>
          <w:pgSz w:w="11907" w:h="16840"/>
          <w:pgMar w:top="1134" w:right="1587" w:bottom="1134" w:left="1587" w:header="567" w:footer="340" w:gutter="0"/>
          <w:cols w:num="1"/>
        </w:sectPr></w:pPr></w:p>'''
    return '''<w:p><w:pPr><w:sectPr>
      <w:pgSz w:w="10772" w:h="14740"/>
      <w:pgMar w:top="992" w:right="1134" w:bottom="992" w:left="1134" w:header="567" w:footer="340" w:gutter="0"/>
      <w:cols w:num="1"/>
    </w:sectPr></w:pPr></w:p>'''


def final_section() -> str:
    if CISC_TEMPLATE:
        return '''<w:sectPr>
          <w:type w:val="continuous"/>
          <w:pgSz w:w="11907" w:h="16840"/>
          <w:pgMar w:top="1134" w:right="1587" w:bottom="1134" w:left="1587" w:header="567" w:footer="340" w:gutter="0"/>
          <w:cols w:num="2" w:space="340"/>
          <w:docGrid w:linePitch="310"/>
        </w:sectPr>'''
    return '''<w:sectPr>
      <w:type w:val="continuous"/>
      <w:pgSz w:w="10772" w:h="14740"/>
      <w:pgMar w:top="992" w:right="1134" w:bottom="992" w:left="1134" w:header="567" w:footer="340" w:gutter="0"/>
      <w:cols w:num="2" w:space="340"/>
      <w:docGrid w:linePitch="300"/>
    </w:sectPr>'''


def build_document(source: str) -> tuple[str, list[Path]]:
    lines = source.splitlines()
    body: list[str] = []
    images: list[Path] = []
    i = 0
    first_h1_seen = False
    while i < len(lines):
        raw = lines[i].rstrip()
        stripped = raw.strip()
        if stripped == "---":
            break
        if not stripped:
            i += 1
            continue

        if stripped.startswith("!["):
            match = re.match(r"!\[([^]]*)]\(([^)]+)\)", stripped)
            if match:
                path = (SOURCE.parent / match.group(2)).resolve()
                images.append(path)
                # The source figure is wide; fit it to one text column.
                body.append(image_paragraph(f"rIdImage{len(images)}", path.name,
                                            2_430_000, 1_240_000))
            i += 1
            continue

        if stripped.startswith("|"):
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
                    rows.append(cells)
                i += 1
            body.append(table(rows))
            continue

        if stripped.startswith("$$") and "\\frac{t}{T}" in stripped:
            body.append(state_equation())
            i += 1
            continue

        if stripped.startswith("# "):
            body.append(paragraph(stripped[2:], align="center", size=34, bold=True,
                                  before=(750 if CISC_TEMPLATE else 0),
                                  after=140, line=360, first_line=0))
        elif stripped.startswith("## "):
            title = stripped[3:]
            if re.match(r"(?:\d+\.|[IVX]+\.) ", title) and not first_h1_seen:
                body.append(one_column_break())
                first_h1_seen = True
            if title in ("요약", "Abstract"):
                body.append(paragraph(title, align="center", size=20, bold=True,
                                      before=120, after=80, line=250,
                                      first_line=0, keep_next=True))
            else:
                body.append(heading(title, 2))
        elif stripped.startswith("### "):
            body.append(heading(stripped[4:], 3))
        elif (stripped.startswith("**Sequential SQL") or
              stripped.startswith("**SeqSQLi:")):
            body.append(paragraph(stripped, align="center", size=28, bold=True,
                                  before=0, after=130, line=320, first_line=0))
        elif stripped.startswith("**주제어:") or stripped.startswith("**Keywords:"):
            body.append(paragraph(stripped, align="left", size=17, before=40,
                                  after=80, line=250, first_line=0))
        elif (stripped.startswith("**그림") or stripped.startswith("**표") or
              stripped.startswith("**Figure") or stripped.startswith("**Table")):
            body.append(paragraph(stripped, align="center", size=16, bold=True,
                                  before=30, after=60, line=220, first_line=0))
        elif ("전북대학교 소프트웨어공학과" in stripped or
              "Department of Software Engineering" in stripped or
              stripped == "Jeonbuk National University"):
            body.append(paragraph(stripped, align="center",
                                  size=(22 if CISC_TEMPLATE else 18),
                                  bold=CISC_TEMPLATE, before=0,
                                  after=(260 if CISC_TEMPLATE else 60),
                                  line=260, first_line=0))
        elif stripped.startswith("로비 피르난도"):
            body.append(paragraph(stripped, align="center", size=22, bold=True,
                                  before=0, after=30, line=260, first_line=0,
                                  font="돋움"))
        elif stripped.startswith("Roby Firnando"):
            body.append(paragraph(stripped, align="center", size=22, bold=True,
                                  before=0, after=45, line=260, first_line=0,
                                  font="Arial"))
        elif stripped.startswith("[") and re.match(r"\[\d+]", stripped):
            body.append(paragraph(stripped, align="left",
                                  size=(19 if CISC_TEMPLATE else 15), before=0,
                                  after=(80 if CISC_TEMPLATE else 35),
                                  line=(280 if CISC_TEMPLATE else 220),
                                  first_line=(-300 if CISC_TEMPLATE else -180)))
        else:
            body.append(paragraph(stripped))
        i += 1

    body.append(final_section())
    document = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="{NS_W}" xmlns:r="{NS_R}"
 xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
 xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
 xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"
 xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math"
><w:body>{''.join(body)}</w:body></w:document>'''
    return document, images


def build_docx() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    document, images = build_document(source)
    title_match = re.search(r"^# (.+)$", source, re.MULTILINE)
    document_title = title_match.group(1) if title_match else "SeqSQLi conference draft"
    rels = [
        '<Relationship Id="rIdStyles" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    ]
    for idx, image in enumerate(images, 1):
        rels.append(
            f'<Relationship Id="rIdImage{idx}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
            f'Target="media/{escape(image.name)}"/>'
        )
    doc_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(rels) + "</Relationships>"
    )
    package_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
 <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>'''
    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
 <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
 <Default Extension="xml" ContentType="application/xml"/>
 <Default Extension="png" ContentType="image/png"/>
 <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
 <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
 <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>'''
    styles = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="{NS_W}">
 <w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="휴먼명조"/><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr></w:rPrDefault>
 <w:pPrDefault><w:pPr><w:spacing w:after="80" w:line="300" w:lineRule="auto"/><w:jc w:val="both"/></w:pPr></w:pPrDefault></w:docDefaults>
 <w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
</w:styles>'''
    core = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <dc:title>''' + escape(document_title) + '''</dc:title>
 <dc:creator>Roby Firnando Yusuf; Abhishek Chaudhary; Sunoh Choi</dc:creator>
 <dc:subject>CISC-W'26 conference draft</dc:subject>
 <dc:description>Professor-review draft generated from the SeqSQLi manuscript.</dc:description>
</cp:coreProperties>'''

    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", package_rels)
        archive.writestr("docProps/core.xml", core)
        archive.writestr("word/document.xml", document)
        archive.writestr("word/styles.xml", styles)
        archive.writestr("word/_rels/document.xml.rels", doc_rels)
        for image in images:
            archive.write(image, f"word/media/{image.name}")
    print(OUTPUT)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--cisc-template", action="store_true")
    args = parser.parse_args()
    SOURCE = args.source.resolve()
    OUTPUT = args.output.resolve()
    CISC_TEMPLATE = args.cisc_template
    build_docx()
