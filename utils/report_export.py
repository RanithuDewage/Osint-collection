from pathlib import Path

from utils.formatter import format_osint_report


def save_txt(report, directory="reports"):
    output_dir = Path(directory)
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    target = report.get(
        "target",
        "target",
    )

    safe_target = target.replace(
        "/",
        "_",
    )

    output = (
        output_dir
        / f"{safe_target}_osint_report.txt"
    )

    output.write_text(
        format_osint_report(report),
        encoding="utf-8",
    )

    return output


def save_pdf(report, directory="reports"):
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
    )
    from reportlab.lib.styles import (
        getSampleStyleSheet,
    )

    output_dir = Path(directory)
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    target = report.get(
        "target",
        "target",
    )

    safe_target = target.replace(
        "/",
        "_",
    )

    output = (
        output_dir
        / f"{safe_target}_osint_report.pdf"
    )

    document = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    story = []

    for line in format_osint_report(
        report
    ).splitlines():

        if not line:
            story.append(
                Spacer(1, 5)
            )
            continue

        escaped = (
            line
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

        if "OSINT REPORT" in line:
            story.append(
                Paragraph(
                    f"<b>{escaped}</b>",
                    styles["Title"],
                )
            )

        elif (
            line.startswith("[ ")
            and line.endswith(" ]")
        ):
            story.append(
                Paragraph(
                    f"<b>{escaped}</b>",
                    styles["Heading2"],
                )
            )

        else:
            story.append(
                Paragraph(
                    escaped,
                    styles["BodyText"],
                )
            )

    document.build(story)

    return output
