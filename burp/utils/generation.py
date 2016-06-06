from html.parser import HTMLParser

import requests
from typing import Generator, Optional
from typing import List
from typing import Tuple

from burp.models.enums import IssueSeverity


class _IssueTypeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.got_main_content = False
        self.got_row = False
        self.td_count = 0

        self.name = None  # type: Optional[str]
        self.severity = None  # type: Optional[str]
        self.issues = set()  # type: Set[Tuple[str, IssueSeverity, int]]

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]) -> None:
        if tag == 'div' and ('id', 'MainContent') in attrs:
            self.got_main_content = True

        if self.got_main_content and tag == 'tr':
            self.got_row = True

        if self.got_row and tag == 'td':
            self.td_count += 1

    def handle_endtag(self, tag: str) -> None:
        if self.got_main_content and tag == 'div':
            self.got_main_content = False

        if self.got_row and tag == 'tr':
            self.got_row = False

        if tag == 'tr':
            self.td_count = 0

    @staticmethod
    def __sanitize_data(data: str) -> Optional[str]:
        data = data.strip()
        if data == '':
            return None
        return data

    def handle_data(self, data: str) -> None:
        data = self.__sanitize_data(data)
        if data is None:
            return

        if self.td_count == 1:
            self.name = data
        elif self.td_count == 2:
            self.severity = data
        elif self.td_count == 3:
            index = int(data, base=16)
            severity = IssueSeverity(self.severity)
            self.issues.add((self.name, severity, index))


def _str_to_enum_ident(name: str) -> str:
    return name.upper(). \
        replace(' ', '_'). \
        replace('-', '_'). \
        replace('(', '').replace(')', ''). \
        replace('.', '')


def _get_issue_type() -> List[Tuple[str, IssueSeverity, int]]:
    response = requests.get('https://portswigger.net/KnowledgeBase/Issues/')
    parser = _IssueTypeParser()
    parser.feed(response.text)

    issues = list(parser.issues)
    issues.sort()

    return issues


def _gen_issue_type() -> Generator[str, None, None]:
    yield 'class IssueType(Enum):'

    for name, severity, index in _get_issue_type():
        ident = _str_to_enum_ident(name)
        severity_name = 'IssueSeverity.{}'.format(severity.name)
        yield '    {} = ({}, {!r})'.format(ident, severity_name, index)

    yield ''
    yield '    def __init__(self, severity: IssueSeverity, index: int):'
    yield '        self.severity = severity'
    yield '        self.index = index'


def gen_issue_type() -> str:
    return '\n'.join(_gen_issue_type())


if __name__ == '__main__':
    print(gen_issue_type())
