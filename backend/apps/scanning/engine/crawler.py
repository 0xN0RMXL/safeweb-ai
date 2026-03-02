"""
WebCrawler — Discovers pages, forms, inputs, and links on a target website.
Uses BFS crawling with configurable depth limits.
"""
import logging
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass, field
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Respect rate limiting — delay between requests (seconds)
CRAWL_DELAY = 0.5


@dataclass
class FormInput:
    """Represents an HTML form input field."""
    name: str
    input_type: str
    value: str = ''


@dataclass
class Form:
    """Represents an HTML form."""
    action: str
    method: str
    inputs: list = field(default_factory=list)


@dataclass
class Page:
    """Represents a crawled web page."""
    url: str
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    body: str = ''
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    parameters: dict = field(default_factory=dict)


class WebCrawler:
    """BFS web crawler for vulnerability scanning."""

    DEPTH_LIMITS = {'shallow': 10, 'medium': 50, 'deep': 200}

    def __init__(self, base_url: str, depth: str = 'medium',
                 follow_redirects: bool = True, include_subdomains: bool = False):
        self.base_url = base_url.rstrip('/')
        self.max_pages = self.DEPTH_LIMITS.get(depth, 50)
        self.follow_redirects = follow_redirects
        self.include_subdomains = include_subdomains
        self.visited = set()
        self.pages = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SafeWeb AI Scanner/1.0 (Security Assessment Tool)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        self.session.verify = False  # Allow self-signed certs for scanning
        self.parsed_base = urlparse(self.base_url)

    def crawl(self) -> list:
        """BFS crawl starting from base_url. Returns list of Page objects."""
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        queue = [self.base_url]
        self.visited.add(self.base_url)

        while queue and len(self.pages) < self.max_pages:
            url = queue.pop(0)

            try:
                page = self._fetch_page(url)
                if page:
                    self.pages.append(page)

                    # Add discovered links to queue
                    for link in page.links:
                        if link not in self.visited and len(self.pages) < self.max_pages:
                            if self._is_in_scope(link):
                                self.visited.add(link)
                                queue.append(link)

                # Rate limiting
                time.sleep(CRAWL_DELAY)

            except Exception as e:
                logger.warning(f'Failed to crawl {url}: {e}')

        logger.info(f'Crawl complete: {len(self.pages)} pages discovered')
        return self.pages

    def _fetch_page(self, url: str) -> 'Page | None':
        """Fetch a single page and extract its components."""
        try:
            response = self.session.get(
                url,
                allow_redirects=self.follow_redirects,
                timeout=15,
            )

            page = Page(
                url=url,
                status_code=response.status_code,
                headers=dict(response.headers),
                cookies=dict(response.cookies),
                body=response.text[:100000],  # Limit body size
            )

            # Parse URL parameters
            parsed = urlparse(url)
            page.parameters = parse_qs(parsed.query)

            # Parse HTML for forms and links
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'lxml')
                page.forms = self._extract_forms(soup, url)
                page.links = self._extract_links(soup, url)

            return page

        except requests.exceptions.Timeout:
            logger.warning(f'Timeout fetching {url}')
            return None
        except requests.exceptions.ConnectionError:
            logger.warning(f'Connection error for {url}')
            return None
        except Exception as e:
            logger.warning(f'Error fetching {url}: {e}')
            return None

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> list:
        """Extract all forms from the page."""
        forms = []
        for form_tag in soup.find_all('form'):
            action = form_tag.get('action', '')
            if action:
                action = urljoin(base_url, str(action))
            else:
                action = base_url

            method = str(form_tag.get('method', 'GET')).upper()

            inputs = []
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name', '')
                if name:
                    inputs.append(FormInput(
                        name=name,
                        input_type=input_tag.get('type', 'text'),
                        value=input_tag.get('value', ''),
                    ))

            forms.append(Form(action=action, method=method, inputs=inputs))

        return forms

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> list:
        """Extract all unique links from the page."""
        links = set()
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            # Skip anchors, javascript, mailto, tel
            if href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue

            full_url = urljoin(base_url, href)
            # Remove fragment
            full_url = full_url.split('#')[0]

            if self._is_in_scope(full_url):
                links.add(full_url)

        return list(links)

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within the scanning scope."""
        try:
            parsed = urlparse(url)

            # Must be HTTP/HTTPS
            if parsed.scheme not in ('http', 'https'):
                return False

            # Check domain scope
            if self.include_subdomains:
                return parsed.netloc.endswith(self.parsed_base.netloc)
            else:
                return parsed.netloc == self.parsed_base.netloc

        except Exception:
            return False
