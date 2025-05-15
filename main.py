
import requests
import re
import json
import hashlib
import base64
import time
import datetime
import os
import sys
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Any, Tuple
import argparse

# Set up logging and error handling for Mac
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('pcsi')

# PCSI Core Classes
class SExpression:
    @staticmethod
    def create_string(s: str) -> str:
        """Create a canonical S-expression string with length prefix."""
        if s is None or s == "":
            return ""
        return f"{len(s)}:{s}"
    
    @staticmethod
    def create_object(name: str, content: str = "") -> str:
        """Create an S-expression object."""
        if not content:
            return ""
        name_expr = SExpression.create_string(name)
        return f"({name_expr}{content})"
    
    @staticmethod
    def hash_sexp(sexp: str) -> str:
        """Create a base64-encoded SHA-256 hash of an S-expression."""
        hash_obj = hashlib.sha256(sexp.encode('utf-8'))
        return base64.b64encode(hash_obj.digest()).decode('utf-8')

@dataclass
class ContentObject:
    """Base class for structured content objects."""
    type: str
    
    def to_sexp(self) -> str:
        """Convert object to canonical S-expression format."""
        raise NotImplementedError
    
    def hash(self) -> str:
        """Generate a hash of the S-expression representation."""
        return SExpression.hash_sexp(self.to_sexp())

@dataclass
class Link:
    url: str
    
    def to_sexp(self) -> str:
        url_expr = SExpression.create_object("url", SExpression.create_string(self.url))
        return SExpression.create_object("link", url_expr)

@dataclass
class Paragraph:
    content: List[Union[str, Link]] = field(default_factory=list)
    
    def to_sexp(self) -> str:
        """Convert paragraph and its content to S-expression format."""
        content_expr = ""
        for item in self.content:
            if isinstance(item, str):
                content_expr += SExpression.create_string(item)
            else:  # Link
                content_expr += item.to_sexp()
        return SExpression.create_object("paragraph", content_expr)

@dataclass
class Subheading:
    text: str
    
    def to_sexp(self) -> str:
        return SExpression.create_object("subheading", SExpression.create_string(self.text))

@dataclass
class Image:
    url: str
    caption: str = ""
    
    def to_sexp(self) -> str:
        url_expr = SExpression.create_object("url", SExpression.create_string(self.url))
        caption_expr = SExpression.create_object("caption", SExpression.create_string(self.caption))
        return SExpression.create_object("image", url_expr + caption_expr)

@dataclass
class ArticleBody:
    elements: List[Union[Paragraph, Subheading, Image]] = field(default_factory=list)
    
    def to_sexp(self) -> str:
        content_expr = ""
        for element in self.elements:
            content_expr += element.to_sexp()
        return SExpression.create_object("body", content_expr)

@dataclass
class Article(ContentObject):
    headline: str
    date: int  # Unix timestamp
    author: str
    body: ArticleBody
    
    def __init__(self, headline: str, date: int, author: str, body: ArticleBody):
        super().__init__(type="article")
        self.headline = headline
        self.date = date
        self.author = author
        self.body = body
    
    def to_sexp(self) -> str:
        headline_expr = SExpression.create_object("headline", SExpression.create_string(self.headline))
        date_expr = SExpression.create_object("date", SExpression.create_string(str(self.date)))
        author_expr = SExpression.create_object("author", SExpression.create_string(self.author))
        body_expr = self.body.to_sexp()
        
        content = headline_expr + date_expr + author_expr + body_expr
        return SExpression.create_object("article", content)

@dataclass
class PCSIRecord:
    """Base class for PCSI records."""
    source: str
    timestamp: int
    
    def to_sexp(self) -> str:
        """Convert record to canonical S-expression format."""
        raise NotImplementedError

@dataclass
class Rule(PCSIRecord):
    pattern: str
    script_hash: str
    object_type: str
    script: Optional[str] = None
    
    def to_sexp(self) -> str:
        source_expr = SExpression.create_object("source", f"|{self.source}|")
        timestamp_expr = SExpression.create_object("timestamp", SExpression.create_string(str(self.timestamp)))
        pattern_expr = SExpression.create_object("pattern", SExpression.create_string(self.pattern))
        script_hash_expr = SExpression.create_object("script-hash", f"|{self.script_hash}|")
        object_type_expr = SExpression.create_object("object-type", SExpression.create_string(self.object_type))
        
        content = source_expr + timestamp_expr + pattern_expr + script_hash_expr + object_type_expr
        if self.script:
            script_expr = SExpression.create_object("script", SExpression.create_string(self.script))
            content += script_expr
            
        return SExpression.create_object("rule", content)

@dataclass
class Inference(PCSIRecord):
    url: str
    script_hash: str
    object_type: Optional[str] = None
    object_hash: Optional[str] = None
    error: Optional[str] = None
    script: Optional[str] = None
    object: Optional[str] = None
    
    def to_sexp(self) -> str:
        source_expr = SExpression.create_object("source", f"|{self.source}|")
        timestamp_expr = SExpression.create_object("timestamp", SExpression.create_string(str(self.timestamp)))
        url_expr = SExpression.create_object("url", SExpression.create_string(self.url))
        script_hash_expr = SExpression.create_object("script-hash", f"|{self.script_hash}|")
        
        content = source_expr + timestamp_expr + url_expr + script_hash_expr
        
        if self.error:
            error_expr = SExpression.create_object("error", SExpression.create_string(self.error))
            content += error_expr
        else:
            object_type_expr = SExpression.create_object("object-type", SExpression.create_string(self.object_type))
            object_hash_expr = SExpression.create_object("object-hash", f"|{self.object_hash}|")
            content += object_type_expr + object_hash_expr
            
        if self.script:
            script_expr = SExpression.create_object("script", SExpression.create_string(self.script))
            content += script_expr
            
        if self.object:
            object_expr = SExpression.create_object("object", self.object)
            content += object_expr
            
        return SExpression.create_object("inference", content)

@dataclass
class Perception(PCSIRecord):
    url: str
    object_type: str
    object_hash: str
    valid: bool
    
    def to_sexp(self) -> str:
        source_expr = SExpression.create_object("source", f"|{self.source}|")
        timestamp_expr = SExpression.create_object("timestamp", SExpression.create_string(str(self.timestamp)))
        url_expr = SExpression.create_object("url", SExpression.create_string(self.url))
        object_type_expr = SExpression.create_object("object-type", SExpression.create_string(self.object_type))
        object_hash_expr = SExpression.create_object("object-hash", f"|{self.object_hash}|")
        valid_expr = SExpression.create_object("valid", SExpression.create_string("1" if self.valid else "0"))
        
        content = source_expr + timestamp_expr + url_expr + object_type_expr + object_hash_expr + valid_expr
        return SExpression.create_object("perception", content)

# HTML Processing Script - Equivalent to the Hex script in the paper
class BBCArticleExtractor:
    """Extract structured content from BBC news articles."""
    
    def __init__(self):
        self.user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
        
    def _parse_date(self, date_str: str) -> int:
        """Convert date string to Unix timestamp."""
        try:
            dt = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return int(dt.timestamp())
        except (ValueError, TypeError):
            logger.warning(f"Failed to parse date string: {date_str}")
            return int(time.time())  # Fallback to current time
    
    def _extract_text_with_links(self, element) -> Paragraph:
        """Extract text and links from an element."""
        paragraph = Paragraph()
        
        # If the element has no children or is just text, add it as a string
        if not element.contents:
            if element.string and element.string.strip():
                paragraph.content.append(element.string.strip())
            return paragraph
            
        current_text = ""
        for child in element.contents:
            if child.name == 'a' and child.get('href'):
                # Add accumulated text before the link
                if current_text:
                    paragraph.content.append(current_text)
                    current_text = ""
                
                # Add the link
                url = child.get('href')
                if not url.startswith('http'):
                    if url.startswith('/'):
                        url = f"https://www.bbc.com{url}"
                    else:
                        url = f"https://www.bbc.com/{url}"
                
                paragraph.content.append(Link(url))
                
                # Add link text
                if child.text:
                    current_text += child.text
            elif isinstance(child, str):
                current_text += child
            else:
                # Recursive extraction for nested elements
                if child.name != 'br':  # Skip line breaks
                    if child.text:
                        current_text += child.text
        
        # Add any remaining text
        if current_text:
            paragraph.content.append(current_text)
            
        return paragraph
    
    def _extract_image(self, figure_element) -> Optional[Image]:
        """Extract image URL and caption from a figure element."""
        img_element = figure_element.find('img')
        if not img_element:
            return None
            
        url = img_element.get('src', '')
        if not url:
            # Try data-src as fallback
            url = img_element.get('data-src', '')
            
        if not url:
            return None
            
        caption = ""
        figcaption = figure_element.find('figcaption')
        if figcaption:
            caption = figcaption.text.strip()
            
        return Image(url=url, caption=caption)
    
    def extract(self, url: str) -> Article:
        """Extract article content from BBC URL."""
        logger.info(f"Extracting content from {url}")
        headers = {'User-Agent': self.user_agent}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch URL: {url} - {str(e)}")
            raise ValueError(f"Failed to fetch URL: {str(e)}")
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract headline
        headline_elem = soup.find('h1')
        if not headline_elem:
            logger.error("Missing headline element")
            raise ValueError("Missing headline element")
        headline = headline_elem.text.strip()
        logger.info(f"Found headline: {headline}")
        
        # Extract date and author from JSON-LD
        date = int(time.time())  # Default to current time
        author = "BBC News"  # Default author
        
        script_element = soup.find('script', {'type': 'application/ld+json'})
        if script_element:
            try:
                json_data = json.loads(script_element.string)
                if 'datePublished' in json_data:
                    date = self._parse_date(json_data['datePublished'])
                
                if 'author' in json_data:
                    if isinstance(json_data['author'], list) and len(json_data['author']) > 0:
                        if 'name' in json_data['author'][0]:
                            author = json_data['author'][0]['name']
                    elif isinstance(json_data['author'], dict) and 'name' in json_data['author']:
                        author = json_data['author']['name']
                    logger.info(f"Found author: {author}")
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(f"Error parsing JSON-LD data: {str(e)}")
        
        # Extract body content
        body = ArticleBody()
        
        # Main content selector varies across BBC articles, try different patterns
        main_content = soup.select_one('main#main-content article') or soup.select_one('article') or soup.select_one('main')
        
        if not main_content:
            logger.error("Could not locate main content")
            raise ValueError("Could not locate main content")
            
        # Process paragraphs, subheadings, and images
        for element in main_content.find_all(['p', 'h2', 'figure']):
            if element.name == 'p' and element.text.strip():
                paragraph = self._extract_text_with_links(element)
                if paragraph.content:
                    body.elements.append(paragraph)
                    
            elif element.name == 'h2' and element.text.strip():
                body.elements.append(Subheading(element.text.strip()))
                
            elif element.name == 'figure':
                image = self._extract_image(element)
                if image:
                    body.elements.append(image)
        
        logger.info(f"Extracted {len(body.elements)} body elements")
        return Article(headline=headline, date=date, author=author, body=body)

# PCSI System Implementation
class PCSISystem:
    def __init__(self, source_id: str = None):
        """Initialize the PCSI system with a source identifier."""
        if source_id:
            self.source_id = source_id
        else:
            # Generate a random source ID if none provided
            self.source_id = base64.b64encode(hashlib.sha256(str(time.time()).encode()).digest()).decode()
            
        self.rules = []
        self.inferences = []
        self.perceptions = []
        self.extractors = {
            'bbc_article': BBCArticleExtractor()
        }
        logger.info(f"PCSI System initialized with source ID: {self.source_id[:8]}...")
    
    def add_rule(self, pattern: str, script_hash: str, object_type: str, script: str = None) -> Rule:
        """Add a rule to the system."""
        rule = Rule(
            source=self.source_id,
            timestamp=int(time.time()),
            pattern=pattern,
            script_hash=script_hash,
            object_type=object_type,
            script=script
        )
        self.rules.append(rule)
        logger.info(f"Added rule for pattern: {pattern}")
        return rule
    
    def find_matching_rule(self, url: str) -> Optional[Rule]:
        """Find a rule matching the given URL."""
        for rule in self.rules:
            if re.match(rule.pattern, url):
                logger.info(f"Found matching rule for {url}")
                return rule
        logger.info(f"No matching rule found for {url}")
        return None
    
    def process_url(self, url: str) -> Tuple[Optional[ContentObject], Optional[Inference]]:
        """Process a URL and generate a structured content object and inference record."""
        rule = self.find_matching_rule(url)
        if not rule:
            # Updated pattern to match more BBC article URL formats
            if 'bbc.com' in url and ('/news/' in url or '/sport/' in url):
                # Create a default rule for BBC articles
                extractor = self.extractors['bbc_article']
                script_hash = "CY7Iwrrw5i7MyjV7Zqdwf2Tj0Hb3iCsJF4Sv6jcrUyw="  # Placeholder hash
                rule = self.add_rule(
                    pattern=r"https?://(www\.)?bbc\.com/.*",
                    script_hash=script_hash,
                    object_type="article"
                )
            else:
                logger.warning(f"No rule available for URL: {url}")
                return None, None
        
        # Start creating an inference record
        inference = Inference(
            source=self.source_id,
            timestamp=int(time.time()),
            url=url,
            script_hash=rule.script_hash
        )
        
        try:
            # Use the appropriate extractor
            extractor = self.extractors['bbc_article']
            content_object = extractor.extract(url)
            
            # Complete the inference record
            inference.object_type = rule.object_type
            inference.object_hash = content_object.hash()
            
            # Store the inference
            self.inferences.append(inference)
            
            return content_object, inference
                
        except Exception as e:
            # Record the error in the inference
            logger.error(f"Error extracting content: {str(e)}")
            inference.error = str(e)
            self.inferences.append(inference)
        
        return None, inference
    
    def add_perception(self, url: str, object_type: str, object_hash: str, valid: bool) -> Perception:
        """Add a perception record about content validity."""
        perception = Perception(
            source=self.source_id,
            timestamp=int(time.time()),
            url=url,
            object_type=object_type,
            object_hash=object_hash,
            valid=valid
        )
        self.perceptions.append(perception)
        logger.info(f"Added perception for {url}: valid={valid}")
        return perception
    
    def export_records(self, filename: str):
        """Export all records to a file."""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Export rules
                for rule in self.rules:
                    f.write(rule.to_sexp() + '\n')
                
                # Export inferences
                for inference in self.inferences:
                    f.write(inference.to_sexp() + '\n')
                
                # Export perceptions
                for perception in self.perceptions:
                    f.write(perception.to_sexp() + '\n')
            logger.info(f"Exported {len(self.rules)} rules, {len(self.inferences)} inferences, and {len(self.perceptions)} perceptions to {filename}")
        except IOError as e:
            logger.error(f"Failed to export records: {str(e)}")
    
    def save_article_content(self, article: Article, output_dir: str = "extracted_articles"):
        """Save article content to a readable text file."""
        try:
            os.makedirs(output_dir, exist_ok=True)
            filename = f"{output_dir}/{article.date}_{article.headline[:30].replace(' ', '_')}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Title: {article.headline}\n")
                f.write(f"Author: {article.author}\n")
                f.write(f"Date: {datetime.datetime.fromtimestamp(article.date).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for element in article.body.elements:
                    if isinstance(element, Paragraph):
                        paragraph_text = ""
                        for item in element.content:
                            if isinstance(item, str):
                                paragraph_text += item
                            elif isinstance(item, Link):
                                paragraph_text += f"[LINK: {item.url}]"
                        f.write(f"{paragraph_text}\n\n")
                    elif isinstance(element, Subheading):
                        f.write(f"\n## {element.text}\n\n")
                    elif isinstance(element, Image):
                        f.write(f"[IMAGE: {element.url}]\n")
                        if element.caption:
                            f.write(f"Caption: {element.caption}\n\n")
            
            logger.info(f"Saved article content to {filename}")
            return filename
        except Exception as e:
            logger.error(f"Failed to save article content: {str(e)}")
            return None

# Main function to demonstrate the PCSI system
def main():
    # Configure argparse with nice help text for macOS Terminal 
    parser = argparse.ArgumentParser(
        description='PCSI: Platform for Content-Structure Inference',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--urls', nargs='+', help='URLs to process')
    parser.add_argument('--export', type=str, default='pcsi_records.txt', help='Export records to file')
    parser.add_argument('--verbose', action='store_true', help='Print verbose output')
    parser.add_argument('--save-content', action='store_true', help='Save article content to text files')
    parser.add_argument('--output-dir', type=str, default='extracted_articles', help='Directory to save extracted articles')
    
    args = parser.parse_args()
    
    # Set logging level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    # Initialize the PCSI system
    pcsi = PCSISystem()
    
    # Updated URLs to more current BBC articles
    urls = args.urls if args.urls else [
        "https://www.bbc.com/news/articles/c8e6wj07xlno",
    ]
    
    successful = 0
    failed = 0
    saved_files = []
    
    # Process each URL
    print("\n📰 PCSI BBC Article Extraction")
    print("==============================\n")
    
    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] Processing {url}...")
        content_object, inference = pcsi.process_url(url)
        
        if content_object:
            successful += 1
            print(f"✅ Successfully extracted: {content_object.headline}")
            
            # Print the S-expression output in the requested format
            print("\n✅ PCSI S-expression output:\n")
            print(content_object.to_sexp())
            print("\n")
            
            # Save article content if requested
            if args.save_content:
                filename = pcsi.save_article_content(content_object, args.output_dir)
                if filename:
                    saved_files.append(filename)
            
            if args.verbose:
                print(f"  - Author: {content_object.author}")
                print(f"  - Date: {datetime.datetime.fromtimestamp(content_object.date).strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"  - Body elements: {len(content_object.body.elements)}")
                print(f"  - Hash: {content_object.hash()}")
                
            # Add a positive perception
            pcsi.add_perception(
                url=url,
                object_type=content_object.type,
                object_hash=content_object.hash(),
                valid=True
            )
        else:
            failed += 1
            print(f"❌ Failed to extract content from {url}")
            if inference and inference.error:
                print(f"  Error: {inference.error}")
    
    # Export records
    pcsi.export_records(args.export)
    print(f"\n📝 Exported PCSI records to {args.export}")
    
    # Print summary
    print("\n📊 Summary:")
    print(f"  - Total URLs processed: {len(urls)}")
    print(f"  - Successfully extracted: {successful}")
    print(f"  - Failed: {failed}")
    
    if args.save_content and saved_files:
        print(f"  - Saved {len(saved_files)} articles to {args.output_dir}/")
        if args.verbose:
            for f in saved_files:
                print(f"    - {os.path.basename(f)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Process interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)