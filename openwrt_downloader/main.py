#!/bin/env python

from __future__ import print_function, unicode_literals

import argparse
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from functools import partial
from hashlib import sha256
from io import BytesIO
try:
    from urllib.parse import urljoin, urlsplit
except ImportError:
    from urlparse import urljoin, urlsplit

import scrapy.signals
from scrapy import Field, Item, Request, Spider
from scrapy.crawler import CrawlerProcess
from scrapy.exceptions import DropItem
from scrapy.pipelines.files import FileException, FilesPipeline
from scrapy.settings import Settings
from scrapy.utils.request import referer_str

OPENWRT_DEFAULT_BASE_URL = 'https://downloads.openwrt.org/releases'

logger = logging.getLogger(__name__)


class Image(Item):
    url = Field()
    version = Field()
    target = Field()
    device = Field()
    filesystem = Field()
    type = Field()
    format = Field()
    sha256 = Field()

    IMAGE_RE = (
        r'(openwrt|lede)-(?P<version>.+?)-{target}-'
        r'(?P<device>.+?)-(?P<filesystem>[^-]+)-(?P<type>[^-]+)\.'
        r'(?P<format>bin|img)$')

    @classmethod
    def from_url(cls, url, target):
        url_target = re.escape(target.replace('/', '-'))
        image_re = cls.IMAGE_RE.format(target=url_target)
        image_match = re.search(image_re, url)
        if not image_match:
            return None

        return Image(url=url, target=target, **image_match.groupdict())


class OpenWrtSpider(Spider):
    SHA256SUM_RE = re.compile(r'^[0-9a-zA-Z]{64}$')

    name = 'openwrt'

    def __init__(self, base_url, version=None, device=None, target=None,
                 image_type=None, **kwargs):
        self.base_url = base_url + '/'
        self.version = version
        self.device = device
        self.target = target
        self.image_type = image_type

        super(OpenWrtSpider, self).__init__(**kwargs)

    def start_requests(self):
        if self.version:
            targets_url = '{}{}/targets/{}'.format(
                self.base_url, self.version, self.target or '')

            if self.target and '/' in self.target:
                yield Request(targets_url, self.parse_images)
            else:
                yield Request(targets_url, self.parse_targets)
        else:
            yield Request(self.base_url, self.parse_versions)

    def _find_links(self, response):
        for link in response.css('a::attr(href)').extract():
            url = response.urljoin(link)
            if not url.startswith(self.base_url):
                continue

            yield urlsplit(url)

    def _follow_targets(self, response, path):
        try:
            _, target = path.split('/targets', 1)
            target = target.strip('/')
        except ValueError:
            return

        if '/' in target:
            yield response.follow(
                url=response.urljoin(path + '/sha256sums'),
                callback=partial(self.parse_images, target))
        else:
            yield response.follow(
                url=response.urljoin(path),
                callback=self.parse_targets)

    def parse_versions(self, response):
        for link in self._find_links(response):
            try:
                _, version = link.path.split('/releases/')
            except ValueError:
                continue

            if not version or version.startswith('packages'):
                continue

            next_path = urljoin(
                link.path, 'targets/{}'.format(self.target or ''))
            for r in self._follow_targets(response, next_path):
                yield r

    def parse_targets(self, response):
        for link in self._find_links(response):
            try:
                _, target = link.path.split('/targets/')
            except ValueError:
                continue

            if not target:
                continue

            if self.target and not target.startswith(self.target):
                continue

            for r in self._follow_targets(response, link.path):
                yield r

    def parse_images(self, target, response):
        for line in response.body.splitlines():
            csum, fname = line.split(None, 1)
            fname = fname.lstrip('*')

            url = response.urljoin(fname)
            image = Image.from_url(url, target=target)

            if not image:
                continue

            if self.device and image['device'] != self.device \
                    or self.image_type and image['type'] != self.image_type:
                continue

            image['sha256'] = csum
            yield image


class PreloadedSpider(Spider):
    name = 'openwrt-preloaded'

    @classmethod
    def from_crawler(cls, crawler, *args, **kwargs):
        from_crawler = super(PreloadedSpider, cls).from_crawler
        spider = from_crawler(crawler, *args, **kwargs)
        crawler.signals.connect(spider.idle, signal=scrapy.signals.spider_idle)
        return spider

    def __init__(self, items, **kwargs):
        self.items = items
        super(PreloadedSpider, self).__init__(**kwargs)

    def idle(self):
        if self.items:
            itemproc = self.crawler.engine.scraper.itemproc
            for item in self.items:
                logger.debug('Manually processing item: %s', item)
                itemproc.process_item(item, self)

            self.items = None


def sha256sum(buf):
    m = sha256()
    while True:
        d = buf.read(8096)
        if not d:
            break
        m.update(d)
    return m.hexdigest()


class OpenWrtDownloaderPipeline(FilesPipeline):
    def get_media_requests(self, item, info):
        meta = {'sha256': item['sha256']}
        yield Request(item['url'], meta=meta)

    def file_path(self, request, response=None, info=None):
        return request.url.split('/')[-1]

    def file_downloaded(self, response, request, info):
        expected_csum = request.meta.get('sha256')
        if expected_csum:
            response_csum = sha256sum(BytesIO(response.body))

            logger.debug('Request %s SHA256: expected %s, actual %s',
                         request, expected_csum, response_csum)

            if expected_csum != response_csum:
                logger.warning(
                    'File (checksum-mismatch): Error downloading %s '
                    'from %s referred in <%s>: expected SHA256 digest %s, '
                    'got %s',
                    self.MEDIA_NAME, request, referer_str(request),
                    expected_csum, response_csum,
                    extra={'spider': info.spider})

                raise FileException('checksum-mismatch')

        return super(OpenWrtDownloaderPipeline, self).file_downloaded(
            response, request, info)

    def item_completed(self, results, item, info):
        ok, result = results[0]
        if not ok:
            raise DropItem("Download failed: {}".format(result))

        return item


def load_index(path):
    if path == '-':
        f = sys.stdin
    else:
        f = open(path, 'rb')

    try:
        data = json.load(f)
        return [Image(**item) for item in data]
    finally:
        if f is not sys.stdin:
            f.close()


def crawl(args):
    settings = {}
    index_items = None
    tmp_fd = tmp_path = None

    if args.command == 'download':
        if args.index_file:
            index_items = list(load_index(args.index_file))
            logger.debug('Loaded index entries: %s', index_items)

        settings.update(
            ITEM_PIPELINES={__name__ + '.OpenWrtDownloaderPipeline': 1},
            FILES_STORE=os.path.abspath(args.download_dir),
            MEDIA_ALLOW_REDIRECTS=True)
    elif args.command == 'index':
        assert args.index_file
        if args.index_file == '-':
            feed_uri = 'stdout:'
        else:
            # Write to a temporary file, since Scrapy always appends when using
            # the JSON exporter, but we want a clean file every time.
            tmp_fd, tmp_path = tempfile.mkstemp('.json')
            feed_uri = 'file://' + tmp_path

        settings.update(FEED_URI=feed_uri, FEED_FORMAT='json')

    try:
        process = CrawlerProcess(settings=Settings(values=settings),
                                 install_root_handler=False)
        logging.getLogger('scrapy').setLevel(logging.INFO)

        if index_items:
            process.crawl(PreloadedSpider, items=index_items)
        else:
            process.crawl(
                OpenWrtSpider,
                base_url=args.base_url, version=args.openwrt_version,
                target=args.target, device=args.device,
                image_type=args.image_type)
        process.start()

        if tmp_path:
            shutil.move(tmp_path, os.path.abspath(args.index_file))
            tmp_path = None
    finally:
        if tmp_fd:
            os.close(tmp_fd)
        if tmp_path:
            os.remove(tmp_path)


def main():
    logging.basicConfig(level=logging.DEBUG)

    argp = argparse.ArgumentParser()
    argp.add_argument(
        '--openwrt-version',
        help='OpenWrt version to look for')
    argp.add_argument(
        '--target', default=None,
        help='OpenWrt target to look for. Optional, but can speed up '
             'crawling. Can be specified as just the architecture (the first '
             'part of the target name, before the slash), or an '
             '"[arch]/[target]" pair.')
    argp.add_argument(
        '--device',
        help='OpenWrt device to look for. This name must be the exact same '
             'string used to name the firmware files. For example, for a '
             'firmware file named "openwrt-18.06.0-rc1-ar71xx-generic-tl-'
             'wdr4300-v1-squashfs-sysupgrade.bin", the device name is '
             '"tl-wdr4300-v1"')
    argp.add_argument(
        '--image-type', default=None,
        help='OpenWrt image type to look for. This is usually "sysupgrade", '
             '"factory", "rootfs", etc.')
    argp.add_argument(
        '--base-url', default=OPENWRT_DEFAULT_BASE_URL,
        help='Base URL to crawl, without a trailing slash')
    argp.add_argument(
        '-i', '--index-file', required=True,
        help='File to load/store indexing results. Use "-" for stdout.')

    cmds = argp.add_subparsers()
    index_cmd = cmds.add_parser(
        'index',
        help='Index image information from the OpenWRT website')
    index_cmd.set_defaults(command='index')

    dl_cmd = cmds.add_parser(
        'download',
        help='Download images to a chosen directory')
    dl_cmd.set_defaults(command='download')
    dl_cmd.add_argument(
        '-d', '--download_dir', required=True,
        help='Directory to download images to.')

    args = argp.parse_args()
    if args.command == 'index' and not args.index_file:
        argp.error('must specify --index-file with index command')

    crawl(args)


if __name__ == '__main__':
    main()
