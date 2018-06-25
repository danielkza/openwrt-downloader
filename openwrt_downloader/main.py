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

from scrapy import Field, Item, Request, Spider
from scrapy import logformatter
from scrapy.crawler import CrawlerProcess
from scrapy.exceptions import DropItem
from scrapy.pipelines.files import FileException, FilesPipeline
from scrapy.settings import Settings
from scrapy.utils.request import referer_str
import twisted.web.http as http
from twisted.internet import defer
from twisted.python.failure import Failure


OPENWRT_DEFAULT_BASE_URL = 'https://downloads.openwrt.org/releases'

logger = logging.getLogger(__name__)


class Image(Item):
    url = Field()
    version = Field()
    build = Field()
    target = Field()
    device = Field()
    filesystem = Field()
    type = Field()
    format = Field()
    sha256 = Field()

    PREFIX_RE = r'(?:openwrt|lede)'
    VERSION_RE = r'(?P<version>(?:\d+\.?)+(?:-rc\d+)?)(?:-(?P<build>.+?))?'
    DEVICE_RE = r'(?P<device>.+?)'
    FILESYSTEM_RE = r'(?P<filesystem>[^-]+)'
    IMAGE_TYPE_RE = r'(?P<type>[^-]+)'
    FORMAT_RE = r'(?P<format>bin|img)'

    @classmethod
    def image_re(cls, target):
        fmt = ('{prefix}-{version}-{target}-{device}-{filesystem}-'
               '{type}\\.{format}')
        target = re.escape(target.replace('/', '-'))
        return fmt.format(prefix=cls.PREFIX_RE, version=cls.VERSION_RE,
                          target=target, device=cls.DEVICE_RE,
                          filesystem=cls.FILESYSTEM_RE, type=cls.IMAGE_TYPE_RE,
                          format=cls.FORMAT_RE)

    @classmethod
    def from_url(cls, url, target):
        image_match = re.search(cls.image_re(target), url)
        if not image_match:
            return None

        return Image(url=url, target=target, **image_match.groupdict())


class OpenWrtSpider(Spider):
    SHA256SUM_RE = re.compile(r'^[0-9a-zA-Z]{64}$')

    name = 'openwrt'

    @classmethod
    def from_crawler(cls, crawler, *args, **kwargs):
        return super(OpenWrtSpider, cls).from_crawler(
            crawler, *args, settings=crawler.settings, **kwargs)

    def __init__(self, **kwargs):
        super(OpenWrtSpider, self).__init__(**kwargs)

        settings = kwargs['settings']
        self.base_url = settings['OPENWRT_BASE_URL'] + '/'
        self.version = settings.get('OPENWRT_VERSION')
        self.device = settings.get('OPENWRT_DEVICE')
        self.target = settings.get('OPENWRT_TARGET')
        self.image_type = settings.get('OPENWRT_IMAGE_TYPE')
        self.index_file = settings.get('OPENWRT_INDEX_FILE')

    def load_index(self, response):
        assert self.index_file

        if self.index_file == '-':
            f = sys.stdin
        else:
            f = open(self.index_file, 'rb')

        try:
            for item in json.load(f):
                yield Image(**item)
        finally:
            self.index_file = None
            if f is not sys.stdin:
                f.close()

    def start_requests(self):
        if self.index_file:
            # Make a simple head request to the base URL, but ignore the result
            # and just generate the cached index images as a response.
            yield Request(self.base_url, self.load_index, method='HEAD')
            return

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

            image['sha256'] = csum
            yield image


def sha256sum(buf):
    m = sha256()
    while True:
        d = buf.read(8096)
        if not d:
            break
        m.update(d)
    return m.hexdigest()


class OpenWrtDownloaderPipeline(FilesPipeline):
    def __init__(self, *args, **kwargs):
        super(OpenWrtDownloaderPipeline, self).__init__(*args, **kwargs)

        settings = kwargs['settings']
        self.version = settings.get('OPENWRT_VERSION')
        self.device = settings.get('OPENWRT_DEVICE')
        self.target = settings.get('OPENWRT_TARGET')
        self.image_type = settings.get('OPENWRT_IMAGE_TYPE')

    def process_item(self, item, spider):
        if not isinstance(item, Image):
            raise DropItem("Not an OpenWRT image")

        if self.version and item['version'] != self.version \
                or self.target and item['target'] != self.target \
                or self.device and item['device'] != self.device \
                or self.image_type and item['type'] != self.image_type:
            raise DropItem("Rejected by OpenWRT filters")

        process_item = super(OpenWrtDownloaderPipeline, self).process_item
        return process_item(item, spider)

    def get_media_requests(self, item, info):
        meta = {
            'sha256': item['sha256'],
            'openwrt_version': item['version'],
            'openwrt_target': item['target']
        }
        yield Request(item['url'], meta=meta)

    def file_path(self, request, response=None, info=None):
        version = request.meta['openwrt_version']
        target = request.meta['openwrt_target']
        fname = request.url.split('/')[-1]
        return '/'.join([version, target, fname])

    def _check_media_fresh(self, response):
        if response.status == 304:
            return True
        elif response.status == 200:
            # The media stores don't set the mtime of the stored files to the
            # value of the Last-Modified headers, and some web servers (e.g
            # nginx) only return 304s if the time matches exactly. Check the
            # time manually when we see a 200 to work around that.
            try:
                request_time = response.meta['media_last_modified']
                response_time = http.stringToDatetime(
                    response.headers['Last-Modified'])
            except KeyError:
                return False

            return request_time >= response_time

    def _handle_download_head(self, response, request, info):
        if isinstance(response, Failure):
            logger.warn('Conditional HTTP request %s failed: %s', request,
                        response)
            return None

        if self._check_media_fresh(response):
            logger.debug('Current copy is up-to-date, skipping download: %s',
                         request.url)
            return response.meta['media_stat']

        return None

    def _check_download_condition(self, request, info, media_stat,
                                  last_modified):
        head_request = request.replace(method='HEAD')
        head_request.meta['media_stat'] = media_stat
        head_request.meta['media_last_modified'] = last_modified
        head_request.headers['If-Modified-Since'] = \
            http.datetimeToString(last_modified)

        dfd = self.crawler.engine.download(head_request, info.spider)
        dfd.addBoth(self._handle_download_head, head_request, info)
        return dfd

    def _handle_download_stat(self, result, request, info, path):
        if not result:
            return  # returning None force download

        last_modified = result.get('last_modified', None)
        if not last_modified:
            return  # returning None force download

        checksum = result.get('checksum', None)
        media_stat = {'url': request.url, 'path': path, 'checksum': checksum}
        return self._check_download_condition(request, info, media_stat,
                                              last_modified)

    def media_to_download(self, request, info):
        path = self.file_path(request, info=info)
        dfd = defer.maybeDeferred(self.store.stat_file, path, info)
        dfd.addBoth(self._handle_download_stat, request, info, path)
        return dfd

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


class PoliteLogFormatter(logformatter.LogFormatter):
    def dropped(self, item, exception, response, spider):
        return {
            'level': logging.DEBUG,
            'msg': logformatter.DROPPEDMSG,
            'args': {
                'exception': exception,
                'item': item,
            }
        }


def crawl(args):
    settings = dict(
        OPENWRT_BASE_URL=args.base_url,
        OPENWRT_VERSION=args.openwrt_version,
        OPENWRT_TARGET=args.target,
        OPENWRT_DEVICE=args.device,
        OPENWRT_IMAGE_TYPE=args.image_type,
        LOG_FORMATTER=__name__ + '.PoliteLogFormatter'
    )
    tmp_fd = tmp_path = None

    if args.command == 'download':
        settings.update(
            OPENWRT_INDEX_FILE=args.index_file,
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
        process.crawl(OpenWrtSpider)
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
        '-i', '--index-file', default=None,
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
