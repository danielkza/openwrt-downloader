from setuptools import setup

VERSION = '0.1.0'

setup(
    name='openwrt-downloader',
    packages=['openwrt_downloader'],
    version=VERSION,
    description='Download OpenWrt firmware images programatically',
    long_description=open('README.md').read(),
    url='https://github.com/danielkza/openwrt-downloader',
    download_url='https://github.com/danielkza/openwrt-downloader/archive/{}.tar.gz'.format(VERSION),
    author='Daniel Miranda',
    author_email='danielkza2@gmail.com',
    license='MIT',
    install_requires=[
        'scrapy'
    ],
    entry_points={
        'console_scripts': ['openwrt-downloader=openwrt_downloader.main:main']
    },
    keywords='openwrt lede firmware download scrapy')
