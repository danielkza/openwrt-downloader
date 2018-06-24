# OpenWRT Downloader

Download OpenWrt firmware images programatically


## Installation

Run `pip install git+https://github.com/danielkza/openwrt-downloader.git`, or
`pip install -e .` from inside the repository.


## Usage

```
usage: openwrt-downloader [-h] [--openwrt-version OPENWRT_VERSION]
                          [--target TARGET] [--device DEVICE]
                          [--image-type IMAGE_TYPE] [--base-url BASE_URL] -i
                          INDEX_FILE
                          {index,download} ...

positional arguments:
  {index,download}
    index               Index image information from the OpenWRT website
    download            Download images to a chosen directory

optional arguments:
  -h, --help            show this help message and exit
  --openwrt-version OPENWRT_VERSION
                        OpenWrt version to look for
  --target TARGET       OpenWrt target to look for. Optional, but can speed up
                        crawling. Can be specified as just the architecture
                        (the first part of the target name, before the slash),
                        or an "[arch]/[target]" pair.
  --device DEVICE       OpenWrt device to look for. This name must be the
                        exact same string used to name the firmware files. For
                        example, for a firmware file named
                        "openwrt-18.06.0-rc1-ar71xx-generic-tl-wdr4300-v1
                        -squashfs-sysupgrade.bin", the device name is "tl-
                        wdr4300-v1"
  --image-type IMAGE_TYPE
                        OpenWrt image type to look for. This is usually
                        "sysupgrade", "factory", "rootfs", etc.
  --base-url BASE_URL   Base URL to crawl, without a trailing slash
  -i INDEX_FILE, --index-file INDEX_FILE
                        File to load/store indexing results. Use "-" for
                        stdout.
```

## Examples

Index *all* images for OpenWRT/LEDE 17.01.4:

```sh
openwrt-downloader \
  --index-file openwrt-17.01.4-all.json \
  --openwrt-version 17.01.4 \
  index
```

Index all `ar71xx/generic` images for all OpenWRT versions.

```sh
openwrt-downloader \
  --index-file openwrt-all-ar71xx.json \
  --target ar71xx/generic \
  index
```

Index all images for the `Linksys WRT1900ACS` device, accounting for the fact
it moved targets in OpenWRT 18.01 (by specifying a partial target):

```sh
openwrt-downloader \
  --index-file openwrt-all-linksys-wrt1900-acs.json \
  --target mvebu \
  --device linksys-wrt1900-acs \
  index
```

Download *all* images for OpenWRT/LEDE 17.01.4 to `./openwrt` using the
previously created index file:

```sh
openwrt-downloader \
  --index-file openwrt-17.01.4-all.json \
  download \
  --download-dir ./openwrt
```

Download *all* images for OpenWRT/LEDE 17.01.4 to `./openwrt` without an index
file:

```sh
openwrt-downloader \
  --openwrt-version 17.01.4 \
  download \
  --download-dir ./openwrt
```

# License (MIT)

See the included `LICENSE` file.
