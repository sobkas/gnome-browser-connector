# GNOME Shell browser connector
## Introduction

This repository contains OS-native connector counterpart for [GNOME Shell browser extension](https://gitlab.gnome.org/GNOME/chrome-gnome-shell).

## Build and install

First you need to install build requirements:
- meson
- python3
- pygobject

Then invoke meson to build and install connector:
```shell
    meson --prefix=/usr builddir
    cd builddir
    meson install
```
