#!/bin/sh

set -e

virtualenv -p `which python3` pyve
pyve/bin/pip install flake8
pyve/bin/flake8 *.py
