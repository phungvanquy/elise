#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Retired entry point retained for release archive compatibility."""
import sys

# Earlier Elise installers require this file in every release archive.
# Installing this stub also replaces the old migration implementation.
if __name__ == '__main__':
    sys.exit('Elise automatic migration has been removed. Set up nodes with '
             'elisectl add; no configuration or state has been changed.')
