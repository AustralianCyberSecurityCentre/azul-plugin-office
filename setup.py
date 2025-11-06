#!/usr/bin/env python3
"""Setup script."""
import os

from setuptools import setup


def open_file(fname):
    """Open and return a file-like object for the relative filename."""
    return open(os.path.join(os.path.dirname(__file__), fname))


setup(
    name="azul-plugin-office",
    description="Parse and feature Microsoft Office files using third-party tools and libraries.",
    author="Azul",
    author_email="azul@asd.gov.au",
    url="https://www.asd.gov.au/",
    packages=["azul_plugin_office"],
    include_package_data=True,
    python_requires=">=3.12",
    classifiers=[],
    entry_points={
        "console_scripts": [
            "azul-plugin-dde = azul_plugin_office.plugin_dde:main",
            "azul-plugin-officedecrypt = azul_plugin_office.plugin_crypto:main",
            "azul-plugin-oleinfo = azul_plugin_office.plugin_oleinfo:main",
            "azul-plugin-openxmlinfo = azul_plugin_office.plugin_xmlinfo:main",
            "azul-plugin-macros = azul_plugin_office.plugin_macros:main",
            "azul-plugin-mimeinfo= azul_plugin_office.plugin_mimeinfo:main",
            "azul-plugin-rtfinfo = azul_plugin_office.plugin_rtfmeta:main",
            "azul-plugin-sylk = azul_plugin_office.plugin_sylk:main",
        ]
    },
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    install_requires=[r.strip() for r in open_file("requirements.txt") if not r.startswith("#")],
)
