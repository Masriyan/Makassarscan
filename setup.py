#!/usr/bin/env python3
"""
MakassarScan - Advanced Vulnerability Assessment & Reconnaissance Toolkit

Setup script for pip installation.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="makassarscan",
    version="2.0.0",
    author="Masriyan",
    author_email="masriyan@security-life.org",
    description="Advanced Vulnerability Assessment & Reconnaissance Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Masriyan/Makassarscan",
    project_urls={
        "Bug Tracker": "https://github.com/Masriyan/Makassarscan/issues",
        "Documentation": "https://github.com/Masriyan/Makassarscan#readme",
        "Source Code": "https://github.com/Masriyan/Makassarscan",
    },
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Environment :: X11 Applications :: GTK",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
    ],
    keywords=[
        "security",
        "vulnerability",
        "scanner",
        "reconnaissance",
        "pentesting",
        "cve",
        "port-scanner",
        "subdomain",
        "web-crawler",
        "osint",
    ],
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "dns": ["dnspython>=2.4.0"],
        "image": ["Pillow>=10.0.0"],
        "full": [
            "dnspython>=2.4.0",
            "Pillow>=10.0.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "black>=23.0.0",
        ],
    },
    py_modules=["app"],
    entry_points={
        "console_scripts": [
            "makassarscan=app:cli_main",
        ],
        "gui_scripts": [
            "makassarscan-gui=app:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
