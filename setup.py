from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="kaido-waf",
    version="2.1.0",
    author="Gustavo",
    author_email="gustavo@kaido.team",
    description="Web Application Firewall do Kaido Red Team",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/KaidoTeam/kaido-waf",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            "kaido-waf=kaido_waf.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Operating System :: OS Independent",
    ],
)
