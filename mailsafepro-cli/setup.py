from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mailsafepro-cli",
    version="1.0.0",
    author="MailSafePro",
    author_email="support@mailsafepro.com",
    description="Command-line interface for MailSafePro email validation API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mailsafepro/mailsafepro-cli",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Communications :: Email",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "httpx>=0.24.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "mailsafepro=mailsafepro.cli:cli",
        ],
    },
)
