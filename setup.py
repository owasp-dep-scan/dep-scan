import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="appthreat-depscan",
    version="3.2.2",
    author="Team AppThreat",
    author_email="cloud@appthreat.com",
    description="Fully open-source security audit for project dependencies based on known vulnerabilities and advisories.",
    entry_points={
        "console_scripts": ["scan=depscan.cli:main", "depscan=depscan.cli:main"]
    },
    license="MIT",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/appthreat/dep-scan",
    packages=["depscan", "depscan.lib", "vendor"],
    include_package_data=True,
    install_requires=[
        "appthreat-vulnerability-db",
        "defusedxml",
        "PyYAML",
        "rich",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Utilities",
        "Topic :: Security",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
