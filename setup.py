from setuptools import setup, find_packages

setup(
    name="backup_tool",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "schedule"
    ],
    entry_points={
        "console_scripts": [
            "backup_tool = backup_tool.main:main"
        ]
    },
)
