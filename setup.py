import os
from distutils.dir_util import copy_tree

from setuptools import setup
from setuptools.command.install import install

class CustomInstall(install):

    def run(self):
        install.run(self)
        self.__post_install()

    def __post_install(self):
        for path in [
            [".r2diaphora"],
            [".r2diaphora", "signatures"],
            [".r2diaphora", "signatures", "flirt"]
        ]:
            try:
                os.makedirs(
                    os.path.join(
                        os.path.expanduser("~"), *path
                    )
                )
            except FileExistsError:
                pass

        dirname  = os.path.dirname(__file__)
        sigs_dir = os.path.join(dirname, "r2diaphora", "signatures", "flirt")
        for _, dirs, _ in os.walk(sigs_dir):
            for d in dirs:
                dir_path = os.path.join(sigs_dir, d)
                copy_tree(
                    dir_path,
                    os.path.join(os.path.expanduser("~"), ".r2diaphora", "signatures", "flirt", d)
                )

setup(
    name="r2diaphora",
    version="0.3.2",
    description="radare2 port of diaphora",
    url="https://github.com/FernandoDoming/r2diaphora",
    author="Fernando Domínguez",
    author_email="fernando.dom.del@gmail.com",
    license="GNU GPL v3",
    packages=[
        "r2diaphora",
        "r2diaphora.idaapi",
        "r2diaphora.jkutils",
        "r2diaphora.others",
    ],
    install_requires=[
        "chardet>=4.0.0",
        "r2pipe>=1.6.3",
        "colorama>=0.4.4",
        "yattag>=1.14.0",
        "mysql-connector-python>=8.0.26",
        "python-magic>=0.4.27",
    ],

    classifiers=[
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],

    entry_points = {
        "console_scripts": ["r2diaphora=r2diaphora.diaphora_r2:main"]
    },

    scripts=[
        "scripts/r2diaphora-bulk",
        "scripts/r2diaphora-db"
    ],

    include_package_data=True,
    cmdclass={"install": CustomInstall}
)