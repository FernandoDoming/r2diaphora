import os
import shutil
import glob

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
        for f in glob.glob(f"{sigs_dir}/*.sig"):
            shutil.copy2(
                f,
                os.path.join(os.path.expanduser("~"), ".r2diaphora", "signatures", "flirt")
            )

setup(
    name="r2diaphora",
    version="0.1.11",
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
        "python_magic>=0.4.24",
        "pycparser>=2.21"
    ],

    classifiers=[
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8"
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