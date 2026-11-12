import os
import shutil

from setuptools import setup
from setuptools.command.install import install


class CustomInstall(install):

    def run(self):
        install.run(self)
        self.__post_install()

    def __post_install(self):
        for path in [
            [".r2diaphora"],
            [".r2diaphora", "dbs"],
            [".r2diaphora", "signatures"],
            [".r2diaphora", "signatures", "flirt"],
        ]:
            os.makedirs(os.path.join(os.path.expanduser("~"), *path), exist_ok=True)

        dirname = os.path.dirname(__file__)
        sigs_dir = os.path.join(dirname, "r2diaphora", "signatures", "flirt")
        if not os.path.isdir(sigs_dir):
            return
        for _, dirs, _ in os.walk(sigs_dir):
            for d in dirs:
                shutil.copytree(
                    os.path.join(sigs_dir, d),
                    os.path.join(
                        os.path.expanduser("~"), ".r2diaphora", "signatures", "flirt", d
                    ),
                    dirs_exist_ok=True,
                )


setup(
    name="r2diaphora",
    version="0.4.0",
    description="radare2 port of Diaphora 3.5",
    url="https://github.com/FernandoDoming/r2diaphora",
    author="Fernando Domínguez",
    author_email="fernando.dom.del@gmail.com",
    license="GNU GPL v3",
    python_requires=">=3.8",
    packages=[
        "r2diaphora",
        "r2diaphora.ida_shim",
        "r2diaphora.idaapi",
        "r2diaphora.jkutils",
        "r2diaphora.others",
        "r2diaphora.upstream",
        "r2diaphora.upstream.codecut",
        "r2diaphora.upstream.db_support",
        "r2diaphora.upstream.jkutils",
        "r2diaphora.upstream.ml",
        "r2diaphora.upstream.others",
    ],
    package_data={
        "r2diaphora.upstream.ml": ["*.pkl"],
        "r2diaphora": ["signatures/**/*"],
    },
    install_requires=[
        "capstone>=5.0",
        "chardet>=4.0.0",
        "colorama>=0.4.4",
        "mysql-connector-python>=8.0.26",
        "pygments>=2.10.0",
        "r2pipe>=1.6.3",
        "yattag>=1.14.0",
    ],
    extras_require={
        # Optional: only used to describe files in the HTML report.
        "magic": ["python-magic>=0.4.27"],
    },
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    entry_points={
        "console_scripts": ["r2diaphora=r2diaphora.diaphora_r2:main"]
    },
    scripts=[
        "scripts/r2diaphora-bulk",
        "scripts/r2diaphora-db",
    ],
    include_package_data=True,
    cmdclass={"install": CustomInstall},
)
