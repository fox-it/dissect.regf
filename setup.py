from setuptools import setup

setup(
    name="dissect.regf",
    packages=["dissect.regf"],
    install_requires=[
        "dissect.cstruct>=3.0.dev,<4.0.dev",
        "dissect.util>=3.0.dev,<4.0.dev",
    ],
)
