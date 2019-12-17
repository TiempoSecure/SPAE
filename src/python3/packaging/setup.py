import setuptools


setuptools.setup(
    name="spae_aes",
    version="0.1.0",
    author="Sebastien Riou",
    author_email="sebastien.riou@tiempo-secure.com",
    description="Library for SPAE authenticated encryption",
    long_description = """
    Library for SPAE authenticated encryption
    """,
    long_description_content_type="text/markdown",
    url="https://github.com/TiempoSecure/SPAE",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
