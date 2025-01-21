from setuptools import setup

setup(
    name="ServiceNowApiWrapper",
    version="1.00",
    py_modules=["ServiceNowApiWrapper_NoOAuth"],
    install_requires=[
        "requests==2.32.3",
    ],
    author="Thomas Obarowski",
    author_email="tjobarow@gmail.com",
    description="A wrapper making it easier to do various tasks, such as create/get incidents, via ServiceNow API",
    long_description="",
    long_description_content_type="text/markdown",
    url="",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
)
