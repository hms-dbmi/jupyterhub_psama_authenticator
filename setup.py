from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='jupyterhub_psama_authenticator',
    version='0.0.5',
    description='JupyterHub PIC-SURE PSAMA Authenticator',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/hms-dbmi/jupyterhub_psama_authenticator',
    author='Nick Benik',
    author_email='nicholas_benik@hms.harvard.edu',
    license='Apache License 2.0',
    packages=find_packages(),
    install_requires=['jupyterhub>=0.8'],
    include_package_data=True,
#    entry_points={
#        'jupyterhub.authenticators': [
#            'myservice = psamaauthenticator:PsamaAuthenticator',
#        ],
#    },
)
