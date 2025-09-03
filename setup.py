from setuptools import setup, find_packages

setup(
    name='network-forensics-app',
    version='0.1.0',
    author='Your Name',
    author_email='your.email@example.com',
    description='A network forensics application for analyzing traffic, detecting incidents, and visualizing insights.',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        # List your project dependencies here
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)