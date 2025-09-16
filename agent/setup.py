#!/usr/bin/env python3

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open(os.path.join(os.path.dirname(__file__), '..', 'README.md'), encoding='utf-8') as f:
        return f.read()

# Read requirements
def read_requirements():
    requirements = []
    try:
        with open(os.path.join(os.path.dirname(__file__), 'requirements.txt'), encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    requirements.append(line)
    except FileNotFoundError:
        # Fallback requirements if requirements.txt doesn't exist
        requirements = [
            'pyyaml>=6.0',
            'requests>=2.25.0',
            'click>=8.0.0',
            'rich>=10.0.0',
            'pydantic>=1.8.0',
            'networkx>=2.5',
            'langchain>=0.0.300',
            'langgraph>=0.0.20',
            'openai>=1.0.0',
            'anthropic>=0.5.0',
            'google-generativeai>=0.3.0'
        ]
    return requirements

setup(
    name='sys-scan-graph-agent',
    version='5.0.0',
    description='AI Intelligence Layer for Sys-Scan-Graph Security Scanner',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    author='Joseph Mazzini',
    author_email='joseph@mazzlabs.works',
    url='https://github.com/Mazzlabs/sys-scan-graph',
    packages=find_packages(),
    include_package_data=True,
    install_requires=read_requirements(),
    extras_require={
        'dev': [
            'pytest>=6.0.0',
            'pytest-cov>=2.10.0',
            'black>=21.0.0',
            'flake8>=3.9.0',
            'mypy>=0.800'
        ],
        'docs': [
            'sphinx>=4.0.0',
            'sphinx-rtd-theme>=1.0.0'
        ]
    },
    entry_points={
        'console_scripts': [
            'sys-scan-agent=sys_scan_graph_agent.cli:app',
            'sys-scan-intelligence=sys_scan_graph_agent.cli:app'
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: Business Source License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities'
    ],
    python_requires='>=3.8',
    keywords='security scanner ai intelligence linux system-analysis',
    project_urls={
        'Bug Reports': 'https://github.com/Mazzlabs/sys-scan-graph/issues',
        'Source': 'https://github.com/Mazzlabs/sys-scan-graph',
        'Documentation': 'https://github.com/Mazzlabs/sys-scan-graph/wiki'
    }
)