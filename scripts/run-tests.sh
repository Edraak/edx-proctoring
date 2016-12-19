#!/usr/bin/env bash set -e

echo 'Beginning Test Run...'
echo ''

echo 'Removing *.pyc files'
find . -name "*.pyc" -exec rm -rf {} \;

echo 'Running test suite'
coverage run manage.py test edx_proctoring --verbosity=3

echo 'Building coverage reports'
coverage report -m
coverage html
echo ''
echo 'View the full coverage report at {CODE_PATH}/edx-proctoring/htmlcov/index.html'

echo 'Checking styling'
pep8 edx_proctoring
pylint edx_proctoring --report=no
echo 'Styling check complete'

echo ''
echo 'Testing Complete!'
