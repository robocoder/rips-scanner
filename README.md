<<<<<<< HEAD
<<<<<<< HEAD
# RIPS
A static source code analyser for vulnerabilities in PHP scripts

## Requirements
* web server: Apache or Nginx recommended
* PHP: latest version recommended
* browser: Firefox recommended

## Installation
1. Download the latest release
2. Extract the files to your local web server's document root 
3. Make sure your web server has file permissions
4. Make sure your installation is protected from unauthorized access
5. Open your browser at http://localhost/rips-xx/ 

## Usage
Follow the instructions on the main page.

## Command-line Interface - CLI

#### usage

see original php-rips scan html form (index.php) for more options.

```
php index.php [option=value]

options:
  loc 				... target scan file/folder <path>
  subdir				... recurse subdirs [0|1]
  ignore_warning		... [0|1]
  vector				... scan vectors [all|..]
  verbosity			... log verbosity [0-9]
  treestyle			... html output style [0|1]
  stylesheet			....html output stylesheet [ayti|...]
  
example: recursively scan ./code for all vuln. classes
  php index.php loc=./code subdirs=1 vector=all verbosity=2
```

Note: in cli-mode argv wil be parsed into $_POST therefore allowing you to set any POST-Vars.

#### Jenkins-CI Integration Notes

1. install the [html publisher plugin](https://wiki.jenkins-ci.org/display/JENKINS/HTML+Publisher+Plugin)
2. configure (multiple) scm to clone both this repository and the source you want to scan to distinct folders
3. add build step: execute shell

```bash
# config - remove this if you configure it via jenkins parameterized builds
PATH_RIPS=rips-scanner
PATH_REPORT=report
FILE_REPORT=report.html
PATH_TARGET=code
RIPS_RECURSE_SUBDIR=1
RIPS_VECTOR=all
RIPS_VERBOSITY=2
# copy dependencies
mkdir -p report
cp -r rips-scanner/css report
cp -r rips-scanner/js report
# run analysis
echo "========================================================="
echo "[**] running scan ... $PATH_TARGET"
echo "========================================================="
php $PATH_RIPS/index.php ignore_warning=1 loc=$PATH_TARGET subdirs=$RIPS_RECURSE_SUBDIR vector=$RIPS_VECTOR verbosity=$RIPS_VERBOSITY treestyle=1 stylesheet=ayti > $PATH_REPORT/$FILE_REPORT
echo "=========================================================" 
echo "[**] scan done ... check out $PATH_REPORT/$FILE_REPORT"
echo "========================================================="
```
  
4. add build step: execute python
  
```python
import os, sys
import rips_stats as rips
if __name__=="__main__":
    report = os.path.join(os.environ.get("PATH_REPORT","report"),os.environ.get("FILE_REPORT","report.html"))
    sys.exit(rips.main([report]))
```

5. add post-build step: publish html, select folder 'report' name 'vulnerability-report'. A new clickable action icon 'vulnerability-report' will appear that points at the archived scan result.

## Development
RIPS 0.5 development is abandoned. A complete rewrite is in development. Follow @FluxReiners for updates. 
