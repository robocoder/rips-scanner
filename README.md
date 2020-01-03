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

## Command Line Interface - CLI

#### Usage

See original php-rips scan html form (index.php) for more options.

```
  php index.php [option=value]
```

| Options | Value |
| --- | --- |
| loc | target scan file/folder <path> |
| subdir | recurse subdirs \[0\|1] |
| ignore_warning | \[0\|1] |
| vector | scan vectors \[all\|...] |
| verbosity | log verbosity \[0-9] |
| treestyle | html output style \[0\|1] |
| stylesheet | html output stylesheet \[ayti\|...] |

Example: recursively scan ./code for all vuln. classes
```
  php index.php loc=./code subdirs=1 vector=all verbosity=2
```

Note: in cli-mode argv wil be parsed into `$_POST` therefore allowing you to set any POST variables.

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
The `community` branch of RIPS is forked from version 0.55 and is not officially supported by RIPS Technologies.

A completely rebuilt solution is available from RIPS Technologies that overcomes fundamental limitations in the open source version and performs state-of-the-art security analysis.

| Compared Feature | RIPS 0.5 | Next Generation |
| --- | --- | --- |
| Supported PHP Language | PHP 3-4, no OOP | all, PHP 3-7 |
| Static Code Analysis | Only Token-based | Full |
| Analysis Precision | Low | Very High |
| PHP Version Specific Analysis | No | Yes |
| Scales to Large Codesizes | No | Yes |
| API / CLI Support | No | Yes |
| Continuous Integration | No | Yes |
| Compliance / Standards | No | Yes |
| Store Analysis Results | No | Yes |
| Export Analysis Results | No | Yes |
| Issue Review System | No | Yes |
| Realtime Results | No | Yes |
| Vulnerability Trends | No | Yes |
| Detects Latest Risks | No | Yes |
| Detects Complex Vulnerabilities | Limited | Yes |
| Supported Issue Types | 15 | >140 |
| Speed | Fast | Fast |

Learn more about the next generation of RIPS at https://www.ripstech.com/product/datasheets/.
