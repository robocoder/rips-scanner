# rips-scanner
RIPS - A static source code analyser for vulnerabilities in PHP scripts

## Command-line Interface - CLI

### run index.php and provide any $_POST param via command-line as key=value

```
 php index.php [<key>=<value>, ...]
```

### usage

see php-rips scan form for details.

```
 php index.php [options]
 
 loc 				... target scan file/folder <path>
 subdir				... recurse subdirs [0|1]
 ignore_warning		... [0|1]
 vector				... scan vectors [all|..]
 verbosity			... log verbosity [0-9]
 treestyle			... html output style [0|1]
 stylesheet			....html output stylesheet [ayti|...]
```

## Jenkins-CI Integration Notes

1. download & install the [html publisher plugin](https://wiki.jenkins-ci.org/display/JENKINS/HTML+Publisher+Plugin)
2. configure scm to clone both this repository and the source you want to scan to distinct folders
3. add build step: execute shell

  ```
	 # config - remove this if you configer it via jenkins parameterized builds
	 PATH_RIPS=rips-scanner
	 PATH_REPORT=report
	 FILE_REPORT=report.html
	 PATH_TARGET=code
	 RIPS_RECURSE_SUBDIR=1
	 RIPS_VECTOR=all
	 RIPS_VERBOSITY=2
	 # copy dependencies
	 mkdir report
	 cp -r rips-scanner/css report
	 cp -r rips-scanner/js report
	 # run analysis
	 echo "========================================================="
	 echo "[**] running scan ... $PATH_TARGET"
	 echo "========================================================="
	 php $PATH_RIPS/index.php ignore_warning=1 loc=$PATH_TARGET subdirs=$RIPS_RECURSE_SUBDIR vector=$RIPS_VECTOR verbosity=$RIPS_VERBOSITY treestyle=1 stylesheet=ayti > $PATH_REPORT/$FILE_REPORT
	 echo "=========================================================" 
	 echo "[**] scan done ... check out $PATH_REPORT/$FILE_REPORT
	 echo "========================================================="
 ```
  
4. add build step: execute python
  
  ```
    
	import os, sys
	import rips_stats as rips
	if __name__=="__main__":
	    report = os.path.join(os.environ.get("PATH_REPORT","report"),os.environ.get("FILE_REPORT","report.html"))
	    sys.exit(rips.main([report]))
  ```
  
5. add post-build step: publish html, select folder 'report' name 'vulnerability-report'. A new clickable action icon 'vulnerability-report' will appear that points at the archived scan result.