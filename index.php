<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			

Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.		

**/

include 'config/general.php';

?><html>
<head>
	<link rel="stylesheet" type="text/css" href="css/rips.css" />
	<?php

	foreach($stylesheets as $stylesheet)
	{
		echo "\t<link type=\"text/css\" href=\"css/$stylesheet.css\" rel=\"";
		if($stylesheet != $default_stylesheet) echo "alternate ";
		echo "stylesheet\" title=\"$stylesheet\" />\n";
	}
	?>
	<script src="js/script.js"></script>
	<script src="js/exploit.js"></script>
	<script src="js/hotpatch.js"></script>
	<script src="js/netron.js"></script>
	<title>RIPS - A static source code analyser for vulnerabilities in PHP scripts</title>
</head>
<body onload="draginit();" onmousemove="getPos(event);" onmouseup="mouseButtonPos='up';">

<div class="menu">
	<div style="float:left; width:100%;">
	<table width="100%">
	<tr><td width="75%" nowrap>
		<table class="menutable" width="50%" style="float:left;">
		<tr>
			<td nowrap><b>path / file:</b></td>
			<td colspan="3" nowrap><input type="text" size=80 id="location" value="<?php echo isset($basedir) ? $basedir : ''; ?>" title="enter path to PHP file(s)">
			</td>
			<td nowrap><input type="checkbox" id="subdirs" value="1" title="check to scan subdirectories" />subdirs</td>
		</tr>
		<tr>
			<td nowrap>verbosity level:</td>
			<td nowrap>
				<select id="verbosity" style="width:100%" title="select verbosity level">
					<?php 
					
						$verbosities = array(
							1 => '1. user tainted only',
							2 => '2. file/DB tainted +1',
							3 => '3. show secured +1,2',
							4 => '4. untainted +1,2,3',
							5 => '5. debug'
						);
						
						foreach($verbosities as $level=>$description)
						{
							echo "<option value=\"$level\">$description</option>\n";							
						}
					?>
				</select>
			</td>
			<td align="right">
			vuln type:
			</td>
			<td>
				<select id="vector" style="width:100%" title="select vulnerability type to scan">
					<?php 
					
						$vectors = array(
							'server' => 'All server side',							
							'code' => '- Code Evaluation',
							'exec' => '- Command Execution',
							'connect' => '- Header Injection',							
							'file_read' => '- File Disclosure',
							'file_include' => '- File Inclusion',							
							'file_affect' => '- File Manipulation',
							'ldap' => '- LDAP Injection',
							'database' => '- SQL Injection',
							'xpath' => '- XPath Injection',
							'client' => 'Cross-Site Scripting',
							'all' => 'All',
							'unserialize' => 'Unserialize / POP',
						);
						
						foreach($vectors as $vector=>$description)
						{
							echo "<option value=\"$vector\">$description</option>\n";
						}
					?>
				</select>
			</td>
			<td><input type="button" value="scan" style="width:100%" class="Button" onClick="scan(false);" title="start scan" /></td>
		</tr>
		<tr>
			<td nowrap>code style:</td>
			<td nowrap>
				<select name="stylesheet" id="css" onChange="setActiveStyleSheet(this.value);" style="width:49%" title="select color schema for scan result">
					<?php 
						foreach($stylesheets as $stylesheet)
						{
							echo "<option value=\"$stylesheet\" ";
							if($stylesheet == $default_stylesheet) echo 'selected';
							echo ">$stylesheet</option>\n";
						}
					?>	
				</select>
				<select id="treestyle" style="width:49%" title="select direction of code flow in scan result">
					<option value="1">bottom-up</option>
					<option value="2">top-down</option>
				</select>	
			</td>	
			<td align="right">
				regex:
			</td>
			<td>
				<input type="text" id="search" style="width:100%" />
			</td>
			<td>
				<input type="button" class="Button" style="width:100%" value="search" onClick="search()" title="search code by regular expression" />
			</td>
		</tr>
		</table>
		<div id="options" style="margin-top:-10px; display:none; text-align:center;" >
			<p class="textcolor">windows</p>
			<input type="button" class="Button" style="width:50px" value="files" onClick="openWindow(5);eval(document.getElementById('filegraph_code').innerHTML);maxWindow(5, 650);" title="show list of scanned files" />
			<input type="button" class="Button" style="width:80px" value="user input" onClick="openWindow(4)" title="show list of user input" /><br />
			<input type="button" class="Button" style="width:50px" value="stats" onClick="document.getElementById('stats').style.display='block';" title="show scan statistics" />
			<input type="button" class="Button" style="width:80px" value="functions" onClick="openWindow(3);eval(document.getElementById('functiongraph_code').innerHTML);maxWindow(3, 650);" title="show list of user-defined functions" />
		</div>
	</td>
	<td width="25%" align="center" valign="center" nowrap>
		<!-- Logo by Gareth Heyes -->
		<div class="logo"><a id="logo" href="http://sourceforge.net/projects/rips-scanner/files/" target="_blank" title="get latest version"><?php echo $version ?></a></div>
	</td></tr>
	</table>
	</div>
	
	<div style="clear:left;"></div>
</div>
<div class="menushade"></div>

<div class="scanning" id="scanning">scanning ...
<div class="scanned" id="scanned"></div>
</div>

<div id="result">
	
	<div style="margin-left:30px;color:#000000;font-size:14px">
		<h3>Quickstart:</h3>
		<p>Locate your PHP <b>path/file</b>, choose the <b>vulnerability type</b> you are looking for and click <u>scan</u>!<br />
		Check <b>subdirs</b> to include subdirectories into the scan. Note that scanning too many large files may exceed the time limit.</p>
		<h3>Advanced:</h3>
		<p>Debug your scan result by choosing a <b>verbosity level</b>.<br />
		After the scan finished click <b>user input</b> to get a list of entry points, <b>functions</b> for a list of all user defined functions or <b>files</b> for a list of all scanned files and their includes. All lists are referenced to the Code Viewer.</p>
		<h3>Style:</h3>
		<p>Change the syntax highlighting schema on-the-fly by selecting a different <b>code style</b>.<br />
		Before scanning you can choose which way the code flow should be displayed: <b>bottom-up</b> or <b>top-down</b>.</p>
		<h3>Icons:</h3>
		<ul>
		<li class="userinput"><font color="black"><b>User input</b> has been found in this line. Potential entry point for vulnerability exploitation.</font></li>
		<li class="functioninput"><font color="black">Vulnerability exploitation depends on the <b>parameters</b> passed to the function declared in this line. Have a look at the calls in the scan result.</font></li>
		<li class="validated"><font color="black">User defined <b>securing</b> has been detected in this line. This may prevent exploitation.</font></li>
		<li><div class="fileico"></div>&nbsp;Click the file icon to open the <b>Code Viewer</b> to review the original code. A new window will be opened with all relevant lines highlighted red.<br />
		Highlight variables temporarily by mouseover or persistently by click. Jump into the code of a user-defined function by clicking on the call. Click <u>return</u> on the bottom of the code viewer to jump back.</li>
		<li><div class="minusico"></div>&nbsp;Click the minimize icon to <b>hide</b> a specific code trace. You may display it later by clicking the icon again.</li>
		<li><div class="exploit"></div>&nbsp;Click the target icon to open the <b>Exploit Creator</b>. A new window will open where you can enter exploit details and create PHP Curl exploit code.</li>
		<li><div class="help"></div>&nbsp;Click the help icon to get a <b>description</b>, example code, example exploitation, patch and related securing functions for this vulnerability type.</li>
		</ul>
		<p style="font-size:12px">hints: Make sure RIPS has file permissions on your source code files. Don't leave the webinterface of RIPS open to the public internet. Tested with Firefox.<p>
		</ul>
	</div>
	
</div>

</body>
</html>