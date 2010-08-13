<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			

Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.		

**/

	###############################  INCLUDES  ################################

	include('config/general.php');			// general settings
	include('config/userinput.php');		// tainted variables and functions
	include('config/tokens.php');			// tokens for lexical analysis
	include('config/securing.php');			// securing functions
	include('config/PVF.php');				// potentially vulnerable functions
	include('config/info.php');				// interesting functions
	
	include('functions/tokens.php');		// prepare and fix token list
	include('functions/scan.php');			// scan for PVF in token list
	include('functions/output.php');		// output scan result
	
	include('classes/classes.php'); 		// classes
	
	###############################  MAIN  ####################################
	
	$output = array();
	$scan_functions = array();
	$user_functions = array();
	$user_functions_offset = array();
	$user_input = array();
	$counterlines=0;
	$scanned_files=0;
		
	if(!empty($_POST['loc']))
	{
		$verbosity = isset($_POST['verbosity']) ? $_POST['verbosity'] : 1;
		
		$location = str_replace('\\', '/', $_POST['loc']);
		
		if(is_dir($location))
		{
			$scan_subdirs = isset($_POST['subdirs']) ? true : false;
			$data = read_recursiv($location, $scan_subdirs);
		}	
		else if(is_file($location))
		{
			$data[0] = $location;
		}
		else
		{
			$data = array();
		}
	
		if(!empty($_POST['scan']))
		{
			switch($_POST['vector']) 
			{
				case 'client': 		$scan_functions = $F_XSS;			break;
				case 'code': 		$scan_functions = $F_CODE;			break;
				case 'file_read':	$scan_functions = $F_FILE_READ;		break;
				case 'file_affect':	$scan_functions = $F_FILE_AFFECT;	break;		
				case 'file_include':$scan_functions = $F_FILE_INCLUDE;	break;			
				case 'exec':  		$scan_functions = $F_EXEC;			break;
				case 'database': 	$scan_functions = $F_DATABASE;		break;
				case 'connect': 	$scan_functions = $F_CONNECT;		break;
				
				case 'all': 

					$scan_functions = array_merge(
						$F_XSS,
						$F_CODE,
						$F_FILE_READ,
						$F_FILE_AFFECT,
						$F_FILE_INCLUDE,
						$F_EXEC,
						$F_DATABASE,
						$F_CONNECT
					); break;
				
				default: // all server side
				{ 
					$scan_functions = array_merge(
						$F_CODE,
						$F_FILE_READ,
						$F_FILE_AFFECT,
						$F_FILE_INCLUDE,
						$F_EXEC,
						$F_DATABASE,
						$F_CONNECT
					); break; 
				}
			}
			
			// always add F_OTHER
			$scan_functions = array_merge($scan_functions, $F_OTHER);
		
			$F_USERINPUT = $F_OTHER_INPUT;
			
			// add file and database functions as tainting functions
			if( $verbosity >= 2 )
			{
				$F_USERINPUT = array_merge($F_OTHER_INPUT, $F_FILE_INPUT, $F_DATABASE_INPUT);
			}
			
			foreach($data as $file_name)
			{
				if(in_array(substr($file_name, strrpos($file_name, '.')), $GLOBALS['filetypes']))
				{
					$userfunction_secures = false;
					$userfunction_taints = false;
					$scanned_files++;
					scan_file($file_name, $scan_functions, 
					$T_FUNCTIONS, $T_ASSIGNMENT, $T_IGNORE, 
					$T_INCLUDES, $T_XSS, $T_IGNORE_STRUCTURE);
				}
			}
		}
	} 

	$elapsed = microtime(TRUE) - $start;
	
	###############################  OUTPUT  ####################################
?><html>
<head>
	<link rel="stylesheet" type="text/css" href="css/default.css" />
	<?php
	$default_stylesheet = isset($_POST['stylesheet']) ? $_POST['stylesheet'] : $default_stylesheet;
	foreach($stylesheets as $stylesheet)
	{
		echo "\t<link type=\"text/css\" href=\"css/$stylesheet.css\" rel=\"";
		if($stylesheet != $default_stylesheet) echo "alternate ";
		echo "stylesheet\" title=\"$stylesheet\" />\n";
	}
	?>
	<script src="js/script.js"></script>
	<script src="js/exploit.js"></script>
</head>
<body onload="draginit();">
<div class="menu">
	<div style="float:left; width:100%;">
	<table width="100%">
	<tr><td width="70%" nowrap>
	<form action="" method="post">
		<table class="menutable" width="50%">
		<tr>
			<td nowrap><b>path / file:</b></td>
			<td colspan="2" nowrap><input type="text" size=80 name="loc" value="<?php 
			echo isset($_POST['loc']) ? htmlentities($_POST['loc'], ENT_QUOTES, 'UTF-8') : $basedir;
			?>">
			</td>
			<td nowrap><input type="checkbox" name="subdirs" value="1" <?php
				echo isset($_POST['subdirs']) ? 'checked' : '';
			?>/>subdirs</td>
		</tr>
		<tr>
			<td nowrap>verbosity level:</td>
			<td nowrap>
				<select name="verbosity" style="width:100%">
					<?php 
						$c_verbosity = isset($_POST['verbosity']) ? $_POST['verbosity'] : 0; 
						
						$verbosities = array(
							1 => '1. user tainted only',
							2 => '2. file/DB tainted +1',
							3 => '3. show secured +1,2',
							4 => '4. info gathering +1,2,3',
							5 => '5. untainted +1,2,3,4'
						);
						
						foreach($verbosities as $level=>$description)
						{
							echo "<option value=\"$level\" ";
							if($level == $c_verbosity) echo 'selected';
							echo ">$description</option>\n";							
						}
					?>
				</select>
			</td>
			<td align="right">
			vuln type:
				<select name="vector">
					<?php 
						$c_vector = isset($_POST['vector']) ? $_POST['vector'] : '';
						
						$vectors = array(
							'server' => 'All server side',							
							'code' => '- Code Evaluation',
							'exec' => '- Command Execution',
							'connect' => '- Connection Handling',							
							'file_read' => '- File Disclosure',
							'file_include' => '- File Inclusion',							
							'file_affect' => '- File Manipulation',
							'database' => '- SQL Injection',
							'client' => 'Cross-Site Scripting',
							'all' => 'All'
						);
						
						foreach($vectors as $vector=>$description)
						{
							echo "<option value=\"$vector\" ";
							if($vector == $c_vector) echo 'selected';
							echo ">$description</option>\n";
						}
					?>
				</select>
			</td>
			<td><input type="submit" name="scan" value="scan" class="Button" /></td>
		</tr>
		<tr>
			<td nowrap>code style:</td>
			<td nowrap>
				<select name="stylesheet" id="css" onchange="setActiveStyleSheet(this.value);" style="width:49%">
					<?php 
						foreach($stylesheets as $stylesheet)
						{
							echo "<option value=\"$stylesheet\" ";
							if($stylesheet == $default_stylesheet) echo 'selected';
							echo ">$stylesheet</option>\n";
						}
					?>	
				</select>
				<select name="treestyle" style="width:49%">
					<option value="1" <?php if($_POST['treestyle'] == 1) echo 'selected'; ?>>bottom-up</option>
					<option value="2" <?php if($_POST['treestyle'] == 2) echo 'selected'; ?>>top-down</option>
				</select>	
			</td>	
			<td align="right">
			<?php
				if(!empty($user_input))
				{
					echo '<input type="button" class="Button" value="user input" ',
					'onClick="openUserinput()" />&nbsp;';
				}

				if(!empty($user_functions_offset))
				{
					echo '<input type="button" class="Button" value="function list" ',
					'onClick="openFunctions()" />';
				}
			?>
			</td>
			<td></td>
		</tr>
		</table>
	</form>
	</td>
	<td width="30%" align="center" valign="top" nowrap>
		<!-- Logo by Gareth Heyes -->
		<div class="logo"><?php echo $version ?></div>
		<div class="footer">
			<?php printf("<p>Scanned $counterlines lines in $scanned_files files for ".
			count($scan_functions).' functions in %.03f seconds.</p>', $elapsed); ?>
		</div>
	</td></tr>
	</table>
	</div>
	
	<div style="clear:left;"></div>
</div>
<div class="menushade"></div>

<div id="window1" name="window">
	<div class="windowtitlebar">
		<div id="windowtitle1" onClick="top(1)" onmousedown="dragstart(1)" class="windowtitle"></div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(1)" />
	</div>
	<div id="windowcontent1" class="windowcontent"></div>
	<div class="windowfooter" onmousedown="resizestart()"></div>
</div>

<div id="window2" name="window">
	<div class="windowtitlebar">
		<div id="windowtitle2" onClick="top(2)" onmousedown="dragstart(2)" class="windowtitle"></div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(2)" />
	</div>
	<div id="windowcontent2" class="windowcontent"></div>
	<div class="windowfooter" onmousedown="resizestart()"></div>
</div>

<div id="window3" name="window">
	<div class="funclisttitlebar">
		<div id="windowtitle3" onClick="top(3)" onmousedown="dragstart(3)" class="funclisttitle">
		user defined functions
		</div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(3)" />
	</div>
	<div id="windowcontent3" class="funclistcontent">
		<?php
			createFunctionList($user_functions_offset);		
		?>
	</div>
	<div class="funclistfooter" onmousedown="resizestart()"></div>
</div>

<div id="window4" name="window">
	<div class="funclisttitlebar">
		<div id="windowtitle4" onClick="top(4)" onmousedown="dragstart(4)" class="funclisttitle">
		user input
		</div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(4)" />
	</div>
	<div id="windowcontent4" class="funclistcontent">
		<?php
			createUserinputList($user_input);		
		?>
	</div>
	<div class="funclistfooter" onmousedown="resizestart()"></div>
</div>

<div id="funccode" onmouseout="closeFuncCode()">
	<div id="funccodetitle"></div>
	<div id="funccodecontent"></div>
</div>

<?php
	if(isset($_POST['loc'])) 
	{
		@printoutput($output, $verbosity, $_POST['treestyle']); 
	}
	else
	{
		echo '<div style="margin-left:30px;color:#000000;font-size:14px">',
		'<h3>Quickstart:</h3>',
		'<p>Locate your PHP <b>path/file</b>, choose the <b>vulnerability type</b> you are looking for and click <u>scan</u>!<br />',
		'Check <b>subdirs</b> to include subdirectories into the scan. Note that scanning too many large files may exceed the time limit.</p>',
		'<h3>Advanced:</h3>',
		'<p>Debug your scan result by choosing a <b>verbosity level</b>.<br />',
		'After the scan finished click <b>user input</b> to get a list of entry points or <b>function list</b> for a list of all user defined functions. Both lists are referenced to the Code Viewer.</p>',
		'<h3>Style:</h3>',
		'<p>Change the syntax highlighting schema on-the-fly by selecting a different <b>code style</b>.<br />',
		'Before scanning you can choose which way a code trace should be displayed: <b>bottom-up</b> or <b>top-down</b>.</p>',
		'<h3>Icons:</h3>',
		'<ul>',
		'<li class="userinput"><font color="black"><b>User input</b> has been found in this line. Potential entry point for vulnerability exploitation.</font></li>',
		'<li class="functioninput"><font color="black">Vulnerability exploitation depends on the <b>parameters</b> passed to the function declared in this line. Have a look at the calls in the scan result.</font></li>',
		'<li class="validated"><font color="black">User defined <b>securing</b> has been detected in this line. This may prevent exploitation.</font></li>',
		'<li><div class="fileico"></div>&nbsp;Click the file icon to open the <b>Code Viewer</b> to review the original code. A new window will be opened with all relevant lines highlighted red.</li>',
		'<li><div class="minusico"></div>&nbsp;Click the minimize icon to <b>minimize</b> a specific code trace. You may maximize it later by clicking the icon again.</li>',
		'<li><div class="exploit"></div>&nbsp;Click the target icon to open the <b>Exploit Creator</b>. A new window will open where you can enter exploit details and create PHP Curl exploit code.</li>',
		'</ul>',
		'<p style="font-size:12px">hints: make sure RIPS has file permissions on your source code files. Don\'t leave the webinterface of RIPS open to the public internet.<p>',
		'</ul>',
		'</div>';
	}
?>

</body>
</html>