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
	include('functions/search.php');		// search functions
	
	include('classes/classes.php'); 		// classes
	
	###############################  MAIN  ####################################
	
	$start = microtime(TRUE);
	
	$output = array();
	$scanned_files = array();
	
	if(!empty($_POST['loc']))
	{		
		$location = str_replace('\\', '/', $_POST['loc']);
		
		if(is_dir($location))
		{
			$scan_subdirs = isset($_POST['subdirs']) ? $_POST['subdirs'] : false;
			$data = read_recursiv($location, $scan_subdirs);
			
			if(count($data) > $warnfiles && !isset($_POST['ignore_warning']))
				die('warning:'.count($data));
		}	
		else if(is_file($location) && in_array(substr($location, strrpos($location, '.')), $filetypes))
		{
			$data[0] = $location;
		}
		else
		{
			$data = array();
		}
	
		// SCAN
		if(empty($_POST['search']))
		{
			$scan_functions = array();
			$user_functions = array();
			$user_functions_offset = array();
			$user_input = array();
			$counterlines=0;
			
			$count_xss=$count_sqli=$count_fr=$count_fa=$count_fi=$count_exec=$count_code=$count_eval=$count_xpath=$count_ldap=$count_con=$count_other=$count_inc=$count_inc_fail=0;
			
			$verbosity = isset($_POST['verbosity']) ? $_POST['verbosity'] : 1;
		
			switch($_POST['vector']) 
			{
				case 'client': 		$scan_functions = $F_XSS;			break;
				case 'code': 		$scan_functions = $F_CODE;			break;
				case 'file_read':	$scan_functions = $F_FILE_READ;		break;
				case 'file_affect':	$scan_functions = $F_FILE_AFFECT;	break;		
				case 'file_include':$scan_functions = $F_FILE_INCLUDE;	break;			
				case 'exec':  		$scan_functions = $F_EXEC;			break;
				case 'database': 	$scan_functions = $F_DATABASE;		break;
				case 'xpath':		$scan_functions = $F_XPATH;			break;
				case 'ldap':		$scan_functions = $F_LDAP;			break;
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
						$F_XPATH,
						$F_LDAP,
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
						$F_XPATH,
						$F_LDAP,
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
				$userfunction_secures = false;
				$userfunction_taints = false;
				$scanned_files[$file_name] = scan_file($file_name, $scan_functions, 
				$T_FUNCTIONS, $T_ASSIGNMENT, $T_IGNORE, 
				$T_INCLUDES, $T_XSS, $T_IGNORE_STRUCTURE);
			}
			
			// remove vulnerabilities in user-defined functions that have not been called
			if($verbosity < 5)
				$output = cleanoutput($output);
		}
		// SEARCH
		else if(!empty($_POST['regex']))
		{
			$count_matches = 0;

			foreach($data as $file_name)
			{
				searchFile($file_name, $_POST['regex']);
			}
		}
	} 
	
	$elapsed = microtime(TRUE) - $start;
	
	################################  RESULT  #################################	
?>	
<div id="window1" name="window" style="width:600px; height:250px;">
	<div class="windowtitlebar">
		<div id="windowtitle1" onClick="top(1)" onmousedown="dragstart(1)" class="windowtitle"></div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(1)" title="close" />	
	</div>
	<div id="windowcontent1" class="windowcontent"></div>
	<div id="return" class="return" onClick="returnLastCode()">&crarr; return</div>
	<div class="windowfooter" onmousedown="resizeStart(event, 1)"></div>
</div>

<div id="window2" name="window" style="width:600px; height:250px;">
	<div class="windowtitlebar">
		<div id="windowtitle2" onClick="top(2)" onmousedown="dragstart(2)" class="windowtitle"></div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(2)" title="close" />
	</div>
	<div id="windowcontent2" class="windowcontent"></div>
	<div class="windowfooter" onmousedown="resizeStart(event, 2)"></div>
</div>

<div id="window3" name="window" style="width:300px; height:300px;">
	<div class="funclisttitlebar">
		<div id="windowtitle3" onClick="top(3)" onmousedown="dragstart(3)" class="funclisttitle">
		user defined functions
		</div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(3)" title="close" />
	</div>
	<div id="windowcontent3" class="funclistcontent">
		<?php
			createFunctionList($user_functions_offset);		
		?>
	</div>
	<div class="funclistfooter" onmousedown="resizeStart(event, 3)"></div>
</div>

<div id="window4" name="window" style="width:300px; height:300px;">
	<div class="funclisttitlebar">
		<div id="windowtitle4" onClick="top(4)" onmousedown="dragstart(4)" class="funclisttitle">
		user input
		</div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(4)" title="close" />
	</div>
	<div id="windowcontent4" class="funclistcontent">
		<?php
			createUserinputList($user_input);		
		?>
	</div>
	<div class="funclistfooter" onmousedown="resizeStart(event, 4)"></div>
</div>

<div id="window5" name="window" style="width:300px; height:300px;">
	<div class="funclisttitlebar">
		<div id="windowtitle4" onClick="top(5)" onmousedown="dragstart(5)" class="funclisttitle">
		scanned files
		</div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(5)" title="close" />
	</div>
	<div id="windowcontent5" class="funclistcontent">
		<?php
			createFileList($scanned_files);		
		?>
	</div>
	<div class="funclistfooter" onmousedown="resizeStart(event, 5)"></div>
</div>		

<div id="funccode" onmouseout="closeFuncCode()">
	<div id="funccodetitle"></div>
	<div id="funccodecontent"></div>
</div>

<div id="stats" class="stats">
	<table width="100%">
		<tr>
			<th align="right" style="font-size:22px">Result</th>
			<th align="right"><input class="button" type="button" value="x" onClick="document.getElementById('stats').style.display='none';" title="close" /></th>
		</tr>
		<tr><td colspan="2"><hr /></td></tr>
<?php 
	if(empty($_POST['search']))
	{
		$count_all=$count_xss+$count_sqli+$count_fr+$count_fa+$count_fi+$count_exec+$count_code+$count_eval+$count_xpath+$count_ldap+$count_con+$count_other;
		
		if($count_all > 0)
		{
			if($count_code > 0)
				statsRow($NAME_CODE, $count_code, $count_all);
			if($count_exec > 0)	
				statsRow($NAME_EXEC, $count_exec, $count_all);
			if($count_con > 0)	
				statsRow($NAME_CONNECT, $count_con, $count_all);
			if($count_fr > 0)	
				statsRow($NAME_FILE_READ, $count_fr, $count_all);
			if($count_fi > 0)	
				statsRow($NAME_FILE_INCLUDE, $count_fi, $count_all);
			if($count_fa > 0)	
				statsRow($NAME_FILE_AFFECT, $count_fa, $count_all);
			if($count_ldap > 0)	
				statsRow($NAME_LDAP, $count_ldap, $count_all);
			if($count_sqli > 0)	
				statsRow($NAME_DATABASE, $count_sqli, $count_all);
			if($count_xpath > 0)	
				statsRow($NAME_XPATH, $count_xpath, $count_all);
			if($count_xss > 0)	
				statsRow($NAME_XSS, $count_xss, $count_all);
			if($count_other > 0)	
				statsRow($NAME_OTHER, $count_other, $count_all);
			echo '<tr><td nowrap>Sum:</td><td>',$count_all,'</td></tr>'; 
		} else
		{
			echo '<tr><td colspan="2">No vulnerabilities found.</td></tr>';
		}
	} else
	{
		echo '<tr><td colspan="2">',(($count_matches == 0) ? 'No' : $count_matches),' matches found.</td></tr>';
	}

	echo '<tr><td colspan="2"><hr /></td></tr>',
		'<tr><td nowrap>Scanned files:</td><td nowrap>',count($scanned_files),'</td></tr>';
	if(empty($_POST['search']))
	{
		echo '<tr><td nowrap>Considered PVFs:</td><td nowrap>',count($scan_functions),'</td></tr>',
		'<tr><td nowrap>Include success:</td><td nowrap>';
	
		if($count_inc > 0)
		{
			echo ($count_inc_success=$count_inc-$count_inc_fail).'/'.$count_inc; 
			echo ' ('.round(($count_inc_success/$count_inc)*100,0).'%)'; 
		} else
		{
			echo 'No includes.';
		}
	}	
		?></td></tr>
		<tr><td nowrap>Scan time:</td><td nowrap><?php printf("%.03f seconds", $elapsed); ?></td></tr>
	</table>		

</div>

<?php 
	// scan result
	@printoutput($output, $_POST['treestyle']); 
?>