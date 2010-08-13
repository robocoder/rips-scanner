<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/
	
	// array to concated string
	function createlist($list)
	{
		$out = '';
		if(is_array($list))
		{
			$list = array_unique($list);
			foreach($list as $element)
			{
				$out .= "$element,";
			}
			$out = substr($out, 0, -1);
		}
		return $out;
	}
	
	// reference function declaration with function calls
	function makefunclink($line, $linenr, $funcname)
	{
			$link = '<A NAME="'.$funcname.'_declare"></A>';
			$link.= '<a href="#'.$funcname.'_call" title="jump to call">';
			$link.= highlightline($line, $linenr).'</a>';
			return $link;
	}
	
	// prepare output to style with CSS
	function highlightline($line, $line_nr, $title=false, $udftitle=false, $tainted_vars=array())
	{
		$reference = true;
		$tokens = @token_get_all('<? '.trim($line).' ?>');
		$output = "<span class=\"linenr\">$line_nr:</span>&nbsp;";
		if($title)
		{
			$output.='<a class="link" href="'.$GLOBALS['doku'].$title.'" title="open php documentation" target=_blank>';
			$output.="$title</a>&nbsp;";
		} 
		else if($udftitle)
		{
			$output.='<a class="link" href="#'.$udftitle.'_declare" title="jump to declaration">'.$udftitle.'</a>&nbsp;';
		}
		
		$var_count = 0;
		
		foreach ($tokens as $token)
		{
			if (is_string($token))
			{		
				$output .= '<span class="phps-code">'.htmlentities($token, ENT_QUOTES, 'utf-8').'</span>';
			} 
			else if (is_array($token) 
			&& $token[0] !== T_OPEN_TAG
			&& $token[0] !== T_CLOSE_TAG) 
			{
				$text = htmlentities($token[1], ENT_QUOTES, 'utf-8');
				$text = str_replace(array(' ', "\n"), array('&nbsp;', '<br/>'), $text);
				
				if($token[0] === T_FUNCTION)
				{
					$reference = false;
				}
				if($token[0] === T_STRING && $reference 
				&& isset($GLOBALS['user_functions_offset'][$text]))
				{				
					$text = @"<span onmouseover=\"getFuncCode(this,'{$GLOBALS['user_functions_offset'][$text][0]}','{$GLOBALS['user_functions_offset'][$text][1]}','{$GLOBALS['user_functions_offset'][$text][2]}')\" style=\"text-decoration:underline\" class=\"phps-".str_replace('_', '-', strtolower(token_name($token[0])))."\">$text</span>";
				}	
				else if ($token[0] !== T_WHITESPACE)
				{
					if($token[0] === T_VARIABLE)
						$var_count++;
						
					if($token[0] === T_VARIABLE && in_array($var_count, $tainted_vars))
						$text = "<span class=\"phps-tainted-var\">$text</span>";
					else
						$text = '<span class="phps-'.str_replace('_', '-', strtolower(token_name($token[0])))."\">$text</span>";
				}
				$output .= $text;
			}
		}
		return $output;
	}
	
	// detect vulnerability type given by the PVF name
	function getVulnNodeTitle($func_name)
	{
		if(isset($GLOBALS['F_CODE'][$func_name])) 
			$vulnname = 'Code Evaluation';
		else if(isset($GLOBALS['F_FILE_READ'][$func_name])) 
			$vulnname = 'File Disclosure';
		else if(isset($GLOBALS['F_FILE_AFFECT'][$func_name])) 
			$vulnname = 'File Manipulation';		
		else if(isset($GLOBALS['F_FILE_INCLUDE'][$func_name])) 
			$vulnname = 'File Inclusion';			
		else if(isset($GLOBALS['F_EXEC'][$func_name])) 
			$vulnname = 'Command Execution';
		else if(isset($GLOBALS['F_DATABASE'][$func_name])) 
			$vulnname = 'SQL Injection';
		else if(isset($GLOBALS['F_CONNECT'][$func_name])) 
			$vulnname = 'Connection Manipulation';	
		else if(isset($GLOBALS['F_XSS'][$func_name])) 
			$vulnname = 'Cross-Site Scripting';		
		else if(isset($GLOBALS['F_OTHER'][$func_name])) 
			$vulnname = 'Possible Flow Control'; // :X				
		else 
			$vulnname = "Call triggers vulnerability in <i>$func_name()</i> (click name to jump to declaration)";
		return $vulnname;	
	}
	
	// traced parameter output bottom-up
	function traverseBottomUp($tree) 
	{
		echo '<ul';
		switch($tree->marker) 
		{
			case 1: echo ' class="userinput"'; break;
			case 2: echo ' class="validated"'; break;
			case 3: echo ' class="functioninput"'; break;
			case 4: echo ' class="persistent"'; break;
		}
		echo '><li>' . $tree->value;

		foreach ($tree->children as $child) 
		{
			traverseBottomUp($child);
		}
		
		echo '</li></ul>',"\n";
	}
	
	// traced parameter output top-down
	function traverseTopDown($tree, $start=true, $lines=array()) 
	{
		if($start) echo '<ul>';
	
		foreach ($tree->children as $child) 
		{
			$lines = traverseTopDown($child, false, $lines);
		}
		
		// do not display a line twice
		if(!isset($lines[$tree->line]))
		{
			echo '<li';
			switch($tree->marker) 
			{
				case 1: echo ' class="userinput"'; break;
				case 2: echo ' class="validated"'; break;
				case 3: echo ' class="functioninput"'; break;
				case 4: echo ' class="persistent"'; break;
			}
			echo '>',$tree->value,'</li>',"\n";
			// add to array to ignore next time
			$lines[$tree->line] = 1;
		}	
			
		if($start) echo '</ul>';
		
		return $lines;
	}	

	// requirements output
	function depthSecondTraverse($tree) 
	{
		if(!empty($tree->dependencies))
		{
			echo '<ul><li><span class="requires">requires:</span>';

			foreach ($tree->dependencies as $linenr=>$dependency) 
			{
				if(!empty($dependency))
				{
					// function declaration in requirement is a bit tricky, extract name to form a link
					if( strpos($dependency, 'function ') !== false && ($end=strpos($dependency, '(')) > 10 ) 
						echo '<ul><li>'.makefunclink($dependency, $linenr, trim(substr($dependency,9,$end-9))).'</li></ul>';
					else
						echo '<ul><li>'.highlightline($dependency, $linenr).'</li></ul>';
				}
			}

			echo '</li></ul>',"\n";
		}
	}
	
	// print the scanresult
	function printoutput($output, $verbosity, $treestyle=1)
	{
		do
		{
			if(!empty($output))
			{
				if($verbosity < 5)
				{
					// clean output (vulnerable function declaration with no calls)
					for($i=count($output[key($output)])-1; $i>=0; $i--)
					{		
						$func_depend = $output[key($output)][$i]->funcdepend;
						if( $func_depend 
						&& !isset($GLOBALS['user_functions'][key($output)][$func_depend]['called']))
						{
							$value = $output[key($output)][$i]->name;
							unset($output[key($output)][$i]);
							if( isset($GLOBALS['user_functions'][key($output)][$value]) )
								unset($GLOBALS['user_functions'][key($output)][$value]);	
						}
					}
				}	
					
				if(key($output) != "" && !empty($output[key($output)]) )
				{
					echo '<div class="filebox">',
					'<span class="filename">File: '.key($output).'</span><br>',
					'<div id="'.key($output).'"><br>';
	
					foreach($output[key($output)] as $tree)
					{		
						echo '<div class="codebox"><table border=0>',"\n",
						'<tr><td valign="top" nowrap>',"\n",
						'<div class="fileico" title="review code" ',
						'onClick="openCodeViewer(this,\'',
						$tree->filename ? $tree->filename : key($output), '\',\'',
						implode(',', $tree->lines), '\');"></div>'."\n",
						'<div id="pic',key($output),$tree->lines[0],'" class="minusico" title="minimize"',
						' onClick="hide(\'',key($output),$tree->lines[0],'\')"></div>',"\n";
					
						if(!empty($tree->get) || !empty($tree->post) 
						|| !empty($tree->cookie) || !empty($tree->files)
						|| !empty($tree->server) )
						{
							echo '<br><div class="exploit" ',
							'title="exploit" ',
							'onClick="openExploitCreator(this, \'',
							$tree->filename ? $tree->filename : key($output),
							'\',\'',createlist($tree->get),'\',\'',createlist($tree->post),
							'\',\'',createlist($tree->cookie),'\',\'',createlist($tree->files),
							'\',\'',createlist($tree->server),'\');">','</div>',"\n";
						}
						
						echo '</td><td><span class="vulntitle">',$tree->title,'</span>',
						'<div class="code" id="'.key($output).$tree->lines[0].'">',"\n";
						
						if($treestyle == 1)
							traverseBottomUp($tree);
						else if($treestyle == 2)
							traverseTopDown($tree);

						echo '<ul><li>',"\n";
						depthSecondTraverse($tree);
						echo '</li></ul>',"\n",	'</div>',"\n", '</td></tr></table></div>',"\n";
					}

					echo '</div><div class="buttonbox">',"\n",
					'<input type="submit" class="Button" value="hide all" ',
					'onClick="hide(\'',key($output),'\')">',"\n",
					'</div></div><hr>',"\n";
				}	
				else if(count($output) == 1)
				{
					echo '<div style="margin-left:30px;color:#000000">Nothing vulnerable found. Change the verbosity level and try again.</div>';
				}
			}
			else if($GLOBALS['scanned_files'] > 0)
			{
				echo '<div style="margin-left:30px;color:#000000">Nothing vulnerable found. Change the verbosity level and try again.</div>';
			}
			else
			{
				echo '<div style="margin-left:30px;color:#000000">Nothing to scan.</div>';
			}
		}
		while(next($output));
	}
	
	// build list of available functions
	function createFunctionList($user_functions_offset)
	{
		if(!empty($user_functions_offset))
		{
			ksort($user_functions_offset);
			echo '<table>';
			foreach($user_functions_offset as $func_name => $info)
			{
				echo '<tr><td><div class="funclistline" title="',$info[0],'" ',
				'onClick="openCodeViewer(3, \'',$info[0],'\', \'',($info[1]+1),
				',',(!empty($info[2]) ? $info[2]+1 : 0),'\')">',$func_name,'</div></td></tr>';
			}
			echo '</table>';
		}
	}
	
	function createUserinputList($user_input)
	{
		if(!empty($user_input))
		{
			ksort($user_input);
			echo '<table>';
			foreach($user_input as $input_name => $file)
			{
				$finds = array();
				foreach($file as $file_name => $lines)
				{
					foreach($lines as $line)
					{
						$finds[] = "<span class=\"funclistline\" title=\"$file_name\" onClick=\"openCodeViewer(4, '$file_name', '$line')\">$line</span>";
					}
				}
				echo "<tr><td nowrap>$input_name</td><td nowrap>",createlist($finds),'</td></tr>';

			}
			echo '</table>';
		}
	}
	
?>	