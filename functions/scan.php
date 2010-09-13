<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/
	
	// get all php files from directory, including all subdirectories
	function read_recursiv($path, $scan_subdirs)
	{  
		$result = array(); 

		$handle = opendir($path);  

		if ($handle)  
		{  
			while (false !== ($file = readdir($handle)))  
			{  
				if ($file !== '.' && $file !== '..')  
				{  
					$name = $path . '/' . $file; 
					if (is_dir($name) && $scan_subdirs) 
					{  
						$ar = read_recursiv($name, true); 
						foreach ($ar as $value) 
						{ 
							if(in_array(substr($value, strrpos($value, '.')), $GLOBALS['filetypes']))
								$result[] = $value; 
						} 
					} else if(in_array(substr($name, strrpos($name, '.')), $GLOBALS['filetypes'])) 
					{  
						$result[] = $name; 
					}  
				}  
			}  
		}  
		closedir($handle); 
		return $result;  
	}  

	// traces recursivly parameters and adds them as child to parent
	// returns true if a parameter is tainted by userinput
	function scan_parameter($file_name, $mainparent, $parent, $var_name, $var_declares, $last_token_id, $var_declares_global, $function_params, $function_obj, $userinput, $F_SECURES, $return_scan=false, $ignore_securing=false)
	{	
		$vardependent = false;
		$ignore_var = '';

		$arrayname = explode('[', $var_name);

		// if $array[key] was not declared explicitly scan for $array
		if(isset($arrayname[1]))
		{
			if($arrayname[0] == '$GLOBALS' && !isset($var_declares[$var_name]) && !empty($arrayname[1]) ) 
			{
				$var_name = '$'. str_replace(array('"', "'", ']'), '', $arrayname[1]);
				// php $GLOBALS: ignore previous local vars and take only global vars
				$var_declares = $var_declares_global;
			}
			else if($arrayname[0] == '$_SESSION' && !isset($var_declares[$var_name]) && !empty($arrayname[1]))
			{
				// $_SESSION data is handled as global variables
				$var_declares = array_merge($var_declares_global, $var_declares);
			}
			// if array[key] was not defined, scan for array itself
			else if(!isset($var_declares[$var_name]) )
				$var_name = $arrayname[0]; 
		}

		// check if var declaration could be found for this var
		if( isset($var_declares[$var_name]) )
		{	
			foreach($var_declares[$var_name] as $var_declare)
			{	
				$line_nr = $var_declare->line;
				$line = $var_declare->value;
				$token_id = $var_declare->id;

				if( $token_id < $last_token_id )
				{	
					// add line to output
					if(count($mainparent->lines) < $GLOBALS['maxtrace'])				
					{
						$foundvalue = $line;
						if(	count($mainparent->dependencies) < 
							count($var_declare->dependencies))
						{							
							foreach($var_declare->dependencies as $deplinenr=>$dependency)
							{
								if( !isset($mainparent->dependencies[$deplinenr]) && $deplinenr != $line_nr )
								{
									$vardependent = true;
									$foundvalue = $foundvalue.' // '.trim($dependency);
								}
							}
						}

						$mainparent->lines[] = $line_nr;	
						$var_trace = new VarDeclare('');
						$parent->children[] = $var_trace;
					} else
					{	
						$stop = new VarDeclare('... Trace stopped.');
						$parent->children[] = $stop; 
						return $userinput;
					}
						
					// find other variables in this line
					$tokens = token_get_all('<?'.trim($line).'?>');
					$tokens = prepare_tokens($tokens, $GLOBALS['T_IGNORE']);
					$last_scanned = '';
					$last_userinput = false;
					$in_arithmetic = false;
					$in_securing = false;
					$parentheses_open = 0;
					$parentheses_save = -1;
					
					$tainted_vars = array();
					$var_count = 1;
					
					for($i=1, $maxtokens=count($tokens); $i<$maxtokens; $i++)
					{
						if( is_array($tokens[$i]) )
						{
							// if token is variable
							if( $tokens[$i][0] === T_VARIABLE 
							&& $tokens[$i][1] !== $ignore_var )
							{	
								$var_count++;
								
								$new_token_trace = $tokens[$i][1];

								// trace $var['keyname'] (if available) not only $var
								if($tokens[$i+1] === '['
								&& isset($tokens[$i+2][1])
								&& (isset($var_declares[$new_token_trace.'['.$tokens[$i+2][1].']'])
								|| in_array($new_token_trace, $GLOBALS['V_USERINPUT']) 
								|| $new_token_trace === '$GLOBALS'))
								{
									$new_token_trace = $new_token_trace.'['.$tokens[$i+2][1].']';
								}								
								
								// global $varname
								if( is_array($tokens[$i-1])
								&& $tokens[$i-1][0] === T_GLOBAL )
								{
									// scan in global scope
									$userinput = scan_parameter($file_name, $mainparent, $var_trace, 
								$new_token_trace, $var_declares_global, $token_id, 
								$var_declares_global, $function_params, $function_obj, $userinput,
								$F_SECURES, $return_scan, $ignore_securing);
								// scan in local scope
								} else
								{
									$userinput = scan_parameter($file_name, $mainparent, $var_trace, 
								$new_token_trace, $var_declares, $token_id, 
								$var_declares_global, $function_params, $function_obj, $userinput,
								$F_SECURES, $return_scan, $ignore_securing);
								}
							
								// check if typecast or securing function wrapped
								if((is_array($tokens[$i-1]) 
								&& in_array($tokens[$i-1][0], $GLOBALS['T_CASTS']))
								|| (is_array($tokens[$i+1]) 
								&& in_array($tokens[$i+1][0], $GLOBALS['T_CASTS'])) 
								|| $in_securing )
								{
									// mark user function as a securing user function
									$GLOBALS['userfunction_secures'] = true;

									$var_trace->marker = 2;
									
									if( $GLOBALS['verbosity'] < 3 && !$last_userinput ) 
									{
										$userinput = false;
									}	
								} 
								
								// check for automatic typecasts by arithmetic
								if(in_array($tokens[$i-1], $GLOBALS['T_ARITHMETIC'])
								|| in_array($tokens[$i+1], $GLOBALS['T_ARITHMETIC'])
								|| $in_arithmetic)
								{
									// mark user function as a securing user function
									$GLOBALS['userfunction_secures'] = true;

									$in_arithmetic = true;
									
									$var_trace->marker = 2;
									
									if( $GLOBALS['verbosity'] < 3 && !$last_userinput ) 
									{
										$userinput = false;
									}
								}
									
								// add tainted variable to the list to get them highlighted in output
								if($userinput && !$last_userinput)
								{
									$tainted_vars[] = $var_count;
								}
							}
							// if in foreach($bla as $key=>$value) dont trace $key, $value back
							else if( $tokens[$i][0] === T_AS )
							{
								break;
							}
							// if tokens is mathematical assignment like $a.=$b, trace $a again
							else if( in_array($tokens[$i][0], $GLOBALS['T_ASSIGNMENT']) )
							{
								$tokens = array_merge(
									array_slice($tokens, 0, $i), 
									array('='), array($tokens[$i-1]),
									array_slice($tokens, $i+1)
								);	
								$maxtokens = count($tokens);
							} 
							// also check for userinput from functions defined as userinput
							// depending on verbosity level
							else if( in_array($tokens[$i][1], $GLOBALS['F_USERINPUT']) )
							{
								$userinput = true;
								$var_trace->marker = 4;
	
								if($return_scan)
								{
									$GLOBALS['userfunction_taints'] = true;
								}	
								// userinput received in function, just needs a trigger
								else if($function_obj !== null)
								{
									addtriggerfunction($mainparent, $function_obj, $file_name);
								}	
								
								// we could return here to not scan all parameters of the tainting function
								// however we need to add the line manually to the output at this point
							}
							// detect securing functions
							else if(!$ignore_securing && (in_array($tokens[$i][1], $F_SECURES)
							|| (isset($tokens[$i][1]) && in_array($tokens[$i][1], $GLOBALS['F_SECURING_STRING']))) )
							{
								$parentheses_save = $parentheses_open;
								$in_securing = true;
							}
							//detect insecuring functions (functions that make previous securing useless)
							else if( isset($tokens[$i][1]) && in_array($tokens[$i][1], $GLOBALS['F_INSECURING_STRING']))
							{
								$parentheses_save = $parentheses_open;
								$ignore_securing = true;
							}
							// if this is a vuln line, it has already been scanned -> return
							else if( in_array($tokens[$i][0], $GLOBALS['T_FUNCTIONS']) 
							&& isset($GLOBALS['scan_functions'][$tokens[$i][1]]) 
							// ignore oftenly used preg_replace() and alike
							&& !isset($GLOBALS['F_CODE'][$tokens[$i][1]]) )
							{
								$var_trace->value = highlightline($foundvalue.' // stopped, already traced', $line_nr);
								$var_trace->line = $line_nr;
								return $userinput;
							}
						}
						// string concat disables arithmetic
						else if($tokens[$i] === '.')
						{
							$in_arithmetic = false;
						}
						// watch opening parentheses
						else if($tokens[$i] === '(')
						{
							$parentheses_open++;
						}
						// watch closing parentheses
						else if($tokens[$i] === ')')
						{
							$parentheses_open--;
							if($parentheses_open === $parentheses_save)
							{
								$parentheses_save = -1;
								$in_securing = false;
								$ignore_securing = false;
							}
						}						
						// special case for var declaration in constructs
						else if( is_array($tokens[$i-1]) )
						{
							// assignments in a if()/while() need to skip the var declaring name
							if( $tokens[$i-1][0] === T_IF || $tokens[$i-1][0] === T_WHILE)
							{
								// if($h = fopen($asd)) , $h should not be traced back
								$i+=2;
							}
							// ignore first variable in for($i=0;...)
							else if( $tokens[$i-1][0] === T_FOR )
							{
								$ignore_var = $tokens[$i+1][1];
							}
						}
											
						// save userinput (true|false) for vars in same line
						$last_userinput = $userinput;
					}

					// add highlighted line to output, mark tainted vars
					$var_trace->value = highlightline($foundvalue, $line_nr, false, false, $tainted_vars);
					$var_trace->line = $line_nr;
					
					// we only need the last var declaration, other declarations have been overwritten
					if( $userinput || !$vardependent ) 
						break;
				}
			}
		}
		// if var comes from function parameter
		if( in_array($arrayname[0], $function_params) )
		{
			// add child with function declaration
			$func_name = $function_obj->name;	
			$mainparent->lines[] = $function_obj->lines[0];
			if($function_obj->marker !== 3)
			{
				$function_obj->value = makefunclink($function_obj->value, $function_obj->lines[0], $function_obj->name);
				// mark as potential userinput
				$function_obj->marker = 3;
			}
			$parent->children[] = $function_obj;
			$mainparent->title = $mainparent->title . " in user defined function <i>$func_name</i> (click declaration to jump to call)";
			
			// add function to scanlist
			$key = array_search($arrayname[0], $function_params);
			$mainparent->funcdepend = $func_name;
			// with potential parameters
			$GLOBALS['user_functions'][$file_name][$func_name][0][$key] = $key+1;
			// and with according securing functions from original find					
			$GLOBALS['user_functions'][$file_name][$func_name][1] = isset($GLOBALS['scan_functions'][$mainparent->name]) ? 
				$GLOBALS['scan_functions'][$mainparent->name][1] : $GLOBALS['user_functions'][$file_name][$mainparent->name][1];
	
			$userinput = true;
		}			
		// if var is userinput, return true directly	
		if( in_array($arrayname[0], $GLOBALS['V_USERINPUT']) )
		{
			// check if userinput variable has been overwritten
			$overwritten = false;
			if(isset($var_declares[$arrayname[0].'['.$arrayname[1]]))
			{
				foreach($var_declares[$arrayname[0].'['.$arrayname[1]] as $var)
				{
					// if there is a var declare for this userinput !except the same line!: overwritten
					if($last_token_id != $var->id)
						$overwritten = true;
				}
			}	
			
			if(!$overwritten)
			{
				// add userinput markers to mainparent object
				if(isset($arrayname[1]))
					$parameter_name = str_replace(array('"', "'", ']'), '', $arrayname[1]);
				
				// mark tainted, but only specific $_SERVER parameters
				if($arrayname[0] !== '$_SERVER'
				|| in_array($parameter_name, $GLOBALS['V_SERVER_PARAMS']) )
				{
					$userinput = true;
					$parent->marker = 1;			

					if(!empty($parameter_name))
					{
						switch($arrayname[0])
						{
							case '$_GET': 				$mainparent->get[] = $parameter_name; break;
							case '$HTTP_GET_VARS': 		$mainparent->get[] = $parameter_name; break;
							case '$_REQUEST': 			$mainparent->get[] = $parameter_name; break;
							case '$HTTP_REQUEST_VARS':	$mainparent->get[] = $parameter_name; break;
							case '$_POST': 				$mainparent->post[] = $parameter_name; break;
							case '$HTTP_POST_VARS':		$mainparent->post[] = $parameter_name; break;
							case '$HTTP_RAW_POST_DATA':	$mainparent->post[] = $parameter_name; break;
							case '$_COOKIE': 			$mainparent->cookie[] = $parameter_name; break;
							case '$HTTP_COOKIE_VARS':	$mainparent->cookie[] = $parameter_name; break;
							case '$_FILES': 			$mainparent->files[] = $parameter_name; break;
							case '$HTTP_POST_FILES':	$mainparent->files[] = $parameter_name; break;
							case '$_SERVER':			$mainparent->server[] = $parameter_name; break;
						}
					}
				}
							
				// userinput received in function, just needs a trigger
				if($function_obj !== null && !$return_scan)
				{
					addtriggerfunction($mainparent, $function_obj, $file_name);
				}
			}
		} 
				
		return $userinput;
	}
	
	// add function to output that triggers something by call
	function addtriggerfunction($mainparent, $function_obj, $file_name)
	{
		// add dependency and mark this as interesting function
		$func_name = $function_obj->name;
		$mainparent->dependencies[$function_obj->lines[0]] = $function_obj->value;
		$mainparent->title = $mainparent->title . " (triggered by function call <i>$func_name()</i>)";
		
		// add function to scanlist
		$mainparent->funcdepend = $func_name;
		// with all parameters as valuable since userinput comes from inside the func
		$GLOBALS['user_functions'][$file_name][$func_name][0][0] = 0;
		// no securings				
		$GLOBALS['user_functions'][$file_name][$func_name][1] = array();
		// doesnt matter if with userinput called or not
		$GLOBALS['user_functions'][$file_name][$func_name][3] = true;
	}
	
	// traces values of variables for dynamic file includes
	function get_var_value($var_name, $var_declares, $var_declares_global, $last_token_id)
	{
		$var_value = '';
		if(isset($var_declares['$'.$var_name]))
		{
			$var_name = '$'.$var_name;
		}
		// check if var declaration could be found for this var
		if( isset($var_declares[$var_name]) )
		{
			foreach($var_declares[$var_name] as $var_declare)
			{
				$token_id = $var_declare->id;

				if( $token_id < $last_token_id )
				{
					$line = $var_declare->value;
											
					// find other variables in this line
					$tokens = token_get_all('<?'.trim($line).'?>');
					$tokens = prepare_tokens($tokens, $GLOBALS['T_IGNORE']);
					
					for($i=($tokens[1] === '[') ? 3:1, $max=count($tokens); $i<$max; $i++)
					{
						if( is_array($tokens[$i]) )
						{
							$token_name = $tokens[$i][0];
							$token_value = $tokens[$i][1];

							// if token is variable trace again
							if( $token_name === T_VARIABLE )
							{	
								$var_trace = $token_value;
								// trace $var['keyname'] (if available) not only $var
								if($tokens[$i+1] === '['
								&& isset($var_declares[$var_trace.'['.$tokens[$i+2][1].']']) 
								|| $var_trace === '$GLOBALS' )
								{
									$var_trace = $var_trace.'['.$tokens[$i+2][1].']';
									$i=$i+2;
								}								
								
								// global $varname -> global scope
								if( is_array($tokens[$i-1]) && $tokens[$i-1][0] === T_GLOBAL )
								{
									$var_value.= get_var_value($var_trace, 
									$var_declares_global, $var_declares_global, $token_id);
								} 
								// local scope
								else
								{
									$var_value.= get_var_value($var_trace, 
									$var_declares, $var_declares_global, $token_id);
								}
							}
							
							// if token is string add string to output 
							// except first string of define('var', 'value')
							else if( $token_name === T_CONSTANT_ENCAPSED_STRING
							&& !($tokens[$i-2][0] === T_STRING
							&& $tokens[$i-2][1] === 'define'))
							{
								$var_value.= str_replace(array('"', "'"), '', $token_value);
							}
							// try to guess constants
							else if( $token_name === T_STRING 
							&& !($tokens[$i-2][0] === T_STRING
							&& $tokens[$i-2][1] === 'define'))
							{							
								if ($token_value == 'DIRECTORY_SEPARATOR' || $token_value == 'PATH_SEPARATOR')
								{
									$var_value.='/';
								}
								else if( isset($var_declares['$'.$token_value]) )
								{
									$var_value.= get_var_value('$'.$token_value, 
									$var_declares, $var_declares_global, $token_id);
								}
							}
						}
					}
				}
				break;
			}
		}
		return $var_value;
	}
		
	// fetches a line from the sourcecode and checks for commands written over several lines	
	function getmultiline($lines_pointer, $linenr)
	{
		$line = trim($lines_pointer[$linenr]);
		$i = strlen($line)-1;
		if($i>0 && $line[$i] != ';' && $line[$i] != ')' /* && $line[$i] != '(' */
		&& $line[$i] != '{' && $line[$i] != '}' && !strpos($line, '?>'))
		{
			$line .= getmultiline($lines_pointer, $linenr+1);
		}
		return $line;
	}	
			
	// scans tokens of php file for function calls and watches dependencies	
	function scan_file($file_name, $scan_functions, 
	$T_FUNCTIONS, $T_ASSIGNMENT, $T_IGNORE, $T_INCLUDES, $T_XSS, $T_IGNORE_STRUCTURE)
	{
		$var_declares_global = array();	
		$var_declares_local = array();
		$put_in_global_scope = array();
		$globals_from_function = array();
		$dependencies = array();
		$exit_functions = array();
		$vuln_classes = array();
		$class_vars = array();
		$braces_open = 0;
		$brace_save_func = -1;
		$brace_save_class = -1;
		$ignore_requirement = false;
		$in_function = false;
		$in_class = false;
		$comment = '';
		$inc_file = '';
		$inc_file_stack = array();
		$inc_map = array();
		
		$lines_stack = array();
		$lines_stack[] = file($file_name);
		// pointer to current lines set
		$lines_pointer =& end($lines_stack);
		
		$code = implode('',$lines_pointer);
		$tokens = token_get_all($code);	
		$tokens = prepare_tokens($tokens, $T_IGNORE);
		$tokens = fix_tokens($tokens);
		
		$GLOBALS['counterlines']+=count($lines_pointer);	
	
		// scan all tokens of file
		for($i=0,$tokencount=count($tokens); $i<$tokencount;  $i++)
		{	
			$token = $tokens[$i];
			
			if( is_array($token) )
			{
				$token_name = $token[0];
				$token_value = $token[1];
				$line_nr = $token[2];
				
				# debug
				#echo "file:".$file_name.",line:".$line_nr.",token:".token_name($token_name).",";
				#echo "value:".htmlentities($token_value).",";
				#echo "in_function:".$in_function.",in_class:".$in_class."<br>";

			// include tokens from included files, only static includes supported
				if( in_array($token_name, $T_INCLUDES) && !$in_function)
				{
					// save found				
					$found_line = trim($lines_pointer[$line_nr-1])."\t".$comment;
					$last_inc_file = $inc_file;	
					
					$GLOBALS['count_inc']++;
	
					// include('xxx')
					if ( (($tokens[$i+1] === '(' 
						&& $tokens[$i+2][0] === T_CONSTANT_ENCAPSED_STRING
						&& $tokens[$i+3] === ')')
					// include 'xxx'
					|| (is_array($tokens[$i+1])
						&& $tokens[$i+1][0] === T_CONSTANT_ENCAPSED_STRING
						&& $tokens[$i+2] === ';' )) )
					{					
						// include('file')
						if($tokens[$i+1] === '(')
						{
							$inc_file = substr($tokens[$i+2][1], 1, -1);
							$skip = 5;
						}
						// include 'file'
						else
						{
							$inc_file = substr($tokens[$i+1][1], 1, -1);
							$skip = 3;
						}	
					}
					// dynamic include
					else
					{
						$inc_file = '';
						$c = 1;
						// check all tokens until include statement ends
						while( $tokens[$i +$c] !== ';' )
						{
							if( is_array($tokens[$i +$c]) )
							{		
								// trace variables for its values
								if( $tokens[$i +$c][0] === T_VARIABLE 
								|| ($tokens[$i +$c][0] === T_STRING 
								&& $tokens[$i +$c +1] !== '(' ) )
								{
									$var_trace = $tokens[$i +$c][1];

									// trace $var['keyname'] (if available) not only $var
									if($tokens[$i +$c +1] === '[')
									{
										$var_trace = $var_trace.'['.$tokens[$i +$c +2][1].']';
										$i=$i+2;
									}
									
									if(!$in_function)
										$inc_file .= get_var_value($var_trace, 
										$var_declares_global, $var_declares_global, $i);
									else
										$inc_file .= get_var_value($var_trace, 
										$var_declares_local, $var_declares_global, $i);
								}
								// add strings to include file name
								else if( $tokens[$i + $c][0] === T_CONSTANT_ENCAPSED_STRING )
								{
									$inc_file .= str_replace(array('"', "'"), '', $tokens[$i + $c][1]);
								}
							}
							if($c>50)break;
							$c++;
						}	
						$skip = $c+1;
					}
					
					// if file name has not been included
					if( !in_array($inc_file, $inc_file_stack) )
					{
						$try_file = dirname($file_name). '/' . $inc_file;
						// try to open include file name
						if ( $inc_lines = @file( $try_file ) )
						{		
							$include = '// successfully analysed';
							$GLOBALS['counterlines']+=count($inc_lines);
						
							$inc_code = implode('',$inc_lines);
							$inc_tokens = token_get_all($inc_code);	
							$inc_tokens = prepare_tokens($inc_tokens, $T_IGNORE);

							// insert included tokens in current tokenlist and mark end
							$tokens = array_merge(
								array_slice($tokens, 0, $i), 					// before include
								$inc_tokens, 									// included tokens
								array(array(T_INCLUDE_END, 0, $inc_file)), 		// extra END-identifier
								array_slice($tokens, $i+$skip) 					// after include
							);

							$tokencount = count($tokens);
							
							// set lines pointer to included lines, save last pointer
							// (the following tokens will be the included ones)
							$lines_stack[] = $inc_lines;
							$lines_pointer =& end($lines_stack);
												
							$comment = '// '.basename($inc_file);
						
							$inc_file_stack[] = $inc_file;	

							// build include map for file list
							$inc_map[] = $try_file; // all basic includes
							
							// decrease token counter because we replaced the include with included tokens
							// and dont wont to miss the first token of these
							$i--;
						} 
						// included file name could not be reversed 
						// (probably dynamic with function calls)
						else
						{
							$include = "// could not analyse file, tried: $try_file";
							$GLOBALS['count_inc_fail']++;
							$inc_file = $last_inc_file;
						}
					}
					else
					{
						$include = "// $inc_file has already been included";
						$inc_file = $last_inc_file;
					}
					
					// add information about include success
					if( $GLOBALS['verbosity'] >= 4 )
					{
						// add include command to output
						$found_value = highlightline(trim($found_line)."\t".$include, $line_nr, $token_value);
						$new_find = new InfoTreeNode($found_value);
						$new_find->line = $line_nr;

						// if in included code, set file name
						if(!empty($last_inc_file))
							$new_find->filename = dirname($file_name) . '/' . $last_inc_file;
						
						$id = (isset($GLOBALS['output'][$file_name])) ? 
							count($GLOBALS['output'][$file_name]) : 0;
						$GLOBALS['output'][$file_name][$id] = $new_find;
					}
					
					// if successfully included, dont check further for file inclusion vulnerability
					if($include == '// successfully analysed')
					{
						continue;
					}
				}
	
			// check for XSS vulns
				if( in_array($token_name, $T_XSS) 
				&& ($_POST['vector'] == 'client' || $_POST['vector'] == 'all') )
				{				
					if($token_name === T_OPEN_TAG_WITH_ECHO)
						$token_value = 'echo';
				
					// build new find					 
					$new_find = new VulnTreeNode();
					$new_find->name = $token_value;
					$new_find->title = 'Cross-Site Scripting';
					$new_find->lines[] = $line_nr;
					
					// if in included code, set file name
					if(!empty($inc_file))
						$new_find->filename = dirname($file_name) . '/' . $inc_file;
				
					// add dependencies
					foreach($dependencies as $deplinenr=>$dependency)
					{
						$new_find->dependencies[$deplinenr] = $dependency;
					}
				
					$c = 1;
					$has_vuln_parameters = false;
					$parameter_has_userinput = false;
					$secured_by_start = false;
					$tainted_vars = array();
					$var_count = 0;

					while( $tokens[$i + $c] !== ';' )
					{
						$this_one_is_secure = false;
						if( $tokens[$i + $c][0] === T_VARIABLE )
						{
							$var_count++;
						
							if( (is_array($tokens[$i + $c -2]) 
							&& (in_array($tokens[$i + $c -2][1], $GLOBALS['F_SECURING_STRING']) 
							|| in_array($tokens[$i + $c -2][1], $GLOBALS['F_SECURING_XSS'])))
							|| in_array($tokens[$i + $c -1][0], $GLOBALS['T_CASTS']) )
							{
								$secured_by_start = true;
								$this_one_is_secure = true;
							}
							$has_vuln_parameters = true;
							
							$trace_par_var = $tokens[$i + $c][1];
							
							// $var['keyname'] should be directly traced, not $var
							if($tokens[$i + $c +1] === '[')
							{
								$trace_par_var = $trace_par_var.'['.$tokens[$i + $c +2][1].']';
							}
							
							// trace back parameters and look for userinput
							if($in_function)
							{
								$userinput = scan_parameter($file_name, $new_find, $new_find, 
								$trace_par_var, $var_declares_local, $i+$c, 
								$var_declares_global, $function_params, $function_obj, 
								false, $GLOBALS['F_SECURING_XSS']);
							} else 
							{
								$userinput = scan_parameter($file_name, $new_find, $new_find, 
								$trace_par_var, $var_declares_global, $i+$c, 
								null, array(), null, false, $GLOBALS['F_SECURING_XSS']);
							}
				
							if($userinput && (!$this_one_is_secure || $GLOBALS['verbosity'] >= 3) )
							{
								$tainted_vars[] = $var_count;
								$parameter_has_userinput = true;
							}	
						} 
						if($c>50)break;
						$c++;
					}				

					// add find to output if function call has variable parameters (With userinput)
					if( ($has_vuln_parameters && $parameter_has_userinput) || $GLOBALS['verbosity'] >= 5 ) 
					{
						$GLOBALS['count_xss']++;
						$new_find->value = highlightline(getmultiline($lines_pointer, $line_nr-1)."\t".$comment, 
													$line_nr, $token_value, false, $tainted_vars);
						if($secured_by_start)
							$new_find->marker = 2;				
					
						$id = (isset($GLOBALS['output'][$file_name])) ? 
								count($GLOBALS['output'][$file_name]) : 0;
						$GLOBALS['output'][$file_name][$id] = $new_find;
						
						// mark function in class as vuln
						if($in_function && $in_class)
						{
							$vuln_classes[$class_name][] = $function_name;
						}

					}
					
				}
			
			// switch lines pointer back to original code if included tokens end
				else if( $token_name === T_INCLUDE_END)
				{
					array_pop($lines_stack);
					$lines_pointer =& end($lines_stack);			
					array_pop($inc_file_stack);
					$inc_file = end($inc_file_stack);
					$comment = '';
				}				
				
			// build list of all variable declarations
				else if( $token_name === T_VARIABLE
					&& ( $tokens[$i+1][0] === '=' || // normal assignment
					  (in_array($tokens[$i+1][0], $T_ASSIGNMENT))  // mathematical assignment
					  || ($tokens[$i-1][0] === T_AS // foreach($var as $key=>$value)
					   || ($tokens[$i-1][0] === T_DOUBLE_ARROW
					    && $tokens[$i-2][0] === T_VARIABLE)) 
					   || ($tokens[$i+1] === '['  // $foo['a'], hard to check all keys and assignments
					   // example: $a[0][$i+$k] &= $_GET['a'];
					   // easier: the last token was an ending statement or beginning of the file
					   && ($tokens[$i-1] === '}' || $tokens[$i-1] === '{' 
						|| $tokens[$i-1] === ';' || !isset($tokens[$i-1][0]))) 
					  ) 
				)
				{	
					// add variable declaration to beginning of varlist
					$new_var = new VarDeclare(getmultiline($lines_pointer, $line_nr-1)."\t".$comment);
					$new_var->line = $line_nr;
					$new_var->id = $i;
						
					$new_token_value = $token_value;
					
					// add dependencies
					foreach($dependencies as $deplinenr=>$dependency)
					{
						$new_var->dependencies[$deplinenr] = $dependency;
					}

					// save $var['keyname'] not only $var
					if($tokens[$i+1] === '[' 
					&& is_array($tokens[$i+2]) 
					&& ($tokens[$i+2][0] === T_CONSTANT_ENCAPSED_STRING
					 || $tokens[$i+2][0] === T_LNUMBER)
					&& $tokens[$i+3] === ']')
					{		
						// first save array name
						// in global varlist or local (in function) varlist
						if($in_function)
						{
							if(!isset($var_declares_local[$new_token_value]))
								$var_declares_local[$new_token_value] = array($new_var);
							else
								array_unshift($var_declares_local[$new_token_value], $new_var);
						} else
						{
							if(!isset($var_declares_global[$new_token_value]))
								$var_declares_global[$new_token_value] = array($new_var);
							else
								array_unshift($var_declares_global[$new_token_value], $new_var);
						}
					
						$new_token_value = $token_value.'['.$tokens[$i+2][1].']';
					}
					
					// global varlist or local (in function) varlist
					if($in_function)
					{
						if(!isset($var_declares_local[$new_token_value]))
							$var_declares_local[$new_token_value] = array($new_var);
						else
							array_unshift($var_declares_local[$new_token_value], $new_var);
						
						// if variable was put in global scope, save assignments
						// later they will be pushed to the global var list when function is called
						if(in_array($new_token_value, $put_in_global_scope))
						{
							if(!isset($globals_from_function[$function_name][$new_token_value]))
								$globals_from_function[$function_name][$new_token_value] = array($new_var);
							else
								array_unshift($globals_from_function[$function_name][$new_token_value], $new_var);
						}
					} else
					{
						if(!isset($var_declares_global[$new_token_value]))
							$var_declares_global[$new_token_value] = array($new_var);
						else
							array_unshift($var_declares_global[$new_token_value], $new_var);
					}
					$i++;
					
				}
				
			// add user input variables to global finding list
				else if($token_name === T_VARIABLE && in_array($token_value, $GLOBALS['V_USERINPUT']))
				{
					$file_finding = (!empty($inc_file)) ? dirname($file_name) . '/' . $inc_file : $file_name;

					if($tokens[$i+1] === '[' && $tokens[$i+2][0] === T_CONSTANT_ENCAPSED_STRING)
						$GLOBALS['user_input'][$token_value.'['.$tokens[$i+2][1].']'][$file_finding][] = $line_nr;	
					else
						$GLOBALS['user_input'][$token_value][$file_finding][] = $line_nr;	
				}
			
			// dynamic function call $bla()
				else if($token_name === T_VARIABLE && $tokens[$i+1][0] === '(')
				{
					// build new find					 
					$new_find = new VulnTreeNode();
					$new_find->name = '$variable';
					$new_find->title = 'Dynamic Function Call (Remote Code Execution)';
					$new_find->lines[] = $line_nr;
					
					// if in included code, set file name
					if(!empty($inc_file))
						$new_find->filename = dirname($file_name) . '/' . $inc_file;
				
					// add dependencies
					foreach($dependencies as $deplinenr=>$dependency)
					{
						$new_find->dependencies[$deplinenr] = $dependency;
					}
					
					// trace back parameters and look for userinput
					if($in_function)
					{
						$userinput = scan_parameter($file_name, $new_find, $new_find, 
						$token_value, $var_declares_local, $i, 
						$var_declares_global, $function_params, $function_obj, 
						false, array());
					} else 
					{
						$userinput = scan_parameter($file_name, $new_find, $new_find, 
						$token_value, $var_declares_global, $i, 
						null, array(), null, false, array());
					}
					
					// add find to output if function call has variable parameters (With userinput)
					if( $userinput || $GLOBALS['verbosity'] >= 5 ) 
					{
						$GLOBALS['count_code']++;
						$new_find->value = highlightline(getmultiline($lines_pointer, $line_nr-1)."\t".$comment, 
													$line_nr, $token_value, false, $tainted_vars);		
					
						$id = (isset($GLOBALS['output'][$file_name])) ? 
								count($GLOBALS['output'][$file_name]) : 0;
						$GLOBALS['output'][$file_name][$id] = $new_find;
						
						// mark function in class as vuln
						if($in_function && $in_class)
						{
							$vuln_classes[$class_name][] = $function_name;
						}

					}
				}
			
			// add globaled variables (global $a, $b, $c;) to var list	
				else if($token_name === T_GLOBAL && $in_function)
				{
					$globals_from_function[$function_name] = array();
					
					// get all globaled variables 
					$b=1;
					while($tokens[$i + $b] !== ';')
					{
						if( $tokens[$i + $b][0] === T_VARIABLE )
						{
							$var_value = $tokens[$i + $b][1];
							// mark variable as global scope affecting
							$put_in_global_scope[] = $var_value;
							// add variable declaration to beginning of varlist
							$new_var = new VarDeclare("global $var_value;\t".$comment);
							$new_var->line = $line_nr;
							$new_var->id = $i;
							
							$var_declares_local[$var_value] = array($new_var);
						}
						if($b>50)break;
						$b++;
					}
				}
				
			// define("FOO", $_GET['asd']);
				else if($token_name === T_STRING && $token_value === 'define')
				{
					// add variable declaration to beginning of varlist
					$new_var = new VarDeclare(getmultiline($lines_pointer, $line_nr-1)."\t".$comment);
					$new_var->line = $line_nr;
					$new_var->id = $i;
					
					// add dependencies
					foreach($dependencies as $deplinenr=>$dependency)
					{
						$new_var->dependencies[$deplinenr] = $dependency;
					}
					
					$token_value = '$'.str_replace(array('"', "'"), '', $tokens[$i+2][1]);
					
					// global varlist or local (in function) varlist
					if($in_function)
					{
						if(!isset($var_declares_local[$token_value]))
							$var_declares_local[$token_value] = array($new_var);
						else
							array_unshift($var_declares_local[$token_value], $new_var);
					} else
					{
						if(!isset($var_declares_global[$token_value]))
							$var_declares_global[$token_value] = array($new_var);
						else
							array_unshift($var_declares_global[$token_value], $new_var);
					}
				}
				
			// $array = compact("event", "city");
				else if($token_name === T_STRING && $token_value === 'compact' && $tokens[$i-2][0] === T_VARIABLE)
				{
					$f=2;
					while( $tokens[$i+$f] !== ')' )
					{	
						// for all array keys save new variable declarations
						if($tokens[$i+$f][0] === T_CONSTANT_ENCAPSED_STRING)
						{
							$token_value = $tokens[$i-2][1].'['.$tokens[$i+$f][1].']';
						
							// add variable declaration to beginning of varlist
							$new_var = new VarDeclare($token_value.' = $'.
									str_replace(array('"', "'"), '', $tokens[$i+$f][1]).";\t //".
									getmultiline($lines_pointer, $line_nr-1));
							$new_var->line = $line_nr;
							$new_var->id = $i;
							
							// add dependencies
							foreach($dependencies as $deplinenr=>$dependency)
							{
								$new_var->dependencies[$deplinenr] = $dependency;
							}
					
							// global varlist or local (in function) varlist
							if($in_function)
							{
								if(!isset($var_declares_local[$token_value]))
									$var_declares_local[$token_value] = array($new_var);
								else
									array_unshift($var_declares_local[$token_value], $new_var);
							} else
							{
								if(!isset($var_declares_global[$token_value]))
									$var_declares_global[$token_value] = array($new_var);
								else
									array_unshift($var_declares_global[$token_value], $new_var);
							}
						}
						if($f>50)break;
						$f++;
					}
				}	
							
			// list($drink, $color, $power) = $info;
				else if($token_name === T_LIST)
				{			
					$c=2;
					while( $tokens[$i + $c] !== ')' )
					{
						if( is_array($tokens[$i + $c]) 
						&& $tokens[$i + $c][0] === T_VARIABLE )
						{
							$token_value = $tokens[$i + $c][1];
							
							// add variable declaration to beginning of varlist
							$new_var = new VarDeclare(getmultiline($lines_pointer, $tokens[$i + $c][2]-1));
							$new_var->line = $tokens[$i + $c][2];
							$new_var->id = $i;
														
							// global varlist or local (in function) varlist
							if($in_function)
							{
								if(!isset($var_declares_local[$token_value]))
									$var_declares_local[$token_value] = array($new_var);
								else
									array_unshift($var_declares_local[$token_value], $new_var);
							} else
							{
								if(!isset($var_declares_global[$token_value]))
									$var_declares_global[$token_value] = array($new_var);
								else
									array_unshift($var_declares_global[$token_value], $new_var);
							}
						}
						if($c>50)break;
						$c++;
					}	
					$i=$i+$c+2;
				}	
				
			// add interesting function calls to output (info gathering)	
				else if( isset($GLOBALS['F_INTEREST'][$token_value]) && $GLOBALS['verbosity'] >= 4 )
				{
					// add include command to output
					$new_find = new InfoTreeNode(
						highlightline(getmultiline($lines_pointer, $line_nr-1)."\t$comment // ".$GLOBALS['F_INTEREST'][$token_value], $line_nr, $token_value)
					);
					$new_find->line = $line_nr;
					
					// if in included code, set file name
					if(!empty($inc_file))
						$new_find->filename = dirname($file_name) . '/' . $inc_file;

					// add dependencies
					foreach($dependencies as $deplinenr=>$dependency)
					{
						$new_find->dependencies[$deplinenr] = $dependency;
					}	
					
					$id = (isset($GLOBALS['output'][$file_name])) ? 
							count($GLOBALS['output'][$file_name]) : 0;
					$GLOBALS['output'][$file_name][$id] = $new_find;
				}	
				
			// check if token is a function call and a function to scan
				else if( in_array($token_name, $T_FUNCTIONS) 
					   && isset($scan_functions[$token_value]) )
				{						
					// prevent alerts with wrong classes (same function name in classes)
					// $classvar->func();
					if($tokens[$i-1][0] === T_OBJECT_OPERATOR)
					{
						$classvar = $tokens[$i-2][1];
						if(substr($classvar,0,1) !== '$')
							$classvar = '$'.$classvar;
						$class = $class_vars[$classvar];

						if(!($in_function && in_array($classvar, $function_params))
						&& !@in_array($token_value, $vuln_classes[$class]) )
						{
							continue;					
						}
					}
					// check if function call is a standalone or not
					else if($tokens[$i-1] === '=' || $tokens[$i-1] === ')' || $tokens[$i-1] === ',')
					{
						$var_count = 1;
					} else
					{
						$var_count = 0;
					}
					
					// add function call to user-defined function list
					$class = !empty($class) ? $class.'::' : '';
					if(isset($GLOBALS['user_functions_offset'][$class.$token_value]))
					{
						$GLOBALS['user_functions_offset'][$class.$token_value][3][] = array(
							(!empty($inc_file) ? dirname($file_name).'/'.$inc_file : $file_name), 
							$line_nr
						);
					}
	
					// build new find					 
					$new_find = new VulnTreeNode();
					$new_find->name = $token_value;
					$new_find->lines[] = $line_nr;

					// if in included code, set file name
					if(!empty($inc_file))
						$new_find->filename = dirname($file_name) . '/' . $inc_file;
					
					// add dependencies
					foreach($dependencies as $deplinenr=>$dependency)
					{
						$new_find->dependencies[$deplinenr] = $dependency;
					}
				
					$c = 2;
					$parameter=1;
					$has_vuln_parameters = false;
					$parameter_has_userinput = false;
					$secured_by_start = false;
					$newbraceopen = ($tokens[$i+1] === '(') ? 1 : 0;
					$tainted_vars = array();
	
					// get all variables in parameter list between (...)
					// not only until ';' because: system(get($a),$b,strstr($c));
					while( !($newbraceopen === 0 || $tokens[$i + $c] === ';') )
					{
						$this_one_is_secure = false;
						if( is_array($tokens[$i + $c]) 
						&& $tokens[$i + $c][0] === T_VARIABLE )
						{
							$var_count++;
							// scan only potential vulnerable parameters of function call
							if ( in_array($parameter, $scan_functions[$token_value][0]) 
							|| (isset($scan_functions[$token_value][0][0])
								&& $scan_functions[$token_value][0][0] === 0) ) // all parameters accepted
							{
								if( (is_array($tokens[$i + $c -2]) 
								&& (in_array($tokens[$i + $c -2][1], $GLOBALS['F_SECURING_STRING']) 
								|| in_array($tokens[$i + $c -2][1], $scan_functions[$token_value][1])))
								|| in_array($tokens[$i + $c -1][0], $GLOBALS['T_CASTS']) )
								{
									$secured_by_start = true;
									$this_one_is_secure = true;
								}
								$has_vuln_parameters = true;
								
								$trace_par_var = $tokens[$i + $c][1];
								
								// $var['keyname'] should be directly traced, not $var
								if($tokens[$i + $c +1] === '[')
								{
									$trace_par_var = $trace_par_var.'['.$tokens[$i + $c +2][1].']';
								}
								
								// trace back parameters and look for userinput
								if($in_function)
								{
									$userinput = scan_parameter($file_name, $new_find, $new_find, 
									$trace_par_var, $var_declares_local, $i+$c, 
									$var_declares_global, $function_params, $function_obj, 
									false, $scan_functions[$token_value][1]);
								} else 
								{
									$userinput = scan_parameter($file_name, $new_find, $new_find, 
									$trace_par_var, $var_declares_global, $i+$c, 
									null, array(), null, false, $scan_functions[$token_value][1]);
								}
					
								if($userinput && (!$this_one_is_secure || $GLOBALS['verbosity'] >= 3) )
								{
									$parameter_has_userinput = true;
									$tainted_vars[] = $var_count;
								}	
							} 
						}
						// count parameters
						else if( $newbraceopen === 1 && $tokens[$i + $c] === ',' )
						{
							$parameter++;
						}
						// watch function calls in function call
						else if( $tokens[$i + $c] === '(' )
						{
							$newbraceopen++;
						}
						else if( $tokens[$i + $c] === ')' )
						{
							$newbraceopen--;
						}
						if($c>50)break;
						$c++;
					}				

					// add find to output if function call has variable parameters (With userinput)
					if( ($has_vuln_parameters && $parameter_has_userinput) || $GLOBALS['verbosity'] >= 5 
					|| isset($scan_functions[$token_value][3]) ) 
					{
						if(isset($GLOBALS['user_functions'][$file_name][$token_value]))
						{
							$found_line = '<A NAME="'.$token_value.'_call"></A>';
							$found_line.= highlightline(getmultiline($lines_pointer, $line_nr-1)."\t".$comment, 
													$line_nr, false, $token_value);
						} else
						{
							$found_line = highlightline(getmultiline($lines_pointer, $line_nr-1)."\t".$comment, 
													$line_nr, $token_value, false, $tainted_vars);
						}
						$new_find->value = $found_line;
					
						if($secured_by_start)
							$new_find->marker = 2; 

						// only show vuln user defined functions 
						// if call with userinput has been found
						if( isset($GLOBALS['user_functions'][$file_name][$token_value]) )
							$GLOBALS['user_functions'][$file_name][$token_value]['called'] = true;
						
						// mark function in class as vuln
						if($in_function && $in_class)
						{
							$vuln_classes[$class_name][] = $function_name;
						}
						
						// putenv with userinput --> getenv is treated as userinput
						if($token_value == 'putenv')
						{
							$GLOBALS['F_USERINPUT'][] = 'getenv';
							$new_find->title = 'User can set PHP enviroment variables. Adding getenv() to tainting functions';
						}
						else if($token_value == 'apache_setenv')
						{
							$GLOBALS['F_USERINPUT'][] = 'apache_getenv';
							$new_find->title = 'User can set Apache enviroment variables. Adding apache_getenv() to tainting functions';
						}
						else
						{
							$new_find->title = getVulnNodeTitle($token_value);
						}
					
						// add to output
						$id = (isset($GLOBALS['output'][$file_name])) ? 
								count($GLOBALS['output'][$file_name]) : 0;
						$GLOBALS['output'][$file_name][$id] = $new_find;
					}

					// if classvar depends on function parameter, add this parameter to list
					if( isset($classvar) && $in_function && in_array($classvar, $function_params) ) 
					{
						$param = array_search($classvar, $function_params);
						$GLOBALS['user_functions'][$file_name][$function_name][0][$param] = $param+1;
					} 
					
					// if securing was inside the function parameter trace
					if($in_function && $GLOBALS['userfunction_secures'] && $GLOBALS['verbosity'] < 3)
					{
						unset($GLOBALS['user_functions'][$file_name][$function_name]);
						$GLOBALS['userfunction_secures'] = false;
					}
				}
								
			// check if token is a function declaration
				else if($token_name === T_FUNCTION)
				{
					$in_function = true;

					// the next token is the "function name()"
					$i++;
					$function_name = isset($tokens[$i][1]) ? $tokens[$i][1] : $tokens[$i+1][1];
					// write to user_functions offset list for referencing in output
					$ref_name = ($in_class ? $class_name.'::' : '') . $function_name;
					$GLOBALS['user_functions_offset'][$ref_name][0] = !empty($inc_file) ? dirname($file_name).'/'.$inc_file : $file_name;
					$GLOBALS['user_functions_offset'][$ref_name][1] = $line_nr-1;
					// save function as object
					$function_obj = new FunctionDeclare(getmultiline($lines_pointer, $line_nr-1));
					$function_obj->lines[] = $line_nr; 
					$function_obj->name = $function_name;
					
					// save all function parameters
					$function_params = array();
					$e=1;
					// until function test(...) {
					//  OR
					// interface test { public function test(...); }
					while( $tokens[$i+$e] !== '{' && $tokens[$i+$e] !== ';' )
					{	
						if( is_array($tokens[$i + $e]) && $tokens[$i + $e][0] === T_VARIABLE )
						{
							$function_params[] = $tokens[$i + $e][1];
						}
						if($e>50)break;
						$e++;
					}
					// now skip the params from rest of scan,
					// or function test($a=false, $b=false) will be detected as var declaration
					$i+=$e-1; // -1, because '{' must be evaluated again
					
					// just for fun
					if($function_name === '__destruct') 
					{
						$scan_functions['unserialize'] = array(array(1), array());
					}
				}
				
			// check if token is a class declaration
				else if($token_name === T_CLASS)
				{
					$i++;
					$class_name = $tokens[$i][1];
					$vuln_classes[$class_name] = array();
					$in_class = true;
				}
				
			// build list of vars that are associated with a class
			// $var = new Classname()
				else if( $token_name === T_NEW && $tokens[$i-2][0] === T_VARIABLE )
				{
					$class_vars[ $tokens[$i-2][1] ] = $tokens[$i+1][1];
				}
				
			// watch function and constructor calls
				else if( $token_name === T_STRING )
				{
					// $var = Classname($constructor_param);
					if( $tokens[$i-1][0] !== T_NEW && isset($vuln_classes[$token_value]) )
					{
						$class_vars[ $tokens[$i-2][1] ] = $token_value;
					}
					// add function call to user-defined function list
					else
					{
						$class='';
						// $classvar->bla()
						if($tokens[$i-1][0] === T_OBJECT_OPERATOR)
						{
							$classvar = $tokens[$i-2][1];
							if(substr($classvar,0,1) !== '$')
								$classvar = '$'.$classvar;
							$class = ($classvar === '$this' ? $class_name : $class_vars[$classvar]).'::';
						}	

						if(isset($GLOBALS['user_functions_offset'][$class.$token_value]))
						{
							$GLOBALS['user_functions_offset'][$class.$token_value][3][] = array(
								(!empty($inc_file) ? dirname($file_name).'/'.$inc_file : $file_name), 
								$line_nr
							);
						}
					}
				}
				
			// add exit(),die() or throw exception() as requirements to watch out for	
				else if(($token_name === T_EXIT || $token_name === T_THROW) && $GLOBALS['verbosity'] >= 4)
				{										
					// build new find					 
					$new_find = new InfoTreeNode();
					$new_find->name = $token_value;
					$new_find->line = $line_nr;
					$new_find->value = highlightline(
						getmultiline($lines_pointer, $line_nr-1)."\t".$comment.' // call my cause exit', 
						$line_nr, $token_value
					);
					
					// if in included code, set file name
					if(!empty($inc_file))
						$new_find->filename = dirname($file_name) . '/' . $inc_file;
											// add dependencies
					foreach($dependencies as $deplinenr=>$dependency)
					{
						$new_find->dependencies[$deplinenr] = $dependency;
					}
												
					// add to output
					$id = (isset($GLOBALS['output'][$file_name])) ? 
							count($GLOBALS['output'][$file_name]) : 0;
					$GLOBALS['output'][$file_name][$id] = $new_find;
					
					// if exit in function, add this function as "exit function"
					if($in_function)
						$GLOBALS['F_INTEREST'][$function_name] = 'call may cause exit';
					
				}
				
			// ignore requirements: do, while, for, foreach	
				else if( in_array($token_name, $T_IGNORE_STRUCTURE) ) 
				{
					$ignore_requirement = true; 
				}
				
			// watch returns before vuln function gets called
				else if($in_function && $token_name === T_RETURN)
				{
					$GLOBALS['userfunction_taints'] = false;
					$GLOBALS['userfunction_secures'] = false;
					$c = 1;
					// get all variables in parameter list
					while( $tokens[$i + $c] !== ';' && $c < 10)
					{
						if( is_array($tokens[$i + $c]) )
						{
							if( $tokens[$i + $c][0] === T_VARIABLE )
							{
								// check if returned var is secured --> securing function
								$new_find = new VulnTreeNode();
								$userinput = scan_parameter($file_name, $new_find, $new_find, 
									$tokens[$i + $c][1],
									$var_declares_local, $i+$c, 
									$var_declares_global, array(), $function_obj, 
									false, $GLOBALS['F_SECURES_ALL'], TRUE);
													
								// add function to securing functions
								if($GLOBALS['userfunction_secures'])
								{
									$GLOBALS['F_SECURING_STRING'][] = $function_name;
								}
								
								// add function to userinput functions if userinput
								// is fetched in the function and then returned
								if($userinput || ($GLOBALS['userfunction_taints'] && $GLOBALS['verbosity'] < 1))
								{
									$GLOBALS['F_USERINPUT'][] = $function_name;
								}
								
							}
							// add function to securing functions if return value is secured
							else if( in_array($tokens[$i + $c][1], $GLOBALS['F_SECURING_STRING']) )
							{
								$GLOBALS['F_SECURING_STRING'][] = $function_name;
								break;
							}
						}
						if($c>50)break;
						$c++;
					}
				}
				
			// check if token is function call that affects variable scope (global)
				if($token_name === T_STRING && isset($globals_from_function[$token_value]) )
				{	
					// put all previously saved global var assignments to global scope
					foreach($globals_from_function[$token_value] as $var_name=>$new_vars)
					{
						foreach($new_vars as $new_var)
						{
							$new_var->value = $new_var->value . "// put in global scope by $token_value()";
							if(!isset($var_declares_global[$var_name]))
								$var_declares_global[$var_name] = array($new_var);
							else
								array_unshift($var_declares_global[$var_name], $new_var);
						}		
					}
				}
				
			// keep track of { program blocks }
			} else 
			{
				// get current dependencies in program flow
				if($token === '{' 
				&& ($tokens[$i-1] === ')' || $tokens[$i-1] === ':'
				|| (is_array($tokens[$i-1])
				&& ($tokens[$i-1][0] === T_DO  // do {
				|| $tokens[$i-1][0] === T_ELSE // else {
				|| $tokens[$i-1][0] === T_STRING)) ) ) // class bla {
				{
					// save brace amount at start of function
					if($in_function && $brace_save_func < 0) 
					{
						$brace_save_func = $braces_open;
					}	
					
					// save brace amount at start of class
					if($in_class && $brace_save_class < 0)
					{
						$brace_save_class = $braces_open;
					}
					
					if(empty($e))
					{
						$k=1;
						// line_nr of the token before '{'
						while( !is_numeric($line_nr) )
						{
							$line_nr = $tokens[$i-$k][2];
							if($k>50)break;
							$k++;
						}
						
						$dependency = '';
						
						if(!$ignore_requirement)
						{
							$dependency = getmultiline($lines_pointer, $line_nr-1);
							// if dependency is 'else' we want the 'if'
							if( preg_match('/else\s*[^\w]*$/i', $dependency) ) 
								$dependency = trim($last_dependency).'else';
						} else
						{
							$ignore_requirement = false;
						}
					
						// add dependency (even push empty dependency on stack, it will get poped again)
						$dependencies[$line_nr] = $dependency;					
					} else
					{
						unset($e);
					}
					
					$braces_open++;
				}	
				// before block ending "}" there must be a ";" or another "}". otherwise curly syntax
				else if( $token === '}' 
				&& ($tokens[$i-1] === ';' || $tokens[$i-1] === '}' || $tokens[$i-1] === '{') )
				{
					$braces_open--;
					
					// delete current dependency
					$last_dependency = array_pop($dependencies);

					// end of function found if brace amount = amount before function start
					if($in_function && $brace_save_func === $braces_open)
					{
						// write ending to user_function list for referencing functions in output
						$ref_name = ($in_class ? $class_name.'::' : '') . $function_name;
						$GLOBALS['user_functions_offset'][$ref_name][2] = $line_nr;
						// reset vars for next function declaration
						$brace_save_func = -1;
						$in_function = false;
						$function_params = array();
						$var_declares_local = array();
						$put_in_global_scope = array();
						// load new found vulnerable user functions to current scanlist
						if(isset($GLOBALS['user_functions'][$file_name]))
						{
							$scan_functions = array_merge($scan_functions, 
											$GLOBALS['user_functions'][$file_name]);
						}
					}
					
					// end of class found
					if($in_class && $brace_save_class === $braces_open)
					{
						$brace_save_class = -1;
						$in_class = false;
					}
				}
			}
			
			// token scanned. next.
		}	
		// all tokens scanned.
		
		return $inc_map;
	}
?>	