<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannes.dahse@rub.de)
			
			
Copyright (C) 2012 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.

**/

class Tokenizer
{	
	// main
	public function tokenize($code)
	{
		$tokens = token_get_all($code);			
		$tokens = self::prepare_tokens($tokens);
		$tokens = self::fix_tokens($tokens);	
		$tokens = self::array_reconstruct_tokens($tokens);
		$tokens = self::fix_ternary($tokens);
		return $tokens;
	}

	// delete all tokens to ignore while scanning, mostly whitespaces	
	function prepare_tokens($tokens)
	{	
		// delete whitespaces and other unimportant tokens, rewrite some special tokens
		for($i=0, $c=count($tokens); $i<$c; $i++)
		{
			if( is_array($tokens[$i]) ) 
			{
				if( in_array($tokens[$i][0], Tokens::$T_IGNORE) )
					unset($tokens[$i]);
				else if( $tokens[$i][0] === T_CLOSE_TAG )
					$tokens[$i] = ';';	
				else if( $tokens[$i][0] === T_OPEN_TAG_WITH_ECHO )
					$tokens[$i][1] = 'echo';
			} else if($tokens[$i] === '@') // @ (depress errors) disturbs connected token handling
				unset($tokens[$i]);
		}
		
		// return tokens with rearranged key index
		return array_values($tokens);
	}	
	
	// adds braces around offsets
	function wrapbraces($tokens, $start, $between, $end)
	{
		$tokens = array_merge(
			array_slice($tokens, 0, $start), array('{'), 
			array_slice($tokens, $start, $between), array('}'),
			array_slice($tokens, $end)
		);	
		return $tokens;
	}
		
	// some tokenchains need to be fixed to scan correctly later	
	function fix_tokens($tokens)
	{	
		for($i=0; $i<count($tokens); $i++)
		{
		// convert `backticks` to backticks()
			if( $tokens[$i] === '`' )
			{		
				$f=1;
				while( $tokens[$i+$f] !== '`' && $tokens[$i+$f] !== ';' && $f<1000)
				{		
					// get line_nr of any near token
					if( is_array($tokens[$i+$f]) )
						$line_nr = $tokens[$i+$f][2];

					$f++;
				}
				if(!empty($line_nr))
				{ 
					$tokens[$i+$f] = ')';
					$tokens[$i] = array(T_STRING, 'backticks', $line_nr);
				
					// add element backticks() to array 			
					$tokens = array_merge(
						array_slice($tokens, 0, $i+1), array('('), 
						array_slice($tokens, $i+1)
					);	
				}

			}
		// rewrite $array{index} to $array[index]
			else if( $tokens[$i] === '{'
			&& ((is_array($tokens[$i-1]) && $tokens[$i-1][0] === T_VARIABLE)
			|| $tokens[$i-1] === ']') )
			{
				$tokens[$i] = '[';
				$f=1;
				while($tokens[$i+$f] !== '}' && $f<1000)
				{
					$f++;
				}
				$tokens[$i+$f] = ']';
			}	
		// real token
			else if( is_array($tokens[$i]) )
			{
			// rebuild if-clauses, for(), foreach(), while() without { }
				if ( ($tokens[$i][0] === T_IF || $tokens[$i][0] === T_ELSEIF || $tokens[$i][0] === T_FOR 
				|| $tokens[$i][0] === T_FOREACH || $tokens[$i][0] === T_WHILE) && $tokens[$i+1] === '(' )
				{		
					// skip condition in ( )
					$f=2;
					$braceopen = 1;
					while($braceopen !== 0 && $f<1000) 
					{
						if($tokens[$i+$f] === '(')
							$braceopen++;
						else if($tokens[$i+$f] === ')')
							$braceopen--;
						$f++;	
					}	

					// if body not in { (and not a do ... while();) wrap next instruction in braces
					if($tokens[$i+$f] !== '{' && $tokens[$i+$f] !== ';')
					{
						$c=2;
						while($tokens[$i+$f+$c] !== ';')
						{
							$c++;
						}
						$tokens = self::wrapbraces($tokens, $i+$f, $c+1, $i+$f+$c+1);
					}
				} 
			// rebuild else without { }	
				else if( $tokens[$i][0] === T_ELSE 
				&& $tokens[$i+1][0] !== T_IF
				&& $tokens[$i+1] !== '{')
				{	
					$f=2;
					while( $tokens[$i+$f] !== ';' )
					{		
						$f++;
					}
					$tokens = self::wrapbraces($tokens, $i+1, $f, $i+$f+1);
				}
			// rebuild switch case: without { }	
				else if( $tokens[$i][0] === T_CASE
				&& $tokens[$i+2] === ':'
				&& $tokens[$i+3] !== '{' )
				{
					$f=3;
					while( isset($tokens[$i+$f]) 
					&& !(is_array($tokens[$i+$f]) 
					&& ($tokens[$i+$f][0] === T_BREAK || $tokens[$i+$f][0] === T_CASE || $tokens[$i+$f][0] === T_DEFAULT) ) )
					{		
						$f++;
					}
					if($tokens[$i+$f][0] === T_BREAK)
					{
						$tokens = self::wrapbraces($tokens, $i+3, $f-1, $i+$f+2);
					}	
					else if($tokens[$i+$f][0] === T_CASE || $tokens[$i+$f][0] === T_DEFAULT || $tokens[$i+$f] === '}')
					{
						$tokens = self::wrapbraces($tokens, $i+3, $f-3, $i+$f);
					}	
					$i++;
				}
			// rebuild switch default: without { }	
				else if( $tokens[$i][0] === T_DEFAULT
				&& $tokens[$i+2] !== '{' )
				{
					$f=2;
					while( $tokens[$i+$f] !== ';' )
					{		
						$f++;
					}
					$tokens = self::wrapbraces($tokens, $i+2, $f-1, $i+$f+1);
				}
			// lowercase all function names because PHP doesn't care	
				else if( $tokens[$i][0] === T_FUNCTION )
				{
					$tokens[$i+1][1] = strtolower($tokens[$i+1][1]);
				}	
				else if( $tokens[$i][0] === T_STRING && $tokens[$i+1] === '(')
				{
					$tokens[$i][1] = strtolower($tokens[$i][1]);
				}	
			// switch a do while with a while (the difference in loop rounds doesnt matter
			// and we need the condition to be parsed before the loop tokens)
				else if( $tokens[$i][0] === T_DO )
				{
					$f=2;
					// f = T_WHILE token position relative to i
					while( $tokens[$i+$f][0] !== T_WHILE )
					{		
						$f++;
					}
					
					// rebuild do while without {} (should never happen but we want to be sure)
					if($tokens[$i+1] !== '{')
					{
						$tokens = self::wrapbraces($tokens, $i+1, $f-1, $i+$f);
						// by adding braces we added two new tokens
						$f+=2;
					}

					$d=1;
					// d = END of T_WHILE condition relative to i
					while( $tokens[$i+$f+$d] !== ';' )
					{
						$d++;
					}
					
					// reorder tokens and replace DO WHILE with WHILE
					$tokens = array_merge(
						array_slice($tokens, 0, $i), array(111),// before DO 
						array_slice($tokens, $i+$f, $d), array(222),// WHILE condition
						array_slice($tokens, $i+1, $f-1), array(333),// DO WHILE loop tokens
						array_slice($tokens, $i+$f+$d+1, count($tokens)) // rest of tokens without while condition
					);						
				}
			}	
		}
		// return tokens with rearranged key index
		return array_values($tokens);
	}
	
	// rewrite $arrays[] to	$variables and save keys in $tokens[$i][3]
	function array_reconstruct_tokens($tokens)
	{	
		for($i=0,$max=count($tokens); $i<$max; $i++)
		{
			// check for arrays
			if( is_array($tokens[$i]) && $tokens[$i][0] === T_VARIABLE && $tokens[$i+1] === '[' )
			{	
				$tokens[$i][3] = array();
				$has_more_keys = true;
				$index = -1;
				$c=2;
				
				// loop until no more index found: array[1][2][3]
				while($has_more_keys && $index < 5)
				{
					$index++;
					// save constant index as constant
					if(($tokens[$i+$c][0] === T_CONSTANT_ENCAPSED_STRING || $tokens[$i+$c][0] === T_LNUMBER || $tokens[$i+$c][0] === T_NUM_STRING) && $tokens[$i+$c+1] === ']')
					{ 		
						unset($tokens[$i+$c-1]);
						$tokens[$i][3][$index] = str_replace(array('"', "'"), '', $tokens[$i+$c][1]);
						unset($tokens[$i+$c]);
						unset($tokens[$i+$c+1]);
						$c+=2;
					// save tokens of non-constant index as token-array for backtrace later	
					} else
					{
						$tokens[$i][3][$index] = array();
						$newbraceopen = 1;
						unset($tokens[$i+$c-1]);
						while($newbraceopen !== 0 && $c < 100)
						{	
							if( $tokens[$i+$c] === '[' )
							{
								$newbraceopen++;
							}
							else if( $tokens[$i+$c] === ']' )
							{
								$newbraceopen--;
							}
							else
							{
								$tokens[$i][3][$index][] = $tokens[$i+$c];
							}	
							unset($tokens[$i+$c]);
							$c++;
						}
						unset($tokens[$i+$c-1]);
					}
					if($tokens[$i+$c] !== '[')
						$has_more_keys = false;
					$c++;	
				}	
				
				$i+=$c-1;
			}
		}
	
		// return tokens with rearranged key index
		return array_values($tokens);		
	}
	
	// handle ternary operator (remove condition, only values should be handled during trace)
	// problem: tainting in the condition is not actual tainting the line -> remove condition	
	function fix_ternary($tokens)
	{
		for($i=0,$max=count($tokens); $i<$max; $i++)
		{
			if( $tokens[$i] === '?' )
			{
				unset($tokens[$i]);
				// condition in brackets: fine, delete condition
				if($tokens[$i-1] === ')')
				{
					unset($tokens[$i-1]);
					// delete tokens till ( 
					$newbraceopen = 1;
					$f = 2;
					while( !($newbraceopen === 0 || $tokens[$i - $f] === ';') )
					{
						if( $tokens[$i - $f] === '(' )
						{
							$newbraceopen--;
						}
						else if( $tokens[$i - $f] === ')' )
						{
							$newbraceopen++;
						}
						unset($tokens[$i - $f]);	

						$f++;
					}

					//delete token before, if T_STRING
					if($tokens[$i-$f] === '!' || (is_array($tokens[$i-$f]) 
					&& ($tokens[$i-$f][0] === T_STRING || $tokens[$i-$f][0] === T_EMPTY || $tokens[$i-$f][0] === T_ISSET)))
					{
						unset($tokens[$i-$f]);
					}
					
				}
				// condition is a check or assignment
				else if(in_array($tokens[$i-2][0], Tokens::$T_ASSIGNMENT) || in_array($tokens[$i-2][0], Tokens::$T_OPERATOR) )
				{
					// remove both operands
					unset($tokens[$i-1]);
					unset($tokens[$i-2]);
					// if operand is in braces
					if($tokens[$i-3] === ')')
					{
						// delete tokens till ( 
						$newbraceopen = 1;
						$f = 4;
						while( !($newbraceopen === 0 || $tokens[$i - $f] === ';') )
						{
							if( $tokens[$i - $f] === '(' )
							{
								$newbraceopen--;
							}
							else if( $tokens[$i - $f] === ')' )
							{
								$newbraceopen++;
							}
						
							unset($tokens[$i - $f]);	

							$f++;
						}

						//delete token before, if T_STRING
						if(is_array($tokens[$i-$f]) 
						&& ($tokens[$i-$f][0] === T_STRING || $tokens[$i-$f][0] === T_EMPTY || $tokens[$i-$f][0] === T_ISSET))
						{
							unset($tokens[$i-$f]);
						}
					}

					unset($tokens[$i-3]);
					
				}
				// condition is a single variable, delete
				else if(is_array($tokens[$i-1]) && $tokens[$i-1][0] === T_VARIABLE)
				{
					unset($tokens[$i-1]);
				}
			}	
		}
		// return tokens with rearranged key index
		return array_values($tokens);	
	}
}	
	
?>	