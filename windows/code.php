<table width='100%'>
<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/

include('../config/general.php');

	// prepare output to style with CSS
	function highlightline($line, $line_nr, $marklines)
	{
		$tokens = @token_get_all('<? '.$line.' ?>');
		
		$output = (in_array($line_nr, $marklines)) ? '<tr><td nowrap class="markline">' : '<tr><td nowrap>';

		foreach ($tokens as $token)
		{
			if (is_string($token))
			{		
				$output .= '<span class="phps-code">';
				$output .= htmlentities($token, ENT_QUOTES, 'utf-8');
				$output .= '</span>';
			} 
			else if (is_array($token) 
			&& $token[0] !== T_OPEN_TAG
			&& $token[0] !== T_CLOSE_TAG) 
			{					
				if ($token[0] !== T_WHITESPACE)
				{
					$text = '<span ';
					if($token[0] === T_VARIABLE)
					{
						$cssname = str_replace('$', '', $token[1]);
						$text.= 'style="cursor:pointer;" name="phps-var-'.$cssname.'" onClick="markVariable(\''.$cssname.'\')" ';
						$text.= 'onmouseover="markVariable(\''.$cssname.'\')" onmouseout="markVariable(\''.$cssname.'\')" ';
					}	
					else if($token[0] === T_STRING)
					{
						$text.= "onmouseover=\"mouseFunction('{$token[1]}', this)\" onmouseout=\"this.style.textDecoration='none'\" ";
						$text.= "onclick=\"openFunction('{$token[1]}','$line_nr');\" ";
					}
					$text.= 'class="phps-'.str_replace('_', '-', strtolower(token_name($token[0]))).'" ';
					$text.= '>'.htmlentities($token[1], ENT_QUOTES, 'utf-8').'</span>';
				}
				else
				{
					$text = str_replace(' ', '&nbsp;', $token[1]);
					$text = str_replace("\t", str_repeat('&nbsp;', 8), $text);
				}
				
				$output .= $text;
			}
		}
		return $output.'</td></tr>';
	}
	
	// print source code and mark lines
	
	$file = $_GET['file'];
	$marklines = explode(',', $_GET['lines']);

	
	if(!empty($file))
	{
		$lines = file($file); 
		
		// place line numbers in extra table for more elegant copy/paste without line numbers
		echo '<tr><td><table>';
		for($i=1, $max=count($lines); $i<=$max;$i++) 
			echo "<tr><td class=\"linenrcolumn\"><span class=\"linenr\">$i</span><A id='".($i+2).'\'></A></td></tr>';
		echo '</table></td><td><table width="100%">';
		
		for($i=0; $i<$max; $i++)
		{
			echo highlightline($lines[$i], $i+1, $marklines);
		}
	} else
	{
		echo '<tr><td>No file specified.</td></tr>';
	}
?>
</table>
</td></tr></table>