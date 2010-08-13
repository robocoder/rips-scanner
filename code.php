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

	// prepare output to style with CSS
	function highlightline($line, $line_nr, $marklines)
	{
		$tokens = @token_get_all('<? '.$line.' ?>');
		$output = "<tr><td class=\"linenrcolumn\"><span class=\"linenr\">$line_nr</span>&nbsp;&nbsp;&nbsp;<A id='".($line_nr+2).'\'></A></td>';
		
		$output .= (in_array($line_nr, $marklines)) ? '<td nowrap class="markline">' : '<td nowrap>';

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
						$text.= 'style="cursor:pointer;" name="phps-var-'.$cssname.'" onClick="markVariable(\''.$cssname.'\')"';
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
		for($i=0, $max=count($lines); $i<$max; $i++)
		{
			echo highlightline($lines[$i], $i+1, $marklines);
		}
	} else
	{
		echo '<tr><td>No file specified.</td></tr>';
	}
?>
</table>