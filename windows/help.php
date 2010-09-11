<?php

include '../config/general.php';
include '../config/securing.php';
include '../config/PVF.php';
include '../config/userinput.php';
include '../config/help.php';
include '../functions/output.php';

$function = htmlentities($_GET['function'], ENT_QUOTES, 'utf-8');
$type = htmlentities($_GET['type'], ENT_QUOTES, 'utf-8');

switch($_GET['type'])
{
	case $NAME_XSS: 			$HELP = $HELP_XSS;	
								$FUNCS = $F_SECURING_XSS;
								break;
	case $NAME_CODE: 			$HELP = $HELP_CODE;	
								$FUNCS = $F_SECURING_PREG;
								break;
	case $NAME_FILE_INCLUDE: 	$HELP = $HELP_FILE_INCLUDE;
								$FUNCS = $F_SECURING_FILE;
								break;
	case $NAME_FILE_READ: 		$HELP = $HELP_FILE_READ;
								$FUNCS = $F_SECURING_FILE;
								break;
	case $NAME_FILE_AFFECT: 	$HELP = $HELP_FILE_AFFECT;
								$FUNCS = $F_SECURING_FILE;
								break;
	case $NAME_EXEC: 			$HELP = $HELP_EXEC;	
								$FUNCS = $F_SECURING_SYSTEM;
								break;
	case $NAME_DATABASE: 		$HELP = $HELP_DATABASE;
								$FUNCS = $F_SECURING_SQL;
								break;
	case $NAME_XPATH: 			$HELP = $HELP_XPATH;
								$FUNCS = $F_SECURING_XPATH;
								break;
	case $NAME_CONNECT: 		$HELP = $HELP_CONNECT; 
								$FUNCS = array();
								break;
	default: 					
		$HELP = array(
			'description' => 'No description available for this vulnerability.',
			'link' => '',		
			'code' => 'Not available.',
			'poc' => 'Not available.'
		);	
		break;
}
?>

<div style="padding:30px">

<h3>vulnerability concept:</h3>

<table>
<tr>
	<th class="helptitle">user input</th>
	<th></th>
	<th class="helptitle">potentially<br />vulnerable function</th>
	<th></th>
	<th class="helptitle">vulnerability</th>
</tr>
<tr>
<td align="left" class="helpbox">
<ul style="margin-left:-25px">
<?php
if($_GET['get']) 	
	echo "<li class=\"userinput\"><a href=\"{$doku}reserved.variables.get\" target=\"_blank\">\$_GET</a></li>";
if($_GET['post'])	
	echo "<li class=\"userinput\"><a href=\"{$doku}reserved.variables.post\" target=\"_blank\">\$_POST</a></li>";
if($_GET['cookie'])	
	echo "<li class=\"userinput\"><a href=\"{$doku}reserved.variables.cookie\" target=\"_blank\">\$_COOKIE</a></li>";
if($_GET['files']) 	
	echo "<li class=\"userinput\"><a href=\"{$doku}reserved.variables.files\" target=\"_blank\">\$_FILES</a></li>";
if($_GET['server'])	
	echo "<li class=\"userinput\"><a href=\"{$doku}reserved.variables.server\" target=\"_blank\">\$_SERVER</a></li>";
?>
</ul>
</td>
<td align="center" valign="center"><h1>+</h1></td>
<td align="center" class="helpbox">
	<?php echo "<a class=\"link\" href=\"$doku$function\" target=\"_blank\">$function()</a>"; ?>
</td>
<td align="center" valign="center"><h1>=</h1></td>
<td align="center" class="helpbox">
<?php echo $type; ?>
</td>
</tr>
</table>

<h3>vulnerability description:</h3>
<p><?php echo $HELP['description']; ?></p>
<p><?php if(!empty($helplink)) echo "More information about $type can be found <a href=\"{$HELP['link']}\">here</a>."; ?></p>

<h3>vulnerable example code:</h3>
<pre><?php echo highlightline($HELP['code'], 1); ?></pre>

<h3>proof of concept:</h3>
<p><?php echo htmlentities($HELP['poc']); ?></p>

<h3>patch:</h3>
<p><?php echo htmlentities($HELP['patchtext']); ?></p>
<pre><?php echo highlightline($HELP['patch'], 1); ?></pre>

<h3>related securing functions:</h3>
<ul>
<?php
if(!empty($FUNCS))
{
	foreach($FUNCS as $func)
	{
		echo "<li><a href=\"$doku$func\" target=\"_blank\">$func</a></li>\n";
	}
} else
{
	echo 'None.';
}
?>
</ul>
</div>