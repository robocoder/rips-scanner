<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/
	
	ini_set('short_open_tag', 1);			// who knows if I use them ;)
	ini_set('auto_detect_line_endings', 1);	// detect newlines in MAC files
	ini_set("memory_limit","1000M");		// set memory size to 1G
	set_time_limit(5*60);					// 5 minutes
	error_reporting(E_ERROR | E_WARNING | E_PARSE);
		
	$version = '0.40';						// RIPS version to be displayed	
	$maxtrace = 30;							// maximum of parameter traces per PVF find
	$warnfiles = 40;						// warn user if amount of files to scan is higher than this value
	$basedir = '';							// default directory shown
	$doku = 'http://php.net/';				// PHP dokumentation
	
	// available stylesheets (filename without .css ending)
	// more colors at http://wiki.macromates.com/Themes/UserSubmittedThemes
	$stylesheets = array(
		'phps',
		'code-dark',
		'twilight',
		'espresso',
		//'sunburst',
		'barf',
		'notepad++',
		'ayti'
	);
	
	// track chosen stylesheet permanently
	if(isset($_POST['stylesheet']) && $_POST['stylesheet'] !== $_COOKIE['stylesheet'])
		$_COOKIE['stylesheet'] = $_POST['stylesheet'];
	$default_stylesheet = isset($_COOKIE['stylesheet']) ? $_COOKIE['stylesheet'] : 'ayti';
	setcookie("stylesheet", $default_stylesheet);
	
	// filetypes to scan
	$filetypes = array(
		'.php', 
		'.inc', 
		'.phps', 
		'.php4', 
		'.php5', 
		//'.html', 
		//'.htm', 
		//'.js',
		'.phtml', 
		'.tpl',  
		'.cgi'
	); 
	
?>	