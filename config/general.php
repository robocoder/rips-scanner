<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/
	
	$start = microtime(TRUE);
	ini_set('short_open_tag', 1);
	set_time_limit(180);
	error_reporting(0);
		
	$version = '0.32';				// RIPS version to be displayed	
	$maxtrace = 30;					// maximum of parameter traces per PVF find
	$basedir = '';					// default directory shown
	$doku = 'http://php.net/';		// PHP dokumentation
	
	// available stylesheets (filename without .css ending)
	// more colors at http://wiki.macromates.com/Themes/UserSubmittedThemes
	$stylesheets = array(
		'phps',
		'code-dark',
		'twilight',
		'espresso',
		'sunburst',
		'barf',
		'notepad++'
	);
	
	$default_stylesheet = 'twilight';
	
	// filetypes to scan
	$filetypes = array(
		'.php', 
		'.inc', 
		'.phps', 
		'.php4', 
		'.php5', 
		'.html', 
		'.htm', 
		'.phtml', 
		'.tpl',  
		'.cgi'
	); 
	
?>	