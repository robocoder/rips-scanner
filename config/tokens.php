<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/
	
	// tokens to ignore while scanning
	$T_IGNORE = array(
		T_BAD_CHARACTER,
		T_DOC_COMMENT,
		T_COMMENT,
		//T_ML_COMMENT,
		T_INLINE_HTML,
		T_WHITESPACE,
		T_OPEN_TAG
		//T_CLOSE_TAG
	);
	
	// code blocks that should be ignored as requirement
	$T_IGNORE_STRUCTURE = array(
		T_DO,
		T_WHILE,
		T_FOR,
		T_FOREACH
	);
	
	// variable assignment tokens
	$T_ASSIGNMENT = array(
		T_AND_EQUAL,
		T_CONCAT_EQUAL,
		T_DIV_EQUAL,
		T_MINUS_EQUAL,
		T_MOD_EQUAL,
		T_MUL_EQUAL,
		T_OR_EQUAL,
		T_PLUS_EQUAL,
		T_SL_EQUAL,
		T_SR_EQUAL,
		T_XOR_EQUAL
	);
	
	// condition operators
	$T_OPERATOR = array(
		T_IS_EQUAL,
		T_IS_GREATER_OR_EQUAL,
		T_IS_IDENTICAL,
		T_IS_NOT_EQUAL,
		T_IS_NOT_IDENTICAL,
		T_IS_SMALLER_OR_EQUAL
	);
	
	// all function call tokens
	$T_FUNCTIONS = array(
		T_STRING, // all functions
		T_EVAL,
		T_INCLUDE,
		T_INCLUDE_ONCE,
		T_REQUIRE,
		T_REQUIRE_ONCE
	);
	
	// including operation tokens
	$T_INCLUDES = array(
		T_INCLUDE,
		T_INCLUDE_ONCE,
		T_REQUIRE,
		T_REQUIRE_ONCE
	);
	
	// XSS affected operation tokens
	$T_XSS = array(
		T_PRINT,
		T_ECHO,
		T_OPEN_TAG_WITH_ECHO
	);
	
	// securing operation tokens
	$T_CASTS = array(
		T_BOOL_CAST,
		T_DOUBLE_CAST,
		T_INT_CAST,
		T_UNSET_CAST,
		T_INC,
		T_DEC,
		T_UNSET
	);
	
	// arithmetical operators to detect automatic typecasts
	$T_ARITHMETIC = array(
		'+',
		'-',
		'*',
		'/',
		'%'
	);
	
	// define own token for include ending
	define('T_INCLUDE_END', 380);
?>	