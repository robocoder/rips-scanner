<?php
/**

RIPS - A static source code analyser for vulnerabilities in PHP scripts
	by Johannes Dahse (johannes.dahse@rub.de)


Copyright (C) 2012 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.

**/

// define own token for include ending
define('T_INCLUDE_END', 10000);

// added in php 5.3
if ( ! defined('T_GOTO'))                                     define('T_GOTO', 10001);
if ( ! defined('T_NAMESPACE'))                                define('T_NAMESPACE', 10002);
if ( ! defined('T_NS_C'))                                     define('T_NS_C', 10003);
if ( ! defined('T_NS_SEPARATOR'))                             define('T_NS_SEPARATOR', 10004);
if ( ! defined('T_USE'))                                      define('T_USE', 10005);

// added in php 5.4
if ( ! defined('T_INSTEADOF'))                                define('T_INSTEADOF', 10006);
if ( ! defined('T_TRAIT'))                                    define('T_TRAIT', 10007);
if ( ! defined('T_TRAIT_C'))                                  define('T_TRAIT_C', 10008);

// added in php 5.5
if ( ! defined('T_FINALLY'))                                  define('T_FINALLY', 10009);
if ( ! defined('T_YIELD'))                                    define('T_YIELD', 10010);
if ( ! defined('T_YIELD_FROM'))                               define('T_YIELD_FROM', 10011);

// added in php 5.6
if ( ! defined('T_ELLIPSIS'))                                 define('T_ELLIPSIS', 10012);
if ( ! defined('T_POW'))                                      define('T_POW', 10013);
if ( ! defined('T_POW_EQUAL'))                                define('T_POW_EQUAL', 10014);

// added in php 7.0
if ( ! defined('T_COALESCE'))                                 define('T_COALESCE', 10015);
if ( ! defined('T_SPACESHIP'))                                define('T_SPACESHIP', 10016);

// added in php 7.4
if ( ! defined('T_COALESCE_EQUAL'))                           define('T_COALESCE_EQUAL', 10017);
if ( ! defined('T_FN'))                                       define('T_FN', 10018);

// added in php 8.0
if ( ! defined('T_ATTRIBUTE'))                                define('T_ATTRIBUTE', 10019);
if ( ! defined('T_MATCH'))                                    define('T_MATCH', 10020);
if ( ! defined('T_NAME_FULLY_QUALIFIED'))                     define('T_NAME_FULLY_QUALIFIED', 10021);
if ( ! defined('T_NAME_QUALIFIED'))                           define('T_NAME_QUALIFIED', 10022);
if ( ! defined('T_NAME_RELATIVE'))                            define('T_NAME_RELATIVE', 10023);
if ( ! defined('T_NULLSAFE_OBJECT_OPERATOR'))                 define('T_NULLSAFE_OBJECT_OPERATOR', 10024);

// added in php 8.1
if ( ! defined('T_ENUM'))                                     define('T_ENUM', 10025);
if ( ! defined('T_READONLY'))                                 define('T_READONLY', 10026);
if ( ! defined('T_AMPERSAND_NOT_FOLLOWED_BY_VAR_OR_VARARG'))  define('T_AMPERSAND_NOT_FOLLOWED_BY_VAR_OR_VARARG', 10027);
if ( ! defined('T_AMPERSAND_FOLLOWED_BY_VAR_OR_VARARG'))      define('T_AMPERSAND_FOLLOWED_BY_VAR_OR_VARARG', 10028);

final class Tokens
{
	// tokens to ignore while scanning
	public static $T_IGNORE = array(
		T_BAD_CHARACTER,
		T_DOC_COMMENT,
		T_COMMENT,
		//T_ML_COMMENT,
		T_INLINE_HTML,
		T_WHITESPACE,
		T_OPEN_TAG,
		//T_CLOSE_TAG,
	);

	// code blocks that should be ignored as requirement
	public static $T_LOOP_CONTROL = array(
		//T_DO, // removed, because DO..WHILE is rewritten to WHILE
		T_WHILE,
		T_FOR,
		T_FOREACH,
	);

	// control structures
	public static $T_FLOW_CONTROL = array(
		T_IF,
		T_SWITCH,
		T_CASE,
		T_ELSE,
		T_ELSEIF,
	);

	// variable assignment tokens
	public static $T_ASSIGNMENT = array(
		T_AND_EQUAL,
		T_CONCAT_EQUAL,
		T_DIV_EQUAL,
		T_MINUS_EQUAL,
		T_MOD_EQUAL,
		T_MUL_EQUAL,
		T_OR_EQUAL,
		T_PLUS_EQUAL,
		T_POW_EQUAL,
		T_SL_EQUAL,
		T_SR_EQUAL,
		T_XOR_EQUAL,
		T_COALESCE_EQUAL,
	);

	// variable assignment tokens that prevent tainting
	public static $T_ASSIGNMENT_SECURE = array(
		T_DIV_EQUAL,
		T_MINUS_EQUAL,
		T_MOD_EQUAL,
		T_MUL_EQUAL,
		T_OR_EQUAL,
		T_PLUS_EQUAL,
		T_POW_EQUAL,
		T_SL_EQUAL,
		T_SR_EQUAL,
		T_XOR_EQUAL,
	);

	// condition operators
	public static $T_OPERATOR = array(
		T_IS_EQUAL,
		T_IS_GREATER_OR_EQUAL,
		T_IS_IDENTICAL,
		T_IS_NOT_EQUAL,
		T_IS_NOT_IDENTICAL,
		T_IS_SMALLER_OR_EQUAL,
		T_SPACESHIP,
		T_COALESCE,
	);

	// all function call tokens
	public static $T_FUNCTIONS = array(
		T_STRING, // all functions
		T_EVAL,
		T_INCLUDE,
		T_INCLUDE_ONCE,
		T_REQUIRE,
		T_REQUIRE_ONCE,
	);

	// including operation tokens
	public static $T_INCLUDES = array(
		T_INCLUDE,
		T_INCLUDE_ONCE,
		T_REQUIRE,
		T_REQUIRE_ONCE,
	);

	// XSS affected operation tokens
	public static $T_XSS = array(
		T_PRINT,
		T_ECHO,
		T_OPEN_TAG_WITH_ECHO,
		T_EXIT,
	);

	// securing operation tokens
	public static $T_CASTS = array(
		T_BOOL_CAST,
		T_DOUBLE_CAST,
		T_INT_CAST,
		T_UNSET_CAST,
		T_UNSET,
	);

	// tokens that will have a space before and after in the output, besides $T_OPERATOR and $T_ASSIGNMENT
	public static $T_SPACE_WRAP = array(
		T_AS,
		T_BOOLEAN_AND,
		T_BOOLEAN_OR,
		T_LOGICAL_AND,
		T_LOGICAL_OR,
		T_LOGICAL_XOR,
		T_SL,
		T_SR,
		T_CASE,
		T_ELSE,
		T_GLOBAL,
		T_NEW,
	);

	// arithmetical operators to detect automatic typecasts
	public static $T_ARITHMETIC = array(
		T_INC,
		T_DEC,
	);

	// arithmetical operators to detect automatic typecasts
	public static $S_ARITHMETIC = array(
		'+',
		'-',
		'*',
		'/',
		'%',
		T_POW,
	);

	// strings that will have a space before and after in the output besides $S_ARITHMETIC
	public static $S_SPACE_WRAP = array(
		'.',
		'=',
		'>',
		'<',
		':',
		'?',
	);
}
