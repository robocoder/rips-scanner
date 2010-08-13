<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/
	
	// variable declarations = childs
	class VarDeclare
	{
		public $id;
    	public $value;
    	public $line;	
		public $marker;
		public $dependencies;
		
		function __construct($value = null) 
		{
			$this->id = 0;
			$this->value = $value;
			$this->line = '';
			$this->marker = 0;
			$this->dependencies = array();
		}
	}
	
	// used to store new finds
	class VulnTreeNode
	{
		public $id;
    	public $value;
		public $dependencies;
		public $title;
		public $name;
		public $marker;
		public $lines;
		public $filename;
		public $children;
		public $funcdepend;
		public $get;
		public $post;
		public $cookie;
		public $files;
		public $server;

		function __construct($value = null) 
		{
			$this->id = 0;
			$this->value = $value;
			$this->title = '';
			$this->dependencies = array();
			$this->name = '';
			$this->marker = 0;
			$this->lines = array();
			$this->filename = '';
			$this->children = array();
			$this->funcdepend = '';
		}
	}
	
	// information gathering finds
	class InfoTreeNode
	{
    	public $value;
		public $dependencies;
		public $name;
		public $line;
		public $title;
		public $filename;

		function __construct($value = null) 
		{
			$this->title = 'Information Gathering';
			$this->value = $value;
			$this->dependencies = array();
			$this->name = '';
			$this->line = 0;
			$this->filename = '';
		}
	}
	
	// function declaration
	class FunctionDeclare
	{
		public $value;
		public $name;
		public $line;
		public $marker;
		
		function __construct($value = null) 
		{
			$this->value = $value;
			$this->name = '';
			$this->line = 0;
			$this->marker = 0;
		}
	}

?>	