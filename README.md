# Get-MissingSecurityUpdates
    .SYNOPSIS
		Script to search for security updates installed and/or missing
	
    .NOTES
		Jan-Andre Tiedemann, Andreas Mirbach, Jan-Hendirk Peters
		Amended by Jan Tiedemann to run offline, added automated download capability of wsusscn2.cab file and parameter handling
    
    .DESCRIPTION
		A CASE script to search for missing security updates used in the Microsoft Baseline Security Analyser
    
    .PARAMETER 	ComputerName
		The machine or machines to connect to if multiple seperated by comma
    
    .PARAMETER Server_file	
		The multiple machines inside a text file
    
    .PARAMETER Path
		The path to the offline scan file, if file does not exists it will be downloaded via WebClient API
	
    .EXAMPLE
		GetMissingUpdates -Server_file 'c:\tmp\myservers.txt'
	
    .EXAMPLE
		GetMissingUpdates -ComputerName 'Server1,Server2,Server3'
	
    .EXAMPLE
		GetMissingUpdates -ComputerName 'Server1'
	
	.EXAMPLE
		GetMissingUpdates.ps1 -ComputerName 'jantiede-x1' -UpdateSearchFilter 'IsHidden=0 and IsInstalled=0'
    
	.OUTPUTS
		System.String. You can pipe it into a Table and write it into a csv for further excel processing.
