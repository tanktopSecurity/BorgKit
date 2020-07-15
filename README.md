# BorgKit

## What is BorgKit?
Inspired by SwiftOnSecurity's "Org Kit", the BorgKit is a lab creation script to aid in the creation of a level higher of "secure by default", on-premises Windows domain/forest. The majority of scripts and tools used within are directly from Microsoft and are at the guidance of their respective Microsoft creators. The intention of BorgKit (at least in this iteration of the project) is not to reach DOD or other extremely high levels of security. The two primay goals are:
  Provide Blue teams with a reference domain/forest
  Allow Red teams to create a "secure by default" domain in which to practice
  
## The BorgKit script automates the following:
  - Ensure a uniform folder structure for components
  - Import a manifest with all neceessary URLs, file locations and destinations
  - Download and extract all files
  - Install a Windows forest and domain, promote the server to a domain controller and reboot
  - Resume script upon reboot and administrator login
  - Create Central Polciy definition folder and populate with ADMX/ADML (support for additional languages coming in future version)
  - Run PAWScripts (per MS link)
  - Secure PAW via MS guidance (MS link on PAW)
  - Configure the local DC as a WEFFLES collector and forward all events locallly (support for a separate WEF host coming in future version)
    - Per Jessica Payne and SwiftOnSecurity
  - Automatically import and link Group Policy Objects to correct OUs
  - Copy all executables to SYSVOL\software and set scheduled tasks GPOs to install security software (per syspanda)
  - Enable Bitlocker on Computers OU and set Bitlocker Readers group

## Known Issues / Task List
Upon resume of script after forest/domain install and server reboot, the script asks for the DomainName and DSRM password. You can just press enter or type anything and press enter. It will not be passed into the second part of the script.

The script is hard-coded to run everything for Windows 10/Server 2019 "1909". The code is mostly there to allow the script to use different Windwos/Server releases, but needs a bit of work to fully support this. 

The Set-PAWOUDelegation.ps1 script from the PAWScripts section does not always initialize properly. I attempted to mittigate this by adding a wait timer and a dectction to wait for the forest to be initialized. 

The Set-GPOLinks function is hard-coded to import GPOs with "1909" in the name.

Works on:

Windows Server 2019 - PowerShell 5.1.17763.592