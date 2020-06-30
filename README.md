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
