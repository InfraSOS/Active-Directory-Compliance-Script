# Active Directory Compliance Powershell Script
Free Active Directory Compliance tool for CIS benchmarks, SOX, NIST, GDPR and HIPAA.  I’ve created a Powershell script that outputs a HTML report on the status of your Active Directory in regards to your compliance.  Run on as many domains as you need.  You can run it remotely, just specify the domain controller and the script will run against your DC. 

  ![Alt text](https://cdn.infrasos.com/wp-content/uploads/2024/06/Active-Directory-Compliance-1-768x424.png)

  ## Prerequisites
  The computer running the script needs connection to a domain controller.
  You also need the following Powershell modules installed:
  ><b>Active Directory Powershell module</b>. Refer to for instructions on installing the Active Directory Powershell module: https://infrasos.com/how-to-install-active-directory-powershell-module-and-import/


  ><b>Group Policy Powershell Module</b> The Group Policy module is also included with RSAT. You can enable this feature using the following commands:

  >Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools

## Running the Active Directory Compliance Script
Within the script update the following fields for the local path to your logo, where to save the report and the domain controller to run the script against:
>#Enter the hostname of one of your domain controllers.
>
>$DomainController = "addc01"
>
>#Add your own logo that will be used in the report.
>
>$LogoPath = "c:\temp\Logo.png"
>
>#Add the local path of where to save the report. Make sure the extension is called .html
>
>$ReportPath = "c:\temp\reportcis123.html"
>
>#Enter your domain.
>
>$domain = "Infrasos.com"



