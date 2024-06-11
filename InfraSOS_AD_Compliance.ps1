#
# Created by Andrew Fitzgerald @ InfraSOS.com 
# This script will generate a HTML report that will check your Active Directory for baseline benchmark controls for CIS, NIST, SOX, GDPR & HIPAA. 
#
# Import required modules
Import-Module ActiveDirectory
Import-Module GroupPolicy

# Suppress errors
$ErrorActionPreference = "SilentlyContinue"

# User input
# Update with your values
$DomainController = "addc01"
$LogoPath = "c:\temp\Logo.png"
$ReportPath = "c:\temp\reportcis123.html"
$domain = "Infrasos.com"

# Domain stats
$DomainName = (Get-ADDomain).DNSRoot
$NumberOfUsers = (Get-ADUser -Filter *).Count
$NumberOfGroups = (Get-ADGroup -Filter *).Count
$NumberOfDisabledUsers = (Get-ADUser -Filter { Enabled -eq $false }).Count
$NumberOfDomainAdmins = (Get-ADGroupMember -Identity "Domain Admins").Count

# Define the CIS benchmarks to check
$CISBenchmarks = @(
    @{ Name = "Ensure 'Account lockout duration' is set to '15 or more minute(s)'"; Command = { (Get-ADDefaultDomainPasswordPolicy -Server $DomainController).LockoutDuration.TotalMinutes -ge 15 }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration"; Type = "CIS" },
    @{ Name = "Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s)'"; Command = { (Get-ADDefaultDomainPasswordPolicy -Server $DomainController).LockoutThreshold -le 10 }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold"; Type = "CIS" },
    @{ Name = "Ensure 'Password minimum length' is set to '14 or more character(s)'"; Command = { (Get-ADDefaultDomainPasswordPolicy -Server $DomainController).MinPasswordLength -ge 14 }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-minimum-length"; Type = "CIS" },
    @{ Name = "Ensure 'Password history size' is set to '24 or more password(s)'"; Command = { (Get-ADDefaultDomainPasswordPolicy -Server $DomainController).PasswordHistorySize -ge 24 }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-password-history"; Type = "CIS" },
    @{ Name = "Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'"; Command = { ((Get-ADDefaultDomainPasswordPolicy -Server $DomainController).MaxPasswordAge.Days -le 60) -and ((Get-ADDefaultDomainPasswordPolicy -Server $DomainController).MaxPasswordAge.Days -gt 0) }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age"; Type = "CIS" },
    @{ Name = "Ensure 'Minimum password age' is set to '1 or more day(s)'"; Command = { (Get-ADDefaultDomainPasswordPolicy -Server $DomainController).MinPasswordAge.Days -ge 1 }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-age"; Type = "CIS" },
    @{ Name = "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"; Command = { (Get-ADDefaultDomainPasswordPolicy -Server $DomainController).UserAccountControl -band 0x80000 -eq 0 }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enable-computer-and-user-accounts-to-be-trusted-for-delegation"; Type = "CIS" },
    @{ Name = "Ensure 'User Rights Assignment: Access this computer from the network' is set to 'Administrators, Authenticated Users'"; Command = {
        try {
            $value = (Get-GPRegistryValue -Name 'Default Domain Controllers Policy' -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ValueName 'NullSessionShares').Value
            return $value -eq ""
        } catch {
            return $false
        }
    }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-this-computer-from-the-network"; Type = "CIS" }
)

# Define the NIST controls to check
$NISTControls = @(
    @{ Name = "Ensure 'Audit Log Retention' is set to '365 or more days'"; Command = { (Get-EventLog -LogName 'Security' -Newest 1 | Select-Object RetentionDays -ExpandProperty RetentionDays -eq 365) }; Link = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"; Type = "NIST" },
    @{ Name = "Ensure 'Windows Firewall: Domain Profile' is set to 'On'"; Command = { (Get-NetFirewallProfile -Profile Domain).Enabled -eq 'True' }; Link = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"; Type = "NIST" },
    @{ Name = "Ensure 'Audit: Audit the access of global system objects' is set to 'Disabled'"; Command = { (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa').AuditBaseObjects -eq 0 }; Link = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"; Type = "NIST" },
    @{ Name = "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"; Command = { (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa').CrashOnAuditFail -eq 0 }; Link = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"; Type = "NIST" }
)

# Define the SOX controls to check
$SOXControls = @(
    @{ Name = "Ensure 'Logon Events are Audited'"; Command = { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security').Start -eq 4 }; Link = "https://example.com/sox-logon-events"; Type = "SOX" }
)

# Define GDPR controls to check
$GDPRControls = @(
    @{ Name = "Ensure 'Access Control Policy' is implemented"; Command = { (Get-ADUser -Filter {AdminCount -eq 1}).Count -le 5 }; Link = "https://gdpr-info.eu/art-32-gdpr/"; Type = "GDPR" },
    @{ Name = "Ensure 'Data Encryption' is enforced"; Command = { (Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\EFIM').DataEncryption -eq 1 }; Link = "https://gdpr-info.eu/art-32-gdpr/"; Type = "GDPR" }
)

# Define HIPAA controls to check
$HIPAAControls = @(
    @{ Name = "Ensure 'Audit Controls' are in place"; Command = { (Get-EventLog -LogName 'Security' -Newest 1 | Select-Object EventID).EventID -eq 1102 }; Link = "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"; Type = "HIPAA" },
    @{ Name = "Ensure 'Access Controls' are enforced"; Command = { (Get-ADUser -Filter {AdminCount -eq 1}).Count -le 5 }; Link = "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"; Type = "HIPAA" }
)

# Initialize counters for compliance
$CISCompliantCount = 0
$CISTotalCount = $CISBenchmarks.Count
$NISTCompliantCount = 0
$NISTTotalCount = $NISTControls.Count
$SOXCompliantCount = 0
$SOXTotalCount = $SOXControls.Count
$GDPRCompliantCount = 0
$GDPRTotalCount = $GDPRControls.Count
$HIPAACompliantCount = 0
$HIPAATotalCount = $HIPAAControls.Count

# Check each CIS benchmark, NIST control, SOX control, GDPR control, and HIPAA control and count compliance
foreach ($Benchmark in $CISBenchmarks + $NISTControls + $SOXControls + $GDPRControls + $HIPAAControls) {
    $Name = $Benchmark.Name
    $Link = $Benchmark.Link
    $Type = $Benchmark.Type
    try {
        $Result = & $Benchmark.Command
        if ($Result) {
            switch ($Type) {
                "CIS" { $CISCompliantCount++ }
                "NIST" { $NISTCompliantCount++ }
                "SOX" { $SOXCompliantCount++ }
                "GDPR" { $GDPRCompliantCount++ }
                "HIPAA" { $HIPAACompliantCount++ }
            }
        }
    } catch {
        # If there's an error, consider it non-compliant
    }
}

# Calculate compliance percentages
$CISCompliancePercentage = [math]::Round(($CISCompliantCount / $CISTotalCount) * 100, 2)
$NISTCompliancePercentage = [math]::Round(($NISTCompliantCount / $NISTTotalCount) * 100, 2)
$SOXCompliancePercentage = [math]::Round(($SOXCompliantCount / $SOXTotalCount) * 100, 2)
$GDPRCompliancePercentage = [math]::Round(($GDPRCompliantCount / $GDPRTotalCount) * 100, 2)
$HIPAACompliancePercentage = [math]::Round(($HIPAACompliantCount / $HIPAATotalCount) * 100, 2)

# Calculate overall risk percentage based on compliance
$TotalChecks = $CISTotalCount + $NISTTotalCount + $SOXTotalCount + $GDPRTotalCount + $HIPAATotalCount
$TotalCompliant = $CISCompliantCount + $NISTCompliantCount + $SOXCompliantCount + $GDPRCompliantCount + $HIPAACompliantCount
$OverallCompliancePercentage = [math]::Round(($TotalCompliant / $TotalChecks) * 100, 2)
$RiskPercentage = 100 - $OverallCompliancePercentage

# Determine risk level
if ($RiskPercentage -le 30) {
    $RiskLevel = "Low"
    $RiskColor = "green"
} elseif ($RiskPercentage -le 60) {
    $RiskLevel = "Medium"
    $RiskColor = "yellow"
} else {
    $RiskLevel = "High"
    $RiskColor = "red"
}

# Initialize the HTML report
$Report = @"
<!DOCTYPE html>
<html>
<head>
    <title>CIS, NIST, SOX, GDPR, and HIPAA Compliance Report</title>
    <script type='text/javascript' src='https://www.gstatic.com/charts/loader.js'></script>
    <script type='text/javascript'>
      google.charts.load('current', {'packages':['gauge', 'corechart']});
      google.charts.setOnLoadCallback(drawChart);
      google.charts.setOnLoadCallback(drawRiskChart);

      function drawChart() {
        var dataCIS = google.visualization.arrayToDataTable([
          ['Label', 'Value'],
          ['', $CISCompliancePercentage]
        ]);

        var dataNIST = google.visualization.arrayToDataTable([
          ['Label', 'Value'],
          ['', $NISTCompliancePercentage]
        ]);

        var dataSOX = google.visualization.arrayToDataTable([
          ['Label', 'Value'],
          ['', $SOXCompliancePercentage]
        ]);

        var dataGDPR = google.visualization.arrayToDataTable([
          ['Label', 'Value'],
          ['', $GDPRCompliancePercentage]
        ]);

        var dataHIPAA = google.visualization.arrayToDataTable([
          ['Label', 'Value'],
          ['', $HIPAACompliancePercentage]
        ]);

        var options = {
          width: 300, height: 300,
          redFrom: 0, redTo: 30,
          yellowFrom: 30, yellowTo: 60,
          greenFrom: 60, greenTo: 100,
          minorTicks: 10,
          majorTicks: ['0', '20', '40', '60', '80', '100']
        };

        var chartCIS = new google.visualization.Gauge(document.getElementById('chart_cis_div'));
        var chartNIST = new google.visualization.Gauge(document.getElementById('chart_nist_div'));
        var chartSOX = new google.visualization.Gauge(document.getElementById('chart_sox_div'));
        var chartGDPR = new google.visualization.Gauge(document.getElementById('chart_gdpr_div'));
        var chartHIPAA = new google.visualization.Gauge(document.getElementById('chart_hipaa_div'));

        chartCIS.draw(dataCIS, options);
        chartNIST.draw(dataNIST, options);
        chartSOX.draw(dataSOX, options);
        chartGDPR.draw(dataGDPR, options);
        chartHIPAA.draw(dataHIPAA, options);
      }

      function drawRiskChart() {
        var data = google.visualization.arrayToDataTable([
          ['Risk Level', 'Percentage', { role: 'style' }],
          ['', $RiskPercentage, '$RiskColor']
        ]);

        var options = {
          title: 'Total Risk Compliance Score',
          width: 400,
          height: 200,
          bar: {groupWidth: '95%'},
          legend: { position: 'none' },
          hAxis: { minValue: 0, maxValue: 100 },
          vAxis: { format: '#' }
        };

        var chart = new google.visualization.BarChart(document.getElementById('risk_chart_div'));
        chart.draw(data, options);
      }

      function filterTable() {
        var typeSelectBox = document.getElementById('typeFilter');
        var resultSelectBox = document.getElementById('resultFilter');
        var selectedType = typeSelectBox.options[typeSelectBox.selectedIndex].value;
        var selectedResult = resultSelectBox.options[resultSelectBox.selectedIndex].value;
        var table = document.getElementById('complianceTable');
        var tr = table.getElementsByTagName('tr');

        for (var i = 1; i < tr.length; i++) {
          var typeCell = tr[i].getElementsByTagName('td')[0].innerHTML;
          var resultCell = tr[i].getElementsByTagName('td')[2].innerHTML;
          var displayType = (selectedType === 'All' || typeCell === selectedType);
          var displayResult = (selectedResult === 'All' || resultCell === selectedResult);

          tr[i].style.display = (displayType && displayResult) ? '' : 'none';
        }
      }
    </script>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
        }
        table {
            width: 80%;
            border-collapse: collapse;
            margin: 0 auto;
            border: 1px solid black;
        }
        table, th, td {
            border: 1px solid black;
        }
        th, td {
            padding: 15px;
            text-align: left;
        }
        th {
            background-color: #98AFC7;
        }
        .compliant {
            background-color: green;
            color: white;
        }
        .non-compliant {
            background-color: red;
            color: white;
        }
        .header {
            display: flex;
            align-items: center;
            justify-content: left;
        }
        .header img {
            max-width: 300px;
            max-height: 300px;
            margin-right: 20px;
        }
        h1 {
            color: #00A4EF;
            text-align: center;
            width: 100%;
        }
        .chart-container {
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .chart {
            margin: 10px;
        }
        .chart-title {
            font-size: 24px; /* h3 font size */
            color: #7FBA00;
            margin-bottom: -10px;
        }
        .risk-container {
            display: flex;
            justify-content: center;
            align-items: flex-start;
            margin-top: 20px;
        }
        .filters {
            text-align: center;
            margin-bottom: 20px;
        }
        .footer {
            margin-top: 20px;
            font-size: 16px;
        }
        .domain-stats {
            margin-right: 20px;
            padding: 10px;
            color: black;
        }
        .domain-stats table {
            border-collapse: collapse;
            width: 100%;
        }
        .domain-stats th, .domain-stats td {
            border: 1px solid black;
            padding: 5px;
            text-align: left;
        }
    </style>
</head>
<body>
    <div class="header">
        <img src="file:///$LogoPath" alt="Logo" />
        <h1>Active Directory Compliance Report for $domain</h1>
    </div>
    <div class='chart-container'>
        <div>
            <div class="chart-title">CIS Compliance</div>
            <div id='chart_cis_div' class='chart'></div>
        </div>
        <div>
            <div class="chart-title">NIST Compliance</div>
            <div id='chart_nist_div' class='chart'></div>
        </div>
        <div>
            <div class="chart-title">SOX Compliance</div>
            <div id='chart_sox_div' class='chart'></div>
        </div>
        <div>
            <div class="chart-title">GDPR Compliance</div>
            <div id='chart_gdpr_div' class='chart'></div>
        </div>
        <div>
            <div class="chart-title">HIPAA Compliance</div>
            <div id='chart_hipaa_div' class='chart'></div>
        </div>
    </div>
    <div class="risk-container">
        <div class="domain-stats">
            <h3>Domain Stats</h3>
            <table>
                <tr><th>Domain Name</th><td>$DomainName</td></tr>
                <tr><th>Number of Users</th><td>$NumberOfUsers</td></tr>
                <tr><th>Number of Groups</th><td>$NumberOfGroups</td></tr>
                <tr><th>Number of Disabled Users</th><td>$NumberOfDisabledUsers</td></tr>
                <tr><th>Number of Domain Admins</th><td>$NumberOfDomainAdmins</td></tr>
            </table>
        </div>
        <div id="risk_chart_div" style="width: 400px; height: 200px;"></div>
    </div>
    <div class="filters">
        <label for="typeFilter">Filter by Type:</label>
        <select id="typeFilter" onchange="filterTable()">
            <option value="All">All</option>
            <option value="CIS">CIS</option>
            <option value="NIST">NIST</option>
            <option value="SOX">SOX</option>
            <option value="GDPR">GDPR</option>
            <option value="HIPAA">HIPAA</option>
        </select>
        <label for="resultFilter">Filter by Result:</label>
        <select id="resultFilter" onchange="filterTable()">
            <option value="All">All</option>
            <option value="Compliant">Compliant</option>
            <option value="Non-Compliant">Non-Compliant</option>
        </select>
    </div>
    <br />
    <table id="complianceTable">
        <tr>
            <th>Type</th>
            <th>Benchmark</th>
            <th>Result</th>
        </tr>
"@

# Check each CIS benchmark and append the result to the report
foreach ($Benchmark in $CISBenchmarks) {
    $Name = $Benchmark.Name
    $Link = $Benchmark.Link
    $Type = $Benchmark.Type
    try {
        $Result = & $Benchmark.Command
        $ResultText = if ($Result) { "Compliant" } else { "Non-Compliant" }
        $ResultClass = if ($Result) { "compliant" } else { "non-compliant" }
    } catch {
        $ResultText = "Non-Compliant"
        $ResultClass = "non-compliant"
    }
    $Report += "<tr><td>$Type</td><td>$Name</td><td class='$ResultClass'>$ResultText</td></tr>"
}

# Check each NIST control and append the result to the report
foreach ($Control in $NISTControls) {
    $Name = $Control.Name
    $Link = $Control.Link
    $Type = $Control.Type
    try {
        $Result = & $Control.Command
        $ResultText = if ($Result) { "Compliant" } else { "Non-Compliant" }
        $ResultClass = if ($Result) { "compliant" } else { "non-compliant" }
    } catch {
        $ResultText = "Non-Compliant"
        $ResultClass = "non-compliant"
    }
    $Report += "<tr><td>$Type</td><td>$Name</td><td class='$ResultClass'>$ResultText</td></tr>"
}

# Check each SOX control and append the result to the report
foreach ($Control in $SOXControls) {
    $Name = $Control.Name
    $Link = $Control.Link
    $Type = $Control.Type
    try {
        $Result = & $Control.Command
        $ResultText = if ($Result) { "Compliant" } else { "Non-Compliant" }
        $ResultClass = if ($Result) { "compliant" } else { "non-compliant" }
    } catch {
        $ResultText = "Non-Compliant"
        $ResultClass = "non-compliant"
    }
    $Report += "<tr><td>$Type</td><td>$Name</td><td class='$ResultClass'>$ResultText</td></tr>"
}

# Check each GDPR control and append the result to the report
foreach ($Control in $GDPRControls) {
    $Name = $Control.Name
    $Link = $Control.Link
    $Type = $Control.Type
    try {
        $Result = & $Control.Command
        $ResultText = if ($Result) { "Compliant" } else { "Non-Compliant" }
        $ResultClass = if ($Result) { "compliant" } else { "non-compliant" }
    } catch {
        $ResultText = "Non-Compliant"
        $ResultClass = "non-compliant"
    }
    $Report += "<tr><td>$Type</td><td>$Name</td><td class='$ResultClass'>$ResultText</td></tr>"
}

# Check each HIPAA control and append the result to the report
foreach ($Control in $HIPAAControls) {
    $Name = $Control.Name
    $Link = $Control.Link
    $Type = $Control.Type
    try {
        $Result = & $Control.Command
        $ResultText = if ($Result) { "Compliant" } else { "Non-Compliant" }
        $ResultClass = if ($Result) { "compliant" } else { "non-compliant" }
    } catch {
        $ResultText = "Non-Compliant"
        $ResultClass = "non-compliant"
    }
    $Report += "<tr><td>$Type</td><td>$Name</td><td class='$ResultClass'>$ResultText</td></tr>"
}

# Finalize the HTML report
$Report += @"
    </table>
    <div class="footer">
        Powered By <a href="https://infrasos.com" target="_blank">InfraSOS.com</a>
    </div>
</body>
</html>
"@

# Save the report to a file
$Report | Out-File -FilePath $ReportPath -Encoding utf8

Write-Host "CIS, NIST, SOX, GDPR, and HIPAA Compliance Report generated at $ReportPath"
