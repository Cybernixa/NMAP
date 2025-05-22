$(document).ready(function() {
    // Initialize DataTable
    const dataTable = $('#resultsTable').DataTable({
        responsive: true,
        columns: [
            { data: 'host', title: 'Host' },
            { data: 'port', title: 'Port' },
            { data: 'service.name', title: 'Service Name' },
            { data: 'service.product', title: 'Product' },
            { data: 'service.version', title: 'Version' },
            {
                data: 'vulnerability_count',
                title: 'CVEs',
                className: 'text-center',
                render: function(data, type, row) {
                    let badgeClass = 'none'; // Default for 0 vulnerabilities
                    if (data > 0) {
                        let maxSeverity = 'UNKNOWN';
                        if (row.vulnerabilities && row.vulnerabilities.length > 0) {
                            const severities = row.vulnerabilities.map(v => v.severity);
                            if (severities.includes('CRITICAL')) maxSeverity = 'CRITICAL';
                            else if (severities.includes('HIGH')) maxSeverity = 'HIGH';
                            else if (severities.includes('MEDIUM')) maxSeverity = 'MEDIUM';
                            else if (severities.includes('LOW')) maxSeverity = 'LOW';
                        }
                        
                        if (maxSeverity === 'CRITICAL') badgeClass = 'critical';
                        else if (maxSeverity === 'HIGH') badgeClass = 'high';
                        else if (maxSeverity === 'MEDIUM') badgeClass = 'medium';
                        else if (maxSeverity === 'LOW') badgeClass = 'low';
                        else badgeClass = 'high'; // Default to high if count > 0 but no specific severities
                    }
                    return `<span class="vuln-count-badge ${badgeClass}">${data}</span>`;
                }
            }
        ],
        language: {
            emptyTable: "No findings to display.",
            zeroRecords: "No matching records found."
        },
        order: [[5, 'desc'], [0, 'asc']] // Sort by vulnerability count desc, then host asc
    });

    // Event Listeners
    $('#scanButton').on('click', startScan);
    $('#target').on('keypress', function(e) {
        if (e.key === 'Enter') {
            startScan();
        }
    });

    async function startScan() {
        const target = $('#target').val().trim(); // Use .val() for jQuery
        if (!target) {
            showScanError('Please enter an IP address or hostname.');
            return;
        }
        hideScanError();
        showLoading(true);
        hideResults();

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ target: target })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ detail: 'Unknown server error' }));
                throw new Error(`Scan failed: ${response.status} ${response.statusText}. ${errorData.detail || ''}`);
            }

            const data = await response.json();
            if (data.error) {
                 showScanError(`Scan error: ${data.error}. ${data.details || ''}`);
            } else {
                updateResults(data);
            }
        } catch (error) {
            console.error('Error during scan:', error);
            showScanError('An unexpected error occurred: ' + error.message);
        } finally {
            showLoading(false);
        }
    }

    function updateResults(data) {
        if (data.summary) {
            $('#total-hosts').text(data.summary.total_hosts || 0);
            $('#total-services').text(data.summary.total_services || 0);
            $('#total-vulnerabilities').text(data.summary.total_vulnerabilities_found || 0);
        }

        dataTable.clear();
        if (data.findings && data.findings.length > 0) {
            dataTable.rows.add(data.findings);
        }
        dataTable.draw();
        
        showResults();
    }

    function showLoading(show) {
        if (show) {
            $('#loading-spinner').removeClass('d-none');
        } else {
            $('#loading-spinner').addClass('d-none');
        }
    }

    function showResults() {
        $('#results-section').removeClass('d-none');
    }

    function hideResults() {
        $('#results-section').addClass('d-none');
    }

    function showScanError(message) {
        const errorDiv = $('#scan-error-message');
        errorDiv.text(message);
        errorDiv.removeClass('d-none');
    }
    function hideScanError() {
        $('#scan-error-message').addClass('d-none');
    }
});