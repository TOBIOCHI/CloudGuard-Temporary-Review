
/* =====================================================
   CLOUDGUARD - DASHBOARD JAVASCRIPT
   ===================================================== */

document.addEventListener("DOMContentLoaded", function () {

    "use strict";

    // -------------------------------------------------
    // 1. Confirm before starting an AWS scan
    // -------------------------------------------------

    const scanForms = document.querySelectorAll(
        'form[action="/run-scan"]'
    );

    scanForms.forEach(function (form) {

        form.addEventListener("submit", function (event) {

            const confirmed = window.confirm(
                "Start a new AWS security scan?\n\n" +
                "CloudGuard will perform read-only security checks."
            );

            if (!confirmed) {
                event.preventDefault();
            }

        });

    });


    // -------------------------------------------------
    // 2. Automatically dismiss flash messages
    // -------------------------------------------------

    const flashMessages = document.querySelectorAll(
        ".alert-dismissible"
    );

    flashMessages.forEach(function (message) {

        window.setTimeout(function () {

            if (message && message.parentNode) {

                message.style.transition = "opacity 0.4s ease";
                message.style.opacity = "0";

                window.setTimeout(function () {

                    if (message.parentNode) {
                        message.remove();
                    }

                }, 450);

            }

        }, 6000);

    });


    // -------------------------------------------------
    // 3. Finding search and severity filter
    // -------------------------------------------------

    const findingTable = document.querySelector(
        "#findingsTable"
    );

    const findingSearch = document.querySelector(
        "#findingSearch"
    );

    const severityFilter = document.querySelector(
        "#severityFilter"
    );

    const noFindingsMatch = document.querySelector(
        "#noFindingsMatch"
    );

    if (findingTable) {

        const rows = findingTable.querySelectorAll(
            "tbody tr[data-severity]"
        );

        function applyFindingFilters() {

            const searchTerm = findingSearch
                ? findingSearch.value.toLowerCase().trim()
                : "";

            const selectedSeverity = severityFilter
                ? severityFilter.value.toUpperCase()
                : "";

            let visibleCount = 0;

            rows.forEach(function (row) {

                const rowText = row.textContent.toLowerCase();

                const rowSeverity = (
                    row.dataset.severity || ""
                ).toUpperCase();

                const matchesSearch = rowText.includes(searchTerm);

                const matchesSeverity =
                    !selectedSeverity ||
                    rowSeverity === selectedSeverity;

                const shouldShow =
                    matchesSearch && matchesSeverity;

                row.style.display = shouldShow ? "" : "none";

                if (shouldShow) {
                    visibleCount++;
                }

            });

            if (noFindingsMatch) {
                noFindingsMatch.style.display =
                    visibleCount === 0 ? "" : "none";
            }

        }

        if (findingSearch) {
            findingSearch.addEventListener(
                "input",
                applyFindingFilters
            );
        }

        if (severityFilter) {
            severityFilter.addEventListener(
                "change",
                applyFindingFilters
            );
        }

    }


    // -------------------------------------------------
    // 4. Update current year
    // -------------------------------------------------

    const yearElement = document.querySelector(
        "#currentYear"
    );

    if (yearElement) {
        yearElement.textContent = new Date().getFullYear();
    }


    // -------------------------------------------------
    // 5. Log dashboard initialization
    // -------------------------------------------------

    console.info(
        "CloudGuard dashboard initialized successfully."
    );

});
