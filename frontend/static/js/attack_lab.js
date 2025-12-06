/**
 * Attack Lab JavaScript Module
 * 
 * Handles attack simulations and UI updates for the SecureChat Attack Lab.
 */

class AttackLab {
    constructor() {
        this.vulnerableButtons = document.querySelectorAll('.btn-attack[data-mode="vulnerable"]');
        this.defendedButtons = document.querySelectorAll('.btn-attack[data-mode="defended"]');
    }

    init() {
        // Set up event listeners for attack buttons
        this.vulnerableButtons.forEach(button => {
            button.addEventListener('click', () => this.runAttack(button.dataset.attack, 'vulnerable'));
        });

        this.defendedButtons.forEach(button => {
            button.addEventListener('click', () => this.runAttack(button.dataset.attack, 'defended'));
        });
    }

    async runAttack(attackType, mode) {
        try {
            // Show loading state
            this.updateStatus(attackType, mode, 'Running...');
            
            // Determine endpoint URL
            const endpoint = `/api/lab/${attackType}/${mode}`;
            
            // Send request to backend
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            
            // Update UI with results
            this.updateResult(attackType, mode, data);
            this.updateLog(attackType, mode, data.log);
            
        } catch (error) {
            console.error('Attack simulation failed:', error);
            this.updateStatus(attackType, mode, `Error: ${error.message}`);
        }
    }

    updateStatus(attackType, mode, status) {
        const statusElement = document.getElementById(`${attackType}-${mode}-status`);
        if (statusElement) {
            statusElement.textContent = status;
        }
    }

    updateResult(attackType, mode, result) {
        const resultElement = document.getElementById(`${attackType}-${mode}-result`);
        if (resultElement) {
            let statusClass = 'danger';
            let statusText = result.result;
            
            // Determine status based on result
            if (result.result.includes('blocked') || result.result.includes('failed')) {
                statusClass = 'success';
            }
            
            // Handle DoS system status if present
            let systemStatusHtml = '';
            if (result.system_status) {
                systemStatusHtml = `
                    <div class="system-status">
                        <strong>System Status:</strong><br>
                        Blocked Requests: ${result.system_status.blocked_requests}<br>
                        Allowed Requests: ${result.system_status.allowed_requests}<br>
                        Total Requests: ${result.system_status.total_requests}<br>
                        Rate Limit Config: ${JSON.stringify(result.system_status.rate_limit_config)}
                    </div>
                `;
            }
            
            resultElement.innerHTML = `
                <div class="result-box ${statusClass}">
                    <strong>Result:</strong> ${statusText}
                    ${systemStatusHtml}
                </div>
            `;
        }
    }

    updateLog(attackType, mode, logMessage) {
        const logElement = document.getElementById(`${attackType}-${mode}-log`);
        if (logElement) {
            // Clear placeholder if present
            logElement.innerHTML = '';
            
            // Create log entry
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            logEntry.textContent = `> ${logMessage}`;
            logElement.appendChild(logEntry);
            
            // Scroll to bottom
            logElement.scrollTop = logElement.scrollHeight;
        }
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.AttackLab = new AttackLab();
    window.AttackLab.init();
});