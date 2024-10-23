const leaveSummaryTab = document.getElementById('leave-summary-tab');
const leaveRequestsTab = document.getElementById('leave-requests-tab');
const teamLeavesTab = document.getElementById('team-leaves-tab');
const teamSummaryTab = document.getElementById('team-summary-tab');

const leaveSummarySection = document.getElementById('leave-summary-section');
const leaveRequestsSection = document.getElementById('leave-requests-section');
const teamLeavesSection = document.getElementById('team-leaves-section');
const teamSummarySection = document.getElementById('team-summary-section');

const modal = document.getElementById('apply-leave-modal');
const openModalButton = document.querySelector('.apply-leave');
const closeButton = document.querySelector('.close-button');

const applyLeaveModal = document.getElementById('apply-leave-modal');
const leaveTypeSelect = document.getElementById('leave-type');

const fromDateInput = document.getElementById('from-date');
const toDateInput = document.getElementById('to-date');

let genderEmployee = "Male";

const leaveStore = {
    compensatoryOff: -1,
    lossOffPay: -1,
    personalTimeOff: -1,
    paternityLeave: -1,
    maternityLeave: -1
};

document.getElementById('mydata-js').addEventListener('click', () => {
    document.getElementById('teamdata-js').classList.remove('active');
    document.getElementById('mydata-js').classList.add('active');

    leaveRequestsTab.classList.remove('active');
    teamSummaryTab.classList.remove('active');
    
    teamLeavesTab.style.display = 'none';
    teamSummaryTab.style.display = 'none';
    
    teamLeavesSection.style.display = 'none';
    teamSummarySection.style.display = 'none';
    
    leaveSummaryTab.style.display = 'block';
    leaveSummarySection.style.display = 'block';
    leaveSummaryTab.classList.add('active');
    
    addRecentLeaves();

    leaveRequestsTab.style.display = 'block';
});

document.getElementById('teamdata-js').addEventListener('click', () => {
    document.getElementById('teamdata-js').classList.add('active');
    document.getElementById('mydata-js').classList.remove('active');

    leaveSummaryTab.classList.remove('active');
    leaveRequestsTab.classList.remove('active');
    
    leaveSummaryTab.style.display = 'none';
    leaveRequestsTab.style.display = 'none';
    
    leaveSummarySection.style.display = 'none';
    leaveRequestsSection.style.display = 'none';
    
    teamLeavesTab.style.display = 'block';
    teamLeavesSection.style.display = 'block';
    teamLeavesTab.classList.add('active');

    teamSummaryTab.style.display = 'block';

    fetchTeamLeave('all');
    
});

leaveSummaryTab.addEventListener('click', () => {
    leaveSummaryTab.classList.add('active');
    leaveRequestsTab.classList.remove('active');
    teamLeavesTab.classList.remove('active');
    teamSummaryTab.classList.remove('active');
    
    leaveSummarySection.style.display = 'block';
    leaveRequestsSection.style.display = 'none';
    teamLeavesSection.style.display = 'none';
    teamSummarySection.style.display = 'none';
    
    addRecentLeaves();
});

leaveRequestsTab.addEventListener('click', () => {
    leaveRequestsTab.classList.add('active');
    leaveSummaryTab.classList.remove('active');
    teamLeavesTab.classList.remove('active');
    teamSummaryTab.classList.remove('active');
    
    leaveSummarySection.style.display = 'none';
    leaveRequestsSection.style.display = 'block';
    teamLeavesSection.style.display = 'none';
    teamSummarySection.style.display = 'none';
    
    addLeaveRequests("all");
});

teamLeavesTab.addEventListener('click', () => {
    teamLeavesTab.classList.add('active');
    leaveSummaryTab.classList.remove('active');
    leaveRequestsTab.classList.remove('active');
    teamSummaryTab.classList.remove('active');
    
    leaveSummarySection.style.display = 'none';
    leaveRequestsSection.style.display = 'none';
    teamLeavesSection.style.display = 'block';
    teamSummarySection.style.display = 'none';
    
    fetchTeamLeave('all');
});

teamSummaryTab.addEventListener('click', () => {
    teamSummaryTab.classList.add('active');
    leaveSummaryTab.classList.remove('active');
    leaveRequestsTab.classList.remove('active');
    teamLeavesTab.classList.remove('active');
    
    leaveSummarySection.style.display = 'none';
    leaveRequestsSection.style.display = 'none';
    teamLeavesSection.style.display = 'none';
    teamSummarySection.style.display = 'block';
    
    fetchLeaveSummaryData();
});


function addLeaveRow(leaveType, reason, fromDate, toDate, leaveCount) {
    const tableBody = document.getElementById('recent-leaves-table-js');
    
    const newRow = document.createElement('tr');
    
    const leaveTypeCell = document.createElement('td');
    leaveTypeCell.textContent = leaveType;
    newRow.appendChild(leaveTypeCell);
    const reasonCell = document.createElement('td');
    reasonCell.textContent = reason;
    newRow.appendChild(reasonCell);
    const fromDateCell = document.createElement('td');
    fromDateCell.textContent = fromDate;
    newRow.appendChild(fromDateCell);
    const toDateCell = document.createElement('td');
    toDateCell.textContent = toDate;
    newRow.appendChild(toDateCell);
    const leaveCountCell = document.createElement('td');
    leaveCountCell.textContent = leaveCount;
    newRow.appendChild(leaveCountCell);
    
    tableBody.appendChild(newRow);
}

function fetchAndDisplayHolidays() {
    fetch('http://localhost:8080/LeaveManagement/holidays')
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
            return response.json();
        })
        .then(data => {
            const leaveList = document.querySelector('.leave-list');
            leaveList.innerHTML = '';
            data.forEach(item => {
                const listItem = document.createElement('li');
                const dateSpan = document.createElement('span');
                const holidaySpan = document.createElement('span');

                dateSpan.className = 'date';
                dateSpan.textContent = new Date(item.holidayDate).toLocaleDateString('en-GB', {
                    day: '2-digit',
                    month: 'short',
                    year: 'numeric'
                });
                holidaySpan.className = 'holiday';
                holidaySpan.textContent = item.holidayName;

                listItem.appendChild(dateSpan);
                listItem.appendChild(holidaySpan);
                leaveList.appendChild(listItem);
            });
        })
        .catch(error => {
            console.error('Error fetching the holidays:', error);
            document.querySelector('.leaves-header').textContent = 'Failed to load holidays.';
        });
}

fetchAndDisplayHolidays();
fetchGenderForEmployee();
addRecentLeaves();
doEmployeeHadTeam();

function genderComponent(gender) {
    const leaveSummarySectionCard = document.getElementById('leave-summary-section');
    const summaryDiv = leaveSummarySectionCard.querySelector('.summary');

    summaryDiv.innerHTML = '';

    let compensatoryOffCard = document.createElement('div');
    compensatoryOffCard.className = 'card';
    compensatoryOffCard.innerHTML = `
        <div class="card-header">Compensatory Off</div>
        <div class="card-body">
            <div class="available">Available</div>
            <div class="count">5</div>
            <div class="booked">Booked</div>
            <div class="count" id="used-compensatiory">0</div>
        </div>`;
    summaryDiv.appendChild(compensatoryOffCard);

    let lossOfPayCard = document.createElement('div');
    lossOfPayCard.className = 'card';
    lossOfPayCard.innerHTML = `
        <div class="card-header">Loss of Pay</div>
        <div class="card-body">
            <div class="available">Available</div>
            <div class="count">5</div>
            <div class="booked">Booked</div>
            <div class="count" id="used-lossofpay">0</div>
        </div>`;
    summaryDiv.appendChild(lossOfPayCard);

    let personalTimeOffCard = document.createElement('div');
    personalTimeOffCard.className = 'card';
    personalTimeOffCard.innerHTML = `
        <div class="card-header">Personal Time Off</div>
        <div class="card-body">
            <div class="available">Available</div>
            <div class="count">15</div>
            <div class="booked">Booked</div>
            <div class="count" id="used-personaltimeoff">0</div>
        </div>`;
    summaryDiv.appendChild(personalTimeOffCard);

    let newCard = document.createElement('div');
    newCard.className = 'card';
    if (gender === 'Male') {
        newCard.innerHTML = `
            <div class="card-header">Paternity Leave</div>
            <div class="card-body">
                <div class="available">Available</div>
                <div class="count">9</div>
                <div class="booked">Booked</div>
                <div class="count" id="count-paternityleave">0</div>
            </div>`;
    } else if (gender === 'Female') {
        newCard.innerHTML = `
            <div class="card-header">Maternity Leave</div>
            <div class="card-body">
                <div class="available">Available</div>
                <div class="count">90</div>
                <div class="booked">Booked</div>
                <div class="count" id="count-maternityleaves">0</div>
            </div>`;
    }
    summaryDiv.appendChild(newCard);
}

function adjustLeaveOptions(gender) {
    const paternityLeaveOption = leaveTypeSelect.querySelector('option[value="Paternity Leave"]');
    const maternityLeaveOption = leaveTypeSelect.querySelector('option[value="Maternity Leave"]');
    if (gender === 'Male') {
        paternityLeaveOption.style.display = 'block';
        maternityLeaveOption.style.display = 'none';
    } else if (gender === 'Female') {
        paternityLeaveOption.style.display = 'none';
        maternityLeaveOption.style.display = 'block';
    } else {
        paternityLeaveOption.style.display = 'none';
        maternityLeaveOption.style.display = 'none';
    }
}

function fetchLeaveSummary(gender) {
    genderComponent(gender);
    adjustLeaveOptions(gender);
    fetch('http://localhost:8080/LeaveManagement/leaves_summary')
        .then(response => response.json())
        .then(data => {
            leaveStore.compensatoryOff = data.compensatoryOff || 0;
            leaveStore.lossOffPay = data.lossOffPay || 0;
            leaveStore.personalTimeOff = data.personalTimeOff || 0;

            if (gender === 'Male') {
                leaveStore.paternityLeave = data.paternityLeave || 0;
            } else if (gender === 'Female') {
                leaveStore.maternityLeave = data.maternityLeave || 0;
            }

            document.getElementById('used-compensatiory').textContent = data.compensatoryOff;
            document.getElementById('used-lossofpay').textContent = data.lossOffPay;
            document.getElementById('used-personaltimeoff').textContent = data.personalTimeOff;

            if (gender == 'Male') {
                document.getElementById('count-paternityleave').textContent = data.paternityLeave;
            }
            else if (data.gender == 'Female') {
                document.getElementById('count-maternityleaves').textContent = data.maternityLeave;
            }
        })
        .catch(error => console.error('Error fetching leave summary:', error));
}

const removeAll = document.getElementById('remove-all');

removeAll.addEventListener('click', function () {
    fetch('http://localhost:8080/LeaveManagement/logout', {
        method: 'POST',
        credentials: 'include'
    })
        .then(response => {
            if (response.ok) {
                window.location.href = 'http://localhost:8080/LeaveManagement';
            } else {
                console.error('Logout failed:', response.statusText);
            }
        })
        .catch(error => {
            console.error('Error during logout:', error);
        });
});

function addRecentLeaves() {
    const tableBody = document.getElementById('recent-leaves-table-js');
    tableBody.innerHTML = '';
    fetch('http://localhost:8080/LeaveManagement/recent_leaves')
        .then(response => response.json())
        .then(data => {
            for (const leave of data) {

                addLeaveRow(
                    leave.leaveType,
                    leave.reason,
                    leave.fromDate,
                    leave.toDate,
                    leave.leaveCount
                );
            }
        })
        .catch(error => console.error('Error fetching employee recent leaves:', error));
}

function fetchGenderForEmployee() {
    fetch('http://localhost:8080/LeaveManagement/gender')
        .then(response => response.json())
        .then(data => {
            let dataArr = data.split(" ");
            let gender = dataArr[0];
            let employeeName = dataArr[1];

            let profileInitial = document.getElementById('shortName-ui');
            let profileName = document.getElementById('employeeName-ui');

            profileInitial.textContent = employeeName.charAt(0);
            profileName.textContent = employeeName;
            genderEmployee = gender;
            fetchLeaveSummary(gender);
        }
        )
        .catch(error => console.error('Error fetching employee recent leaves:', error));
}
function doEmployeeHadTeam() {
    fetch('http://localhost:8080/LeaveManagement/employee_had_team')
        .then(response => response.json())
        .then(data => {
            if (data) {
                document.getElementById('teamdata-js').style.display = 'block';
            }
        }
        )
        .catch(error => console.error('Error fetching employee recent leaves:', error));
}

function disableWeekends(date) {
    const day = date.getDay();
    return day === 0 || day === 6;
}

function disableDates(input) {
    input.addEventListener('input', function () {
        const date = new Date(this.value);
        const today = new Date();
        if (date < today) {
            this.value = '';
            alert('You cannot select a past date.');
        } else if (disableWeekends(date)) {
            this.value = '';
            alert('You cannot select a weekend.');
        }
    });
}

fromDateInput.addEventListener('input', function () {
    const fromDate = new Date(fromDateInput.value);
    toDateInput.min = fromDate.toISOString().split('T')[0];
    if (disableWeekends(fromDate)) {
        fromDateInput.value = '';
        alert('You cannot select a weekend.');
    }
});

toDateInput.addEventListener('input', function () {
    const fromDate = new Date(fromDateInput.value);
    const toDate = new Date(toDateInput.value);
    if (toDate < fromDate) {
        toDateInput.value = '';
        alert('The "To Date" cannot be before the "From Date".');
    } else if (disableWeekends(toDate)) {
        toDateInput.value = '';
        alert('You cannot select a weekend.');
    }
});

disableDates(fromDateInput);
disableDates(toDateInput);

function addLeaveRequestRow(leaveType, reason, fromDate, toDate, leaveCount, status) {
    const tableBody = document.getElementById('leave-requests-table-js');

    const newRow = document.createElement('tr');
    const leaveTypeCell = document.createElement('td');
    leaveTypeCell.textContent = leaveType;
    newRow.appendChild(leaveTypeCell);
    const reasonCell = document.createElement('td');
    reasonCell.textContent = reason;
    newRow.appendChild(reasonCell);
    const fromDateCell = document.createElement('td');
    fromDateCell.textContent = fromDate;
    newRow.appendChild(fromDateCell);
    const toDateCell = document.createElement('td');
    toDateCell.textContent = toDate;
    newRow.appendChild(toDateCell);
    const leaveCountCell = document.createElement('td');
    leaveCountCell.textContent = leaveCount;
    newRow.appendChild(leaveCountCell);
    const statusCell = document.createElement('td');
    if (status === 'Approved') {
        statusCell.innerHTML = '<span class="accepted-text">Approved</span>';
    } else if (status === 'Rejected') {
        statusCell.innerHTML = '<span class="rejected-text">Rejected</span>';
    } else if (status === 'Pending') {
        statusCell.innerHTML = '<span class="pending-text">Pending</span>';
    } else {
        statusCell.textContent = status;
    }

    newRow.appendChild(statusCell);
    tableBody.appendChild(newRow);
}
document.getElementById('leave-status-filter').addEventListener('change', function () {
    const selectedStatus = encodeURIComponent(this.value);
    addLeaveRequests(selectedStatus);
});

document.getElementById('team-leave-filter').addEventListener('change', function () {
    const teamLeaveStatus = encodeURIComponent(this.value)
    fetchTeamLeave(teamLeaveStatus);
})

function addLeaveRequests(status) {
    const tableBody = document.getElementById('leave-requests-table-js');
    tableBody.innerHTML = '';
    fetch(`http://localhost:8080/LeaveManagement/employees?status=${status}`)
        .then(response => response.json())
        .then(data => {
            for (const leave of data) {

                addLeaveRequestRow(
                    leave.leaveType,
                    leave.reason,
                    leave.fromDate,
                    leave.toDate,
                    leave.leaveCount,
                    leave.status
                );
            }
        })
        .catch(error => console.error('Error fetching employee total leaves:', error));
}

function fetchTeamLeave(status) {
    const tableBody = document.getElementById('team-leaves-table-js');
    tableBody.innerHTML = '';
    console.log(status);
    fetch(`http://localhost:8080/LeaveManagement/leave_request?status=${status}`)
        .then(response => response.json())
        .then(data => {
            for (const requestLeave of data) {
                addTeamLeaveRow(
                    requestLeave.leaveId,
                    requestLeave.employeeId,
                    requestLeave.employeeName,
                    requestLeave.leaveType,
                    requestLeave.reason,
                    requestLeave.fromDate,
                    requestLeave.toDate,
                    requestLeave.leaveCount,
                    requestLeave.createdAt,
                    requestLeave.status
                );
            }
        })
        .catch(error => console.error('Error fetching employee total leaves:', error));
}

function addTeamLeaveRow(leaveId, employeeId, employeeName, leaveType, reason, fromDate, toDate, leaveCount, createdAt, status) {
    const tableBody = document.getElementById('team-leaves-table-js');

    const newRow = document.createElement('tr');
    newRow.setAttribute('data-leave-id', leaveId);

    const employeeIdCell = document.createElement('td');
    employeeIdCell.textContent = employeeId;
    newRow.appendChild(employeeIdCell);

    const employeeNameCell = document.createElement('td');
    employeeNameCell.textContent = employeeName;
    newRow.appendChild(employeeNameCell);

    const leaveTypeCell = document.createElement('td');
    leaveTypeCell.textContent = leaveType;
    newRow.appendChild(leaveTypeCell);

    const reasonCell = document.createElement('td');
    reasonCell.textContent = reason;
    newRow.appendChild(reasonCell);

    const fromDateCell = document.createElement('td');
    fromDateCell.textContent = fromDate;
    newRow.appendChild(fromDateCell);

    const toDateCell = document.createElement('td');
    toDateCell.textContent = toDate;
    newRow.appendChild(toDateCell);

    const leaveCountCell = document.createElement('td');
    leaveCountCell.textContent = leaveCount;
    newRow.appendChild(leaveCountCell);

    const createdAtCell = document.createElement('td');
    createdAtCell.textContent = createdAt;
    newRow.appendChild(createdAtCell);

    const actionCell = document.createElement('td');

    if (status === 'Pending') {
        const acceptButton = document.createElement('button');
        acceptButton.textContent = 'Accept';
        acceptButton.classList.add('accept-button');
        acceptButton.setAttribute('data-leave-id', leaveId);

        const rejectButton = document.createElement('button');
        rejectButton.textContent = 'Reject';
        rejectButton.classList.add('reject-button');
        rejectButton.setAttribute('data-leave-id', leaveId);

        acceptButton.addEventListener('click', function () {
            updateLeaveStatus(leaveId, 'Approved', actionCell);
        });

        rejectButton.addEventListener('click', function () {
            updateLeaveStatus(leaveId, 'Rejected', actionCell);
        });

        actionCell.appendChild(acceptButton);
        actionCell.appendChild(rejectButton);
    } else if (status === 'Approved') {
        actionCell.innerHTML = '<span class="accepted-text">Approved</span>';
    } else if (status === 'Rejected') {
        actionCell.innerHTML = '<span class="rejected-text">Rejected</span>';
    }

    newRow.appendChild(actionCell);
    tableBody.appendChild(newRow);
}

function updateLeaveStatus(leaveId, status, actionCell) {
    fetch('http://localhost:8080/LeaveManagement/employees', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ leaveId: leaveId, status: status })
    })
        .then(response => {
            if (response.ok) {
                if (status === 'Approved') {
                    actionCell.innerHTML = '<span class="accepted-text">Approved</span>';
                } else if (status === 'Rejected') {
                    actionCell.innerHTML = '<span class="rejected-text">Rejected</span>';
                }
            } else {
                throw new Error('Failed to update leave status');
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
}


openModalButton.addEventListener('click', function () {
    modal.style.display = 'flex';
});

closeButton.addEventListener('click', function () {
    modal.style.display = 'none';
});

window.addEventListener('click', function (event) {
    if (event.target === modal) {
        modal.style.display = 'none';
    }
});

function calculateWeekdays(fromDate, toDate) {

    const start = new Date(fromDate);
    const end = new Date(toDate);
    let leaveCount = 0;

    while (start <= end) {
        // Get the day of the week (0 = Sunday, 1 = Monday, ..., 6 = Saturday)
        const dayOfWeek = start.getDay();
        if (dayOfWeek !== 0 && dayOfWeek !== 6) {
            leaveCount++;
        }
        start.setDate(start.getDate() + 1);
    }

    return leaveCount;
}


document.getElementById('apply-leave-form').addEventListener('submit', function (event) {
    event.preventDefault();

    const leaveType = document.getElementById('leave-type').value;
    const reason = document.getElementById('reason').value;
    const fromDate = document.getElementById('from-date').value;
    const toDate = document.getElementById('to-date').value;
    const leaveCount = calculateWeekdays(fromDate, toDate);

    const leaveData = {
        leaveType: leaveType,
        reason: reason,
        fromDate: fromDate,
        toDate: toDate,
        createdAt: new Date().toISOString().split('T')[0],
        leaveCount: leaveCount,
        status: "Pending"
    };

    let maxLeaveAllowed = 0;
    let errorMessage = '';
    const errorElement = document.getElementById('error-message');

    // Clear any previous error message
    errorElement.style.display = 'none';
    errorElement.textContent = '';

    switch (leaveType) {
        case 'Compensatory Off':
            maxLeaveAllowed = leaveStore.compensatoryOff + leaveData.leaveCount;
            if (maxLeaveAllowed > 5) {
                errorMessage = `Exceeded ${5 - leaveStore.compensatoryOff} days limit for Compensatory Off.`;
            }
            break;
        case 'Loss of Pay':
            maxLeaveAllowed = leaveStore.lossOffPay + leaveData.leaveCount;
            if (maxLeaveAllowed > 5) {
                errorMessage = `Exceeded ${5 - leaveStore.lossOffPay} days limit for Loss of Pay.`;
            }
            break;
        case 'Personal Time Off':
            maxLeaveAllowed = leaveStore.personalTimeOff + leaveData.leaveCount;
            if (maxLeaveAllowed > 15) {
                errorMessage = `Exceeded ${15 - leaveStore.personalTimeOff} days limit for Personal Time Off.`;
            }
            break;
        case 'Paternity Leave':
            maxLeaveAllowed = leaveStore.paternityLeave + leaveData.leaveCount;
            if (maxLeaveAllowed > 9) {
                errorMessage = `Exceeded ${9 - leaveStore.paternityLeave} days limit for Paternity Leave.`;
            }
            break;
        case 'Maternity Leave':
            maxLeaveAllowed = leaveStore.maternityLeave + leaveData.leaveCount;
            if (maxLeaveAllowed > 90) {
                errorMessage = `Exceeded ${5 - leaveStore.maternityLeave} days limit for Maternity Leave.`;
            }
            break;
        default:
            console.error('Invalid leave type');
            return;
    }

    if (errorMessage) {
        errorElement.style.display = 'block';
        errorElement.textContent = errorMessage;
        return;
    }
    fetch('http://localhost:8080/LeaveManagement/employees', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(leaveData)
    })
        .then(response => {
            if (response.ok) {
                return response.json();
            }
            throw new Error('Network response was not ok');
        })
        .then(data => {
            console.log('Success:', data);
        })
        .catch(error => {
            console.error('Error:', error);
        });

    const modal = document.getElementById('apply-leave-modal');
    modal.style.display = 'none';
});

const dropdownButton = document.getElementById('dropdownAvatarNameButton');
const dropdownMenu = document.getElementById('dropdownAvatarName');

dropdownButton.addEventListener('click', function (event) {
    event.stopPropagation();
    dropdownMenu.classList.toggle('show');
});

document.addEventListener('click', function (event) {
    if (!dropdownButton.contains(event.target) && !dropdownMenu.contains(event.target)) {
        dropdownMenu.classList.remove('show');
    }
});

dropdownMenu.addEventListener('click', function (event) {
    dropdownMenu.classList.remove('show');
});

function fetchLeaveSummaryData() {
    fetch('http://localhost:8080/LeaveManagement/team_leaves_summary')
        .then(response => response.json())
        .then(data => {
            const processedTeamMembers = data.map(member => {
                let dataArr = member.gender.split(" ");
                member.gender = dataArr[0];
                return {
                    name: member.employeeName,
                    compensatoryOffAllowed: 5, 
                    compensatoryOffTaken: member.compensatoryOff,
                    lossOfPayAllowed: 5,
                    lossOfPayTaken: member.lossOffPay,
                    personalTimeOffAllowed: 15,
                    personalTimeOffTaken: member.personalTimeOff,
                    gender: member.gender,
                    maternityLeaveTaken: member.gender === 'Female' ? member.maternityLeave : null,
                    paternityLeaveTaken: member.gender === 'Male' ? member.paterpaternityLeavenityLeave : null
                };
            });
            displayTeamSummary(processedTeamMembers);
        })
        .catch(error => console.error('Error fetching employee total leaves:', error));
}

function displayTeamSummary(teamMembers) {
    const teamSummaryContainer = document.getElementById('team-summary-container');
    teamSummaryContainer.innerHTML = ''; 

    teamMembers.forEach(member => {
        const card = document.createElement('div');
        card.classList.add('employee-card');
        card.innerHTML = `
            <div class="employee-card-header">${member.name}</div>
            <div class="leave-info">
                <div>
                    <span class="leave-type">Compensatory Off: </span>
                    <span class="leave-count">${member.compensatoryOffTaken}/${member.compensatoryOffAllowed}</span>
                </div>
                <div>
                    <span class="leave-type">Loss of Pay: </span>
                    <span class="leave-count">${member.lossOfPayTaken}/${member.lossOfPayAllowed}</span>
                </div>
                <div>
                    <span class="leave-type">Personal Time Off: </span>
                    <span class="leave-count">${member.personalTimeOffTaken}/${member.personalTimeOffAllowed}</span>
                </div>
                ${member.gender === 'Male' && member.paternityLeaveTaken !== null ?
                `<div>
                    <span class="leave-type">Paternity Leave: </span>
                    <span class="leave-count">${member.paternityLeaveTaken}/9</span>
                </div>`
                : ''}
                ${member.gender === 'Female' && member.maternityLeaveTaken !== null ?
                `<div>
                    <span class="leave-type">Maternity Leave: </span><
                    span class="leave-count">${member.maternityLeaveTaken}/90</>
                </div>`
                : ''}
            </div>
        `;
        teamSummaryContainer.appendChild(card);
    });
}