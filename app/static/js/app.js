// GLOBAL STATE
let isKeyAuthorized = false;
let currentHospitalId = null;
const strongCredentialPattern =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/;

async function readApiResponse(response) {
    const responseText = await response.text();

    try {
        return responseText ? JSON.parse(responseText) : {};
    } catch (error) {
        return {
            error: `The server returned an unexpected response (${response.status}).`
        };
    }
}

function getApiError(result, fallback) {
    return result && (result.error || result.message)
        ? (result.error || result.message)
        : fallback;
}

function getPatientField(patientData, fieldName) {
    const matchingKey = Object.keys(patientData).find(
        key => key.toLowerCase() === fieldName.toLowerCase()
    );
    return matchingKey ? patientData[matchingKey] : undefined;
}
// 1. LOGIN / REGISTER PAGE NAVIGATION
function showRegisterPage() {
    document.getElementById('login-page').classList.remove('active');
    document.getElementById('login-page').classList.add('hidden');

    document.getElementById('register-page').classList.remove('hidden');
    document.getElementById('register-page').classList.add('active');

    // Clear previous registration fields
    const form = document.getElementById('register-form');
    if (form) {
        form.reset();
    }
    const resultDiv = document.getElementById('register-result');
    if (resultDiv) {
        resultDiv.classList.add('hidden');
        resultDiv.innerText = '';
    }
}
function showLoginPage() {
    document.getElementById('register-page').classList.remove('active');
    document.getElementById('register-page').classList.add('hidden');
    const setupPage = document.getElementById('secret-key-setup-page');
    if (setupPage) {
        setupPage.classList.remove('active');
        setupPage.classList.add('hidden');
    }
    document.getElementById('login-page').classList.remove('hidden');
    document.getElementById('login-page').classList.add('active');
    const form = document.getElementById('login-form');
    if (form) {
        form.reset();
    }
}
function showSecretKeySetupPage() {
    document.getElementById('register-page').classList.add('hidden');
    document.getElementById('register-page').classList.remove('active');
    document.getElementById('login-page').classList.add('hidden');
    document.getElementById('login-page').classList.remove('active');
    const setupPage = document.getElementById('secret-key-setup-page');
    setupPage.classList.remove('hidden');
    setupPage.classList.add('active');
    document.getElementById('secret-key-setup-form').reset();
}
// 2. HOSPITAL REGISTRATION
async function handleRegister(event) {
    event.preventDefault();
    const hospitalId =
        document.getElementById('register-hospital-id').value.trim();
    const email =
        document.getElementById('register-email').value.trim();
    const password =
        document.getElementById('register-password').value;
    const confirmPassword =
        document.getElementById('register-confirm-password').value;
    const resultDiv =
        document.getElementById('register-result');
    // Clear previous result
    resultDiv.classList.add('hidden');
    resultDiv.innerText = '';
    // ---------------- VALIDATION ----------------
    if (!hospitalId || !email || !password || !confirmPassword) {
        resultDiv.className = "alert error";
        resultDiv.innerText =
            "Please fill in all registration fields.";
        resultDiv.classList.remove('hidden');
        return;
    }
    if (!strongCredentialPattern.test(password)) {
        resultDiv.className = "alert error";
        resultDiv.innerText =
            "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.";
        resultDiv.classList.remove('hidden');
        return;
    }
    if (password !== confirmPassword) {
        resultDiv.className = "alert error";
        resultDiv.innerText =
            "Passwords do not match.";
        resultDiv.classList.remove('hidden');
        return;
    }
    try {
        const response = await fetch('/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                hospital_id: hospitalId,
                email: email,
                password: password
            })
        });
        const result = await readApiResponse(response);
        // ---------------- SUCCESS ----------------
        if (response.ok) {
            resultDiv.className = "alert success";
            resultDiv.innerText =
                result.message ||
                "Hospital registered successfully.";
            resultDiv.classList.remove('hidden');
            showToast(
                "Hospital registered successfully!",
                "success"
            );
            /*
             * Registration is complete.
             *
             * We do NOT automatically log the hospital in.
             * The hospital should now log in using its
             * registered credentials.
             */

            setTimeout(showSecretKeySetupPage, 700);
        }
        // ---------------- ERROR ----------------
        else {
            resultDiv.className = "alert error";
            resultDiv.innerText =
                result.error ||
                "Hospital registration failed.";
            resultDiv.classList.remove('hidden');
        }
    } catch (error) {
        console.error(
            "Registration network error:",
            error
        );
        resultDiv.className = "alert error";
        resultDiv.innerText =
            "Unable to connect to the registration server.";
        resultDiv.classList.remove('hidden');
    }
}
async function handleSecretKeySetup(event) {
    event.preventDefault();
    const secretKey = document.getElementById('setup-secret-key').value;
    const confirmSecretKey = document.getElementById('setup-confirm-secret-key').value;
    const resultDiv = document.getElementById('secret-key-setup-result');
    if (!strongCredentialPattern.test(secretKey)) {
        resultDiv.textContent =
            'Secret key must be at least 8 characters and include uppercase, lowercase, number, and special character.';
        resultDiv.className = 'alert error';
    } else if (secretKey !== confirmSecretKey) {
        resultDiv.textContent = 'Secret keys do not match.';
        resultDiv.className = 'alert error';
    } else {
        try {
            const response = await fetch('/auth/set_secret_key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ secret_key: secretKey, confirm_secret_key: confirmSecretKey })
            });
            const result = await readApiResponse(response);

            if (!response.ok || !result.success) {
                throw new Error(result.error || 'Secret key setup failed.');
            }
            resultDiv.textContent = result.message;
            resultDiv.className = 'alert success';
            setTimeout(showLoginPage, 700);
        } catch (error) {
            resultDiv.textContent = error.message;
            resultDiv.className = 'alert error';
        }
    }
    resultDiv.classList.remove('hidden');
}
// 3. LOGIN
async function handleLogin(event) {
    event.preventDefault();
    const hospitalId =
        document.getElementById('login-hospital-id').value.trim();
    const email =
        document.getElementById('login-email').value.trim();
    const password =
        document.getElementById('login-password').value;
    if (!hospitalId || !email || !password) {
        alert("Please fill in all login fields.");
        return;
    }
    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                hospital_id: hospitalId,
                email: email,
                password: password
            })
        });
        const result = await readApiResponse(response);
        if (response.ok && result.success) {
            currentHospitalId = hospitalId;
            // ---------------- SHOW DASHBOARD ----------------
            document
                .getElementById('login-page')
                .classList.remove('active');
            document
                .getElementById('login-page')
                .classList.add('hidden');
            document
                .getElementById('register-page')
                .classList.remove('active');
            document
                .getElementById('register-page')
                .classList.add('hidden');
            document
                .getElementById('dashboard-container')
                .classList.remove('hidden');
            document
                .getElementById('dashboard-container')
                .classList.add('active');
            // ---------------- UPDATE DASHBOARD ----------------
            document.getElementById('dash-bucket').innerText =
                hospitalId;

            document.getElementById('display-hosp-badge').innerText =
                `Hospital: ${hospitalId}`;

            document.getElementById('upload-hosp-id').value =
                hospitalId;
            // Reset key state after login
            isKeyAuthorized = false;
            updateKeyUI();
            showToast(
                "Successfully logged in!",
                "success"
            );
        }
        else if (result.setup_required) {
            showSecretKeySetupPage();
        }

        else {

            alert(
                "Login failed: " +
                (result.error ||
                 "Invalid hospital credentials")
            );
        }
    } catch (error) {

        console.error(
            "Login network error:",
            error
        );

        alert(
            "An error occurred during login."
        );
    }
}
// 4. LOGOUT
function handleLogout() {
    currentHospitalId = null;
    isKeyAuthorized = false;
    // Hide dashboard
    document
        .getElementById('dashboard-container')
        .classList.remove('active');

    document
        .getElementById('dashboard-container')
        .classList.add('hidden');
    // Show login page
    document
        .getElementById('login-page')
        .classList.remove('hidden');

    document
        .getElementById('login-page')
        .classList.add('active');
    // Reset key state
    updateKeyUI();
    // Clear login fields
    const loginForm =
        document.getElementById('login-form');

    if (loginForm) {
        loginForm.reset();
    }

    showToast(
        "Logged out successfully.",
        "info"
    );
}


// ============================================================
// 5. TAB NAVIGATION
// ============================================================

function switchTab(tabName) {

    // Hide all tabs
    document
        .querySelectorAll('.tab-pane')
        .forEach(pane => {
            pane.classList.remove('active');
        });


    // Deactivate sidebar items
    document
        .querySelectorAll('.sidebar-menu li')
        .forEach(item => {
            item.classList.remove('active');
        });


    // Activate selected tab
    const targetTab =
        document.getElementById(`tab-${tabName}`);

    if (targetTab) {
        targetTab.classList.add('active');
    }


    // Find corresponding sidebar item
    const menuItems =
        document.querySelectorAll('.sidebar-menu li');

    menuItems.forEach(item => {

        const text =
            item.innerText.toLowerCase();

        if (
            (tabName === 'dashboard' && text.includes('dashboard')) ||
            (tabName === 'upload' && text.includes('upload')) ||
            (tabName === 'search' && text.includes('search')) ||
            (tabName === 'add' && text.includes('add patient')) ||
            (tabName === 'update' && text.includes('update')) ||
            (tabName === 'delete' && text.includes('delete'))
        ) {
            item.classList.add('active');
        }

    });


    // Update title
    const titles = {

        dashboard:
            'Dashboard Overview',

        upload:
            'Upload & Encrypt Dataset',

        search:
            'Search Patient Record',

        add:
            'Add New Patient Record',

        update:
            'Update Patient Record',

        delete:
            'Delete Patient Record'

    };


    const titleElement =
        document.getElementById('current-view-title');

    if (titleElement) {

        titleElement.innerText =
            titles[tabName] || 'Dashboard';
    }
}


// ============================================================
// 6. SECRET KEY MODAL
// ============================================================

function openKeyModal() {

    if (!currentHospitalId) {

        alert(
            "Please login before entering the secret key."
        );

        return;
    }


    document
        .getElementById('key-modal')
        .classList.remove('hidden');
}


function closeKeyModal() {

    document
        .getElementById('key-modal')
        .classList.add('hidden');


    document
        .getElementById('modal-secret-key')
        .value = '';


    document
        .getElementById('modal-error')
        .innerText = '';
}


// ============================================================
// 7. VERIFY SECRET KEY
// ============================================================

async function verifySecretKey() {

    const key =
        document
            .getElementById('modal-secret-key')
            .value
            .trim();


    const hospitalId =
        currentHospitalId ||
        document
            .getElementById('login-hospital-id')
            .value
            .trim();


    const errorEl =
        document.getElementById('modal-error');


    if (!key) {

        errorEl.innerText =
            "Please enter your secret key.";

        return;
    }


    if (!hospitalId) {

        errorEl.innerText =
            "Hospital ID is missing.";

        return;
    }


    try {

        const response = await fetch(
            '/auth/verify_key',
            {
                method: 'POST',

                headers: {
                    'Content-Type': 'application/json'
                },

                body: JSON.stringify({
                    hospital_id: hospitalId,
                    secret_key: key
                })
            }
        );


        const result =
            await readApiResponse(response);


        if (response.ok && result.valid) {

            isKeyAuthorized = true;

            updateKeyUI();

            closeKeyModal();


            showToast(
                "Secret key authorized successfully!",
                "success"
            );

        }

        else {

            errorEl.innerText =
                result.error ||
                "Invalid secret key for this hospital.";

            isKeyAuthorized = false;

            updateKeyUI();
        }


    } catch (error) {

        console.error(
            "Key verification error:",
            error
        );

        errorEl.innerText =
            "Server error verifying key.";

    }
}


// ============================================================
// 8. KEY STATUS UI
// ============================================================

function updateKeyUI() {

    const badge =
        document.getElementById('key-status-badge');

    const stateText =
        document.getElementById('dash-key-state');


    if (!badge || !stateText) {
        return;
    }


    if (isKeyAuthorized) {

        badge.className =
            "badge unlocked";

        badge.innerHTML =
            '<i class="fa-solid fa-key"></i> Key Unlocked';

        stateText.innerText =
            "Unlocked / Active";

        stateText.style.color =
            "#2ecc71";

    }

    else {

        badge.className =
            "badge locked";

        badge.innerHTML =
            '<i class="fa-solid fa-key"></i> Key Locked';

        stateText.innerText =
            "Locked";

        stateText.style.color =
            "#e74c3c";
    }
}


// ============================================================
// 9. ACTION PROTECTION
// ============================================================

function promptKeyForAction(event, actionType) {

    if (event && typeof event.preventDefault === 'function') {
        event.preventDefault();
    }


    if (!isKeyAuthorized) {

        alert(
            "Action restricted! Please authorize your Secret Key first."
        );

        openKeyModal();

        return false;
    }


    if (actionType === 'add') {

        handleAddPatient(event);

    }

    else if (actionType === 'update') {

        handleUpdatePatient(event);

    }

    else if (actionType === 'upload') {

        handleUpload(event);

    }

    return false;
}


// ============================================================
// 10. UPLOAD CSV
// ============================================================

async function handleUpload(event) {

    if (event && typeof event.preventDefault === 'function') {
        event.preventDefault();
    }


    if (!isKeyAuthorized) {

        alert(
            "Please authorize your Secret Key first."
        );

        openKeyModal();

        return;
    }


    const hospital_id =
        document
            .getElementById('upload-hosp-id')
            .value;


    const secretKey =
        document
            .getElementById('upload-secret-key')
            .value;


    const fileInput =
        document.getElementById('upload-file');


    if (!fileInput.files.length) {

        alert(
            "Please select a CSV file first."
        );

        return;
    }


    const formData =
        new FormData();


    formData.append(
        'hospital_id',
        hospital_id
    );

    formData.append(
        'secret_key',
        secretKey
    );

    formData.append(
        'file',
        fileInput.files[0]
    );


    const loader =
        document.getElementById('upload-loader');

    const resultDiv =
        document.getElementById('upload-result');


    loader.classList.remove('hidden');
    resultDiv.classList.add('hidden');


    try {

        const response =
            await fetch(
                '/api/upload_csv',
                {
                    method: 'POST',
                    body: formData
                }
            );


        const result =
            await readApiResponse(response);


        loader.classList.add('hidden');

        resultDiv.classList.remove('hidden');


        if (response.ok) {

            resultDiv.className =
                "alert success";

            resultDiv.innerText =
                result.message ||
                "Dataset successfully encrypted and uploaded!";


            document
                .getElementById('upload-form')
                .reset();


            document
                .getElementById('upload-hosp-id')
                .value = hospital_id;

        }

        else {

            resultDiv.className =
                "alert error";

            resultDiv.innerText =
                "Upload failed: " +
                getApiError(result, "The server could not upload the dataset. Please try again.");
        }


    } catch (error) {

        loader.classList.add('hidden');

        resultDiv.classList.remove('hidden');

        resultDiv.className =
            "alert error";


        console.error(
            "Upload error:",
            error
        );


        resultDiv.innerText =
            "Could not upload the dataset. Please check your connection and try again.";
    }
}


// ============================================================
// 11. ADD PATIENT
// ============================================================

async function handleAddPatient(event) {

    if (event && typeof event.preventDefault === 'function') {
        event.preventDefault();
    }


    if (!isKeyAuthorized) {

        alert(
            "Please authorize your Secret Key first."
        );

        openKeyModal();

        return;
    }


    const hospital_id =
        currentHospitalId;


    const patient_id =
        document
            .getElementById('add-pid')
            .value
            .trim();


    const patient_data = {

        name:
            document
                .getElementById('add-name')
                .value,

        age:
            Number(
                document
                    .getElementById('add-age')
                    .value
            ),

        gender:
            document
                .getElementById('add-gender')
                .value,

        disease:
            document
                .getElementById('add-disease')
                .value,

        admission_date:
            document
                .getElementById('add-date')
                .value,

        blood_sugar:
            Number(
                document
                    .getElementById('add-bs')
                    .value
            ),

        heart_rate:
            Number(
                document
                    .getElementById('add-hr')
                    .value
            ),

        temperature:
            Number(
                document
                    .getElementById('add-temp')
                    .value
            ),

        weight:
            Number(
                document
                    .getElementById('add-weight')
                    .value
            ),

        height:
            Number(
                document
                    .getElementById('add-height')
                    .value
            ),

        doctor:
            document
                .getElementById('add-doc')
                .value

    };


    try {

        const response =
            await fetch(
                '/api/add_patient',
                {
                    method: 'POST',

                    headers: {
                        'Content-Type':
                            'application/json'
                    },

                    body: JSON.stringify({
                        hospital_id,
                        patient_id,
                        patient_data
                    })
                }
            );


        const result =
            await readApiResponse(response);


        if (response.ok) {

            showToast(
                "Patient encrypted and stored successfully!",
                "success"
            );


            document
                .getElementById('add-form')
                .reset();

        }

        else {

            alert(
                "Failed to save patient: " +
                getApiError(result, "The server could not save the patient. Please try again.")
            );
        }


    } catch (error) {

        console.error(
            "Add patient error:",
            error
        );

        alert(
            "Could not save the patient. Please check your connection and try again."
        );
    }
}


// ============================================================
// 12. SEARCH PATIENT
// ============================================================

async function searchPatient() {

    if (!isKeyAuthorized) {

        alert(
            "Please authorize your Secret Key first."
        );

        openKeyModal();

        return;
    }


    const patientId =
        document
            .getElementById('search-patient-id')
            .value
            .trim();


    const hospitalId =
        currentHospitalId;


    const container =
        document
            .getElementById(
                'patient-result-container'
            );


    if (!patientId) {

        alert(
            "Please enter a Patient ID."
        );

        return;
    }


    if (!hospitalId) {

        alert(
            "Hospital ID is missing."
        );

        return;
    }


    try {

        const response =
            await fetch(
                `/api/get_patient?hospital_id=${encodeURIComponent(hospitalId)}&patient_id=${encodeURIComponent(patientId)}`
            );


        const result =
            await readApiResponse(response);


        container.classList.remove('hidden');


        if (response.ok) {

            const patientData = result.patient_data || {};

let patientRows = '';

for (const [key, value] of Object.entries(patientData)) {

    const label = key
        .replace(/_/g, ' ')
        .replace(/\b\w/g, char => char.toUpperCase());

    patientRows += `
        <tr>
            <td>${label}</td>
            <td>${value !== null && value !== undefined && value !== ''
                ? value
                : 'Not provided'}
            </td>
        </tr>
    `;
}

container.innerHTML = `

    <div class="patient-card">

        <h3>
            <i class="fa-solid fa-check-circle"></i>
            Patient Record Found
        </h3>

        <table class="patient-table">

            <tr>
                <td>Hospital ID</td>
                <td>${result.hospital_id}</td>
            </tr>

            <tr>
                <td>Patient ID</td>
                <td>${result.patient_id}</td>
            </tr>

            ${patientRows}

        </table>

    </div>

`;

        }

        else {

            container.innerHTML = `

                <p style="color:#ef4444;">
                    ${getApiError(result, "Patient not found. Please check the Patient ID.")}
                </p>

            `;
        }


    } catch (error) {

        console.error(
            "Search error:",
            error
        );


        container.classList.remove('hidden');


        container.innerHTML = `

            <p style="color:#ef4444;">
                Could not search for the patient. Please check your connection and try again.
            </p>

        `;
    }
}


// ============================================================
// 13. LOAD PATIENT FOR UPDATE
// ============================================================

async function loadPatientForUpdate() {

    if (!isKeyAuthorized) {

        alert(
            "Please authorize your Secret Key first."
        );

        openKeyModal();

        return;
    }


    const targetIdElement =
        document.getElementById(
            'update-target-id'
        );


    if (
        !targetIdElement ||
        !targetIdElement.value.trim()
    ) {

        alert(
            "Please enter a Patient ID to load."
        );

        return;
    }


    const targetId =
        targetIdElement.value.trim();


    const hospitalId =
        currentHospitalId;


    try {

        const response =
            await fetch(
                `/api/get_patient?hospital_id=${encodeURIComponent(hospitalId)}&patient_id=${encodeURIComponent(targetId)}`
            );


        const result =
            await readApiResponse(response);


        if (response.ok) {

            const data =
                result.patient_data || {};


            const setValue =
                (id, value) => {

                    const element =
                        document.getElementById(id);

                    if (element) {

                        element.value =
                            value !== undefined &&
                            value !== null
                                ? value
                                : '';
                    }
                };


            setValue(
                'up-disease',
                getPatientField(data, 'disease')
            );

            setValue(
                'up-bs',
                getPatientField(data, 'blood_sugar')
            );

            setValue(
                'up-hr',
                getPatientField(data, 'heart_rate')
            );


            const updateForm =
                document.getElementById(
                    'update-form'
                );


            if (updateForm) {
                updateForm.classList.remove('hidden');
            }


            showToast(
                "Loaded patient data for editing.",
                "success"
            );

        }

        else {

            alert(
                "Patient not found: " +
                getApiError(result, "Check the Patient ID and try again.")
            );
        }


    } catch (error) {

        console.error(
            "Load error:",
            error
        );

        alert(
            "Could not load the patient record. Please check your connection and try again."
        );
    }
}


// ============================================================
// 14. UPDATE PATIENT
// ============================================================

async function handleUpdatePatient(event) {

    if (event && typeof event.preventDefault === 'function') {
        event.preventDefault();
    }


    if (!isKeyAuthorized) {

        alert(
            "Please authorize your Secret Key first."
        );

        openKeyModal();

        return;
    }


    const hospital_id =
        currentHospitalId;


    const patient_id =
        document
            .getElementById('update-target-id')
            .value
            .trim();


    const getNumberValue =
        (id) => {

            const element =
                document.getElementById(id);

            return element &&
                   element.value !== ''
                ? Number(element.value)
                : 0;
        };


    const getValue =
        (id) => {

            const element =
                document.getElementById(id);

            return element
                ? element.value
                : '';
        };


    const patient_data = {

        disease:
            getValue('up-disease'),

        blood_sugar:
            getNumberValue('up-bs'),

        heart_rate:
            getNumberValue('up-hr')

    };


    try {

        const response =
            await fetch(
                '/api/add_patient',
                {
                    method: 'POST',

                    headers: {
                        'Content-Type':
                            'application/json'
                    },

                    body: JSON.stringify({
                        hospital_id,
                        patient_id,
                        patient_data
                    })
                }
            );


        const result =
            await readApiResponse(response);


        if (response.ok) {

            showToast(
                "Patient record updated successfully!",
                "success"
            );


            const updateForm =
                document.getElementById(
                    'update-form'
                );


            if (updateForm) {

                updateForm.classList.add(
                    'hidden'
                );

                updateForm.reset();
            }


            document
                .getElementById(
                    'update-target-id'
                )
                .value = '';

        }

        else {

            alert(
                "Failed to update patient: " +
                getApiError(result, "The server could not update the patient. Please try again.")
            );
        }


    } catch (error) {

        console.error(
            "Update error:",
            error
        );

        alert(
            "Could not update the patient. Please check your connection and try again."
        );
    }
}


// ============================================================
// 15. DELETE PATIENT
// ============================================================

async function confirmDeletePatient() {

    if (!isKeyAuthorized) {

        alert(
            "Action restricted! Please authorize your Secret Key first."
        );

        openKeyModal();

        return;
    }


    const patientId =
        document
            .getElementById('delete-pid')
            .value
            .trim();


    if (!patientId) {

        alert(
            "Please enter a Patient ID to delete."
        );

        return;
    }


    if (
        !confirm(
            `Are you sure you want to permanently delete patient ${patientId}?`
        )
    ) {

        return;
    }


    const hospitalId =
        currentHospitalId;


    try {

        const response =
            await fetch(
                '/api/delete_patient',
                {
                    method: 'DELETE',

                    headers: {
                        'Content-Type':
                            'application/json'
                    },

                    body: JSON.stringify({
                        hospital_id: hospitalId,
                        patient_id: patientId
                    })
                }
            );


        if (response.ok) {

            showToast(
                "Patient record deleted successfully.",
                "success"
            );


            document
                .getElementById('delete-pid')
                .value = '';

        }

        else {

            const result =
                await readApiResponse(response);

            alert(
                "Failed to delete patient: " +
                (result.error ||
                 "Patient not found.")
            );
        }


    } catch (error) {

        console.error(
            "Delete error:",
            error
        );
    }
}


// ============================================================
// 16. TOAST NOTIFICATIONS
// ============================================================

function showToast(
    message,
    type = 'success'
) {

    const toast =
        document.getElementById('toast');


    if (!toast) {
        return;
    }


    toast.innerText =
        message;


    toast.className =
        `toast ${type}`;


    toast.classList.remove(
        'hidden'
    );


    setTimeout(() => {

        toast.classList.add(
            'hidden'
        );

    }, 3500);
}


// ============================================================
// 17. EVENT BINDINGS
// ============================================================

document.addEventListener(
    'DOMContentLoaded',
    () => {

        // ---------------- LOGIN ----------------

        const loginForm =
            document.getElementById(
                'login-form'
            );


        if (loginForm) {

            loginForm.addEventListener(
                'submit',
                handleLogin
            );
        }


        // ---------------- REGISTER ----------------

        const registerForm =
            document.getElementById(
                'register-form'
            );


        if (registerForm) {

            registerForm.addEventListener(
                'submit',
                handleRegister
            );
        }


        // ---------------- ADD PATIENT ----------------

        const addForm =
            document.getElementById(
                'add-form'
            );


        if (addForm) {

            addForm.addEventListener(
                'submit',
                (event) =>
                    promptKeyForAction(
                        event,
                        'add'
                    )
            );
        }


        // ---------------- UPDATE PATIENT ----------------

        const updateForm =
            document.getElementById(
                'update-form'
            );


        if (updateForm) {

            updateForm.addEventListener(
                'submit',
                (event) =>
                    promptKeyForAction(
                        event,
                        'update'
                    )
            );
        }


        // ---------------- UPLOAD ----------------

        const uploadForm =
            document.getElementById(
                'upload-form'
            );


        if (uploadForm) {

            uploadForm.addEventListener(
                'submit',
                (event) =>
                    promptKeyForAction(
                        event,
                        'upload'
                    )
            );
        }


        // ---------------- INITIAL KEY STATE ----------------

        updateKeyUI();

    }
);