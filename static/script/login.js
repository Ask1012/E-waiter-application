const passwordInput = document.getElementById('password');
const faceElement = document.getElementById('face');
const togglePassword = document.getElementById('toggle-password');

// Function to hide pupils by adding a class to the face element
function hidePupils() {
    faceElement.classList.add('hide-pupils');
}

// Function to show pupils by removing the class
function showPupils() {
    faceElement.classList.remove('hide-pupils');
}

// Event listeners for focus and blur
passwordInput.addEventListener('focus', hidePupils);
passwordInput.addEventListener('blur', showPupils);

// Event listener for toggle password visibility
togglePassword.addEventListener('click', function () {
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);

    // Change the SVG based on the visibility state
    if (type === 'password') {
        this.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" width="24" height="24">
                <path stroke="currentColor" stroke-width="2" d="M12 4.5c-7.5 0-11.5 7.5-11.5 7.5S4.5 19.5 12 19.5s11.5-7.5 11.5-7.5S19.5 4.5 12 4.5z</path>
            <path stroke="currentColor" stroke-width="2" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
            </svg>
        `;
    } else {
        this.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" width="24" height="24">
                <path stroke="currentColor" stroke-width="2" d="M12 4.5c-7.5 0-11.5 7.5-11.5 7.5S4.5 19.5 12 19.5s11.5-7.5 11.5-7.5S19.5 4.5 12 4.5z"/>
                <path stroke="currentColor" stroke-width="2" d="M12 17.5a5.5 5.5 0 1 0 0-11 5.5 5.5 0 0 0 0 11z"/>
                <path stroke="currentColor" stroke-width="2" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
                <path stroke="currentColor" stroke-width="2" d="M3 3l18 18"/>
            </svg>
        `;
    }
});