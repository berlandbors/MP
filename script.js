// === Получаем элементы ===
const serviceName = document.getElementById('serviceName');
const login = document.getElementById('login');
const password = document.getElementById('password');
const savePasswordBtn = document.getElementById('savePasswordBtn');
const generatePasswordBtn = document.getElementById('generatePasswordBtn');
const clearBtn = document.getElementById('clearBtn');
const passwordList = document.getElementById('passwordList');
const modal = document.getElementById('modal');
const modalTitle = document.getElementById('modalTitle');
const modalLogin = document.getElementById('modalLogin');
const modalPassword = document.getElementById('modalPassword');
const deleteBtn = document.getElementById('deleteBtn');
const copyPasswordBtn = document.getElementById('copyPasswordBtn');
const closeModal = document.querySelector('.close');
const usedSpaceElement = document.getElementById('usedSpace');
const warningElement = document.getElementById('warning');
const uploadJsonBtn = document.getElementById('uploadJsonBtn');
const uploadCsvBtn = document.getElementById('uploadCsvBtn');
const downloadJsonBtn = document.getElementById('downloadJsonBtn');
const authScreen = document.getElementById('authScreen');
const authInput = document.getElementById('authInput');
const authSubmitBtn = document.getElementById('authSubmitBtn');
const authError = document.getElementById('authError');
const authTitle = document.getElementById('authTitle');
const searchInput = document.getElementById('searchInput');
const resetBtn = document.getElementById('resetBtn');
const addModal = document.getElementById('addModal');
const openAddModalBtn = document.getElementById('openAddModalBtn');
const closeAddModal = document.querySelector('.closeAddModal');

let currentPasswordIndex = null;
const MAX_STORAGE = 5000;
let masterPassword = "";

// === Мастер-пароль ===
async function digest(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(x => x.toString(16).padStart(2, '0')).join('');
}

function checkMasterPassword() {
  const savedHash = localStorage.getItem('masterHash');
  if (!savedHash) authTitle.textContent = "Установите мастер-пароль";
  authScreen.style.display = 'flex';

  authSubmitBtn.onclick = async () => {
    const input = authInput.value.trim();
    if (!input) return;
    const hash = await digest(input);
    if (!savedHash) {
      localStorage.setItem('masterHash', hash);
      masterPassword = input;
      authScreen.style.display = 'none';
    } else if (hash === savedHash) {
      masterPassword = input;
      authScreen.style.display = 'none';
      loadPasswords();
    } else {
      authError.textContent = "Неверный мастер-пароль!";
    }
  };
}

// === Работа с паролями ===
function generatePassword() {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
  const length = 12;
  password.value = Array.from(crypto.getRandomValues(new Uint32Array(length)))
    .map(x => charset[x % charset.length]).join('');
}

function getPasswords() {
  return JSON.parse(localStorage.getItem('passwords')) || [];
}

function savePasswords(passwords) {
  localStorage.setItem('passwords', JSON.stringify(passwords));
}

function loadPasswords() {
  const passwords = getPasswords();
  const filter = searchInput.value.trim().toLowerCase();
  passwordList.innerHTML = '';
  passwords.forEach((entry, index) => {
    if (!filter || entry.service.toLowerCase().includes(filter)) {
      const li = document.createElement('li');
      li.innerHTML = `<strong>${entry.service}</strong> - ${entry.login}`;
      li.addEventListener('click', () => openPassword(index));
      passwordList.appendChild(li);
    }
  });
  updateStorageStatus();
}

function showAlert(message) {
  const alertBox = document.getElementById('alertMessage');
  alertBox.textContent = message;
  alertBox.style.display = 'block';
  setTimeout(() => alertBox.style.display = 'none', 3000);
}

function showAlert1(message) {
  const alertBox = document.getElementById('alertMessage1');
  if (!alertBox) return;
  alertBox.textContent = message;
  alertBox.style.display = 'block';
  setTimeout(() => alertBox.style.display = 'none', 3000);
}

function savePassword() {
  const service = serviceName.value.trim();
  const userLogin = login.value.trim();
  const userPassword = password.value.trim();

  if (!service || !userLogin || !userPassword) {
    showAlert('Пожалуйста, заполните все поля.');
    return;
  }

  const passwords = getPasswords();
  passwords.push({ service, login: userLogin, password: userPassword });
  savePasswords(passwords);

  serviceName.value = '';
  login.value = '';
  password.value = '';

  loadPasswords();
  showAlert('Новый сервис успешно добавлен!');
  addModal.style.display = 'none';
}

function openPassword(index) {
  const passwords = getPasswords();
  const entry = passwords[index];
  modalTitle.textContent = `Сервис: ${entry.service}`;
  modalLogin.textContent = `Логин: ${entry.login}`;
  modalPassword.textContent = `Пароль: ${entry.password}`;
  modal.style.display = 'block';
  currentPasswordIndex = index;
}

function deletePassword() {
  const passwords = getPasswords();
  passwords.splice(currentPasswordIndex, 1);
  savePasswords(passwords);
  modal.style.display = 'none';
  loadPasswords();
}

function copyPassword() {
  const text = modalPassword.textContent.replace('Пароль: ', '');
  navigator.clipboard.writeText(text).then(() => showAlert('Пароль скопирован!'));
}

function clearFields() {
  serviceName.value = '';
  login.value = '';
  password.value = '';
}

function updateStorageStatus() {
  const sizeBytes = new Blob(Object.values(localStorage)).size;
  const usedKB = (sizeBytes / 1024).toFixed(2);
  usedSpaceElement.textContent = usedKB;
  warningElement.textContent = usedKB >= MAX_STORAGE * 0.8 ? 'Внимание! Почти всё хранилище занято.' : '';
}

// === Шифрование / дешифрование ===
async function deriveKey(password) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey({
    name: "PBKDF2",
    salt: enc.encode("static-salt"),
    iterations: 100000,
    hash: "SHA-256"
  }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function encryptData(data, password) {
  const key = await deriveKey(password);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(data);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  return { iv: Array.from(iv), data: Array.from(new Uint8Array(ciphertext)) };
}

async function decryptData(encrypted, password) {
  const key = await deriveKey(password);
  const iv = new Uint8Array(encrypted.iv);
  const data = new Uint8Array(encrypted.data);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return new TextDecoder().decode(decrypted);
}

// === Загрузка и сохранение JSON ===
async function downloadPasswordsAsJSON() {
  const password = prompt("Введите мастер-пароль для шифрования:");
  if (!password) return;

  const data = JSON.stringify(getPasswords());
  const encrypted = await encryptData(data, password);
  const blob = new Blob([JSON.stringify(encrypted, null, 2)], { type: 'application/json' });

  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'passwords_encrypted.json';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function uploadPasswordsFromJSON(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async function (e) {
    try {
      const encrypted = JSON.parse(e.target.result);
      if (!encrypted.iv || !encrypted.data) {
        showAlert("Файл повреждён или не содержит шифрованных данных.");
        return;
      }

      const password = prompt("Введите мастер-пароль для расшифровки:");
      const decrypted = await decryptData(encrypted, password);
      const imported = JSON.parse(decrypted);

      if (!Array.isArray(imported)) {
        showAlert("Файл расшифрован, но данные некорректны.");
        return;
      }

      const existing = getPasswords();
      const combined = [...existing];
      imported.forEach(newEntry => {
        const duplicate = existing.find(e => e.service === newEntry.service && e.login === newEntry.login);
        if (!duplicate) combined.push(newEntry);
      });

      savePasswords(combined);
      loadPasswords();
      showAlert("Пароли успешно загружены!");
    } catch (err) {
      console.error("Ошибка при загрузке:", err);
      showAlert("Ошибка расшифровки. Проверьте пароль или целостность файла.");
    }
  };
  reader.readAsText(file);
}

// === Импорт CSV из Chrome ===
function handleChromeCSVUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (e) {
    const text = e.target.result;
    const lines = text.split('\n').slice(1); // пропускаем заголовок
    const newEntries = [];

    for (let line of lines) {
      if (!line.trim()) continue;

      const parts = line.split(',').map(x => x.replace(/^"|"$/g, '').trim());
      if (parts.length < 4) continue;

      const [name, , username, pass] = parts;

      if (name && username && pass) {
        newEntries.push({ service: name, login: username, password: pass });
      }
    }

    if (newEntries.length === 0) {
      showAlert("Файл CSV пуст или в неправильном формате.");
      return;
    }

    const existing = getPasswords();
    const combined = [...existing];
    newEntries.forEach(entry => {
      const duplicate = existing.find(e => e.service === entry.service && e.login === entry.login);
      if (!duplicate) combined.push(entry);
    });

    savePasswords(combined);
    loadPasswords();
    showAlert("Пароли из Chrome успешно загружены!");
  };

  reader.readAsText(file);
}

// === Обработчики событий ===
closeModal.addEventListener('click', () => modal.style.display = 'none');
window.addEventListener('click', e => {
  if (e.target === modal) modal.style.display = 'none';
});
generatePasswordBtn.addEventListener('click', generatePassword);
savePasswordBtn.addEventListener('click', savePassword);
clearBtn.addEventListener('click', clearFields);
deleteBtn.addEventListener('click', deletePassword);
copyPasswordBtn.addEventListener('click', copyPassword);
uploadJsonBtn.addEventListener('change', uploadPasswordsFromJSON);
uploadCsvBtn.addEventListener('change', handleChromeCSVUpload);
downloadJsonBtn.addEventListener('click', downloadPasswordsAsJSON);
resetBtn.addEventListener('click', () => {
  if (confirm("Удалить все данные? Это действие необратимо.")) {
    localStorage.clear();
    location.reload();
  }
});
searchInput.addEventListener('input', loadPasswords);

openAddModalBtn.addEventListener('click', () => {
  addModal.style.display = 'flex';
});
closeAddModal.addEventListener('click', () => {
  addModal.style.display = 'none';
});
window.addEventListener('click', e => {
  if (e.target === addModal) addModal.style.display = 'none';
});

// === PWA: Установка и обновление приложения ===
let deferredPrompt;
let swRegistration = null;

const installBtn = document.getElementById('installBtn');
const updateBtn = document.getElementById('updateBtn');

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  installBtn.style.display = 'inline-block';
});

installBtn.addEventListener('click', async () => {
  if (!deferredPrompt) return;

  deferredPrompt.prompt();
  const { outcome } = await deferredPrompt.userChoice;

  if (outcome === 'accepted') {
    showAlert('Приложение успешно установлено!');
  }

  deferredPrompt = null;
  installBtn.style.display = 'none';
});

window.addEventListener('appinstalled', () => {
  deferredPrompt = null;
  installBtn.style.display = 'none';
  showAlert('Приложение установлено! Теперь оно доступно на вашем устройстве.');
});

// Перезагрузка после активации нового SW (регистрируется один раз)
if ('serviceWorker' in navigator) {
  let refreshing = false;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (!refreshing) {
      refreshing = true;
      window.location.reload();
    }
  });
}

updateBtn.addEventListener('click', () => {
  if (!swRegistration || !swRegistration.waiting) return;

  swRegistration.waiting.postMessage({ type: 'SKIP_WAITING' });

  updateBtn.style.display = 'none';
  showAlert('Обновление применяется...');
});

// Регистрация Service Worker
if ('serviceWorker' in navigator) {
  window.addEventListener('load', async () => {
    try {
      swRegistration = await navigator.serviceWorker.register('service-worker.js');

      const updateIntervalId = setInterval(() => {
        swRegistration.update();
      }, 60000);

      window.addEventListener('beforeunload', () => clearInterval(updateIntervalId));

      swRegistration.addEventListener('updatefound', () => {
        const newWorker = swRegistration.installing;
        if (!newWorker) return;

        newWorker.addEventListener('statechange', () => {
          if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
            updateBtn.style.display = 'inline-block';
            showAlert('Доступно обновление приложения!');
          }
        });
      });
    } catch (err) {
      console.warn('Service Worker registration failed:', err);
    }
  });
}

// === Инициализация ===
window.addEventListener('load', () => {
  checkMasterPassword();
});