const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');
const sqlite3 = require('sqlite3').verbose();
const util = require('util');

// Промисифицируем exec
const execPromise = util.promisify(exec);

// Базовый путь к пользовательским данным Chrome
const CHROME_USER_DATA_PATH = path.join('C:', 'Users', 'user', 'AppData', 'Local', 'Google', 'Chrome', 'User Data');

// Функция для поиска всех профилей Chrome
function findChromeProfiles() {
  try {
    if (!fs.existsSync(CHROME_USER_DATA_PATH)) {
      throw new Error(`Директория ${CHROME_USER_DATA_PATH} не найдена`);
    }
    
    // Читаем содержимое директории
    const items = fs.readdirSync(CHROME_USER_DATA_PATH);
    
    // Отбираем профили - это папки с именами "Default", "Profile 1", "Profile 2" и т.д.
    const profiles = items.filter(item => {
      const itemPath = path.join(CHROME_USER_DATA_PATH, item);
      return fs.statSync(itemPath).isDirectory() && 
             (item === 'Default' || item.startsWith('Profile '));
    });
    
    // Проверяем, содержит ли каждый профиль файл Login Data
    const profilesWithLoginData = profiles.filter(profile => {
      const loginDataPath = path.join(CHROME_USER_DATA_PATH, profile, 'Login Data');
      return fs.existsSync(loginDataPath);
    });
    
    console.log(`Найдено ${profilesWithLoginData.length} профилей с Login Data`);
    return profilesWithLoginData;
  } catch (error) {
    console.error('Ошибка при поиске профилей Chrome:', error.message);
    return [];
  }
}

// Функция для получения реального ключа шифрования Chrome
async function getEncryptionKey() {
  try {
    const localStatePath = path.join(CHROME_USER_DATA_PATH, 'Local State');
    
    if (!fs.existsSync(localStatePath)) {
      throw new Error(`Файл Local State не найден по пути: ${localStatePath}`);
    }
    
    const localStateContent = fs.readFileSync(localStatePath, 'utf8');
    const localState = JSON.parse(localStateContent);
    
    if (!localState.os_crypt || !localState.os_crypt.encrypted_key) {
      throw new Error('Не удалось найти encrypted_key в Local State');
    }
    
    // Получаем закодированный ключ шифрования и декодируем из base64
    const encryptedKey = Buffer.from(localState.os_crypt.encrypted_key, 'base64');
    
    // Удаляем префикс DPAPI (первые 5 байт 'DPAPI')
    const encryptedKeyWithoutPrefix = encryptedKey.slice(5);
    
    // Сохраняем зашифрованный ключ во временный файл
    const tempDir = os.tmpdir();
    const encryptedFile = path.join(tempDir, `chrome_key_encrypted_${Math.random().toString(36).substring(2, 8)}`);
    fs.writeFileSync(encryptedFile, encryptedKeyWithoutPrefix);
    
    // Используем PowerShell для расшифровки через DPAPI
    const psScript = `
    Add-Type -AssemblyName System.Security;
    try {
        $encryptedBytes = [System.IO.File]::ReadAllBytes('${encryptedFile.replace(/\\/g, '\\\\')}');
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $null, 'CurrentUser');
        [System.IO.File]::WriteAllBytes('${encryptedFile}_decrypted', $decrypted);
        Write-Output "Decryption successful";
    } catch {
        Write-Error "Decryption error: $_";
        exit 1;
    }
    `;
    
    const psPath = path.join(tempDir, `decrypt_chrome_key_${Math.random().toString(36).substring(2, 8)}.ps1`);
    fs.writeFileSync(psPath, psScript);
    
    // Запускаем PowerShell скрипт асинхронно
    try {
      await execPromise(`powershell -ExecutionPolicy Bypass -File "${psPath}"`);
    } catch (e) {
      console.error("PowerShell error:", e.message);
      throw new Error("Ошибка выполнения PowerShell скрипта");
    }
    
    // Читаем расшифрованный ключ
    const decryptedKeyPath = `${encryptedFile}_decrypted`;
    if (!fs.existsSync(decryptedKeyPath)) {
      throw new Error('Не удалось создать файл с расшифрованным ключом');
    }
    
    const decryptedKey = fs.readFileSync(decryptedKeyPath);
    
    // Очищаем временные файлы
    try {
      fs.unlinkSync(encryptedFile);
      fs.unlinkSync(decryptedKeyPath);
      fs.unlinkSync(psPath);
    } catch (e) {
      console.warn('Предупреждение: не удалось удалить временные файлы');
    }
    
    console.log('Ключ шифрования успешно получен');
    return decryptedKey;
  } catch (error) {
    console.error('Ошибка при получении ключа шифрования:', error.message);
    throw error;
  }
}

// Функция для расшифровки значения
function decryptValue(encryptedValue, key) {
  try {
    if (!encryptedValue || encryptedValue.length === 0) {
      return '';
    }
    
    // Проверяем, является ли это v10 (формат AES-GCM)
    const isV10 = encryptedValue.length > 3 && 
                  encryptedValue[0] === 118 && // 'v'
                  encryptedValue[1] === 49 &&  // '1'
                  encryptedValue[2] === 48;    // '0'
    
    if (isV10) {
      try {
        // Извлекаем nonce, ciphertext и auth tag
        const nonce = encryptedValue.slice(3, 15);
        const ciphertext = encryptedValue.slice(15, -16);
        const authTag = encryptedValue.slice(-16);
        
        // Создаем AES-GCM расшифровщик
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
        decipher.setAuthTag(authTag);
        
        // Расшифровываем данные
        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString('utf8');
      } catch (e) {
        console.error(`Ошибка расшифровки AES-GCM: ${e.message}`);
        return `[Ошибка расшифровки: ${e.message}]`;
      }
    } else {
      // Для старого формата DPAPI (до v10)
      return `[Encrypted-Legacy: ${encryptedValue.toString('hex').substring(0, 10)}...]`;
    }
  } catch (e) {
    console.error(`Ошибка при расшифровке значения: ${e.message}`);
    return `[Ошибка: ${e.message}]`;
  }
}

// Преобразуем микросекунды с 1601 года в дату
function chromeTimeToDate(chromeTime) {
  if (!chromeTime) return null;
  // Chrome хранит время в микросекундах с 1601-01-01
  const microsecSince1601 = Number(chromeTime);
  // Конвертируем в миллисекунды с 1970-01-01 (Unix epoch)
  const millisecSince1970 = Math.floor(microsecSince1601 / 1000) - 11644473600000;
  
  if (millisecSince1970 < 0) return null;
  return new Date(millisecSince1970).toISOString();
}

// Функция для расшифровки паролей из файла Login Data для одного профиля
async function decryptProfilePasswords(profileName, encryptionKey) {
  const loginDataPath = path.join(CHROME_USER_DATA_PATH, profileName, 'Login Data');
  
  // Проверяем существование файла
  if (!fs.existsSync(loginDataPath)) {
    console.error(`Файл Login Data не найден для профиля ${profileName}`);
    return [];
  }
  
  // Создаем временную копию файла, так как Chrome может блокировать его
  const tempDir = os.tmpdir();
  const tempDbPath = path.join(tempDir, `chrome_login_data_temp_${Math.random().toString(36).substring(2, 8)}`);
  
  try {
    // Копируем файл
    fs.copyFileSync(loginDataPath, tempDbPath);
    console.log(`Файл Login Data для профиля ${profileName} скопирован во временную директорию`);
    
    // Открываем базу данных SQLite
    const db = new sqlite3.Database(tempDbPath);
    
    // Промисифицируем функции для async/await
    const dbAll = util.promisify(db.all.bind(db));
    const dbClose = util.promisify(db.close.bind(db));
    
    // Получаем информацию о столбцах в таблице logins
    const tableInfo = await dbAll("PRAGMA table_info(logins)");
    
    // Проверяем наличие нужных столбцов
    const hasUsernameValue = tableInfo.some(col => col.name === 'username_value');
    const hasPasswordValue = tableInfo.some(col => col.name === 'password_value');
    
    if (!hasUsernameValue || !hasPasswordValue) {
      throw new Error(`В таблице logins профиля ${profileName} отсутствуют необходимые столбцы`);
    }
    
    // Формируем SQL запрос
    const sql = `
      SELECT 
        origin_url, 
        action_url, 
        username_value, 
        password_value,
        date_created,
        date_last_used,
        times_used
      FROM 
        logins
      ORDER BY 
        times_used DESC, 
        date_last_used DESC
    `;
    
    // Выполняем запрос
    const rows = await dbAll(sql);
    console.log(`Найдено ${rows.length} записей паролей в профиле ${profileName}`);
    
    // Расшифровываем пароли
    const decryptedRows = rows.map(row => {
      try {
        const passwordBuffer = Buffer.from(row.password_value);
        const decryptedPassword = decryptValue(passwordBuffer, encryptionKey);
        
        return {
          profile: profileName,
          origin_url: row.origin_url,
          action_url: row.action_url,
          username: row.username_value,
          password: decryptedPassword,
          date_created: chromeTimeToDate(row.date_created),
          date_last_used: chromeTimeToDate(row.date_last_used),
          times_used: row.times_used
        };
      } catch (e) {
        console.error(`Ошибка расшифровки пароля для ${row.origin_url} в профиле ${profileName}:`, e.message);
        return {
          profile: profileName,
          origin_url: row.origin_url,
          action_url: row.action_url,
          username: row.username_value,
          password: `[Ошибка расшифровки: ${e.message}]`,
          date_created: chromeTimeToDate(row.date_created),
          date_last_used: chromeTimeToDate(row.date_last_used),
          times_used: row.times_used
        };
      }
    });
    
    // Закрываем базу данных
    await dbClose();
    
    // Удаляем временный файл
    try {
      fs.unlinkSync(tempDbPath);
      console.log(`Временный файл для профиля ${profileName} удален`);
    } catch (e) {
      console.warn(`Не удалось удалить временный файл для профиля ${profileName}: ${e.message}`);
    }
    
    return decryptedRows;
  } catch (error) {
    console.error(`Ошибка при расшифровке паролей профиля ${profileName}:`, error.message);
    
    // Удаляем временный файл в случае ошибки
    if (fs.existsSync(tempDbPath)) {
      try {
        fs.unlinkSync(tempDbPath);
      } catch (e) {
        console.warn(`Не удалось удалить временный файл для профиля ${profileName}: ${e.message}`);
      }
    }
    
    return []; // Возвращаем пустой массив в случае ошибки
  }
}

// Функция для расшифровки паролей из всех профилей Chrome
async function decryptAllProfilesPasswords() {
  try {
    // Находим все профили с файлами Login Data
    const profiles = findChromeProfiles();
    
    if (profiles.length === 0) {
      console.log('Не найдено профилей с файлами Login Data');
      return null;
    }
    
    // Получаем ключ шифрования (общий для всех профилей)
    const encryptionKey = await getEncryptionKey();
    
    // Массив для хранения всех расшифрованных паролей
    let allPasswords = [];
    
    // Для каждого профиля расшифровываем пароли
    for (const profile of profiles) {
      console.log(`\nОбработка профиля: ${profile}`);
      const profilePasswords = await decryptProfilePasswords(profile, encryptionKey);
      allPasswords = allPasswords.concat(profilePasswords);
    }
    
    // Сортируем все пароли по дате последнего использования
    allPasswords.sort((a, b) => {
      // Сначала по количеству использований (по убыванию)
      if (b.times_used !== a.times_used) {
        return b.times_used - a.times_used;
      }
      
      // Затем по дате последнего использования (по убыванию)
      if (a.date_last_used && b.date_last_used) {
        return new Date(b.date_last_used) - new Date(a.date_last_used);
      }
      
      return 0;
    });
    
    // Сохраняем результаты в один JSON-файл с фиксированным именем
    const outputPath = 'chrome_passwords_result.json';
    fs.writeFileSync(outputPath, JSON.stringify(allPasswords, null, 2), 'utf8');
    console.log(`\nВсе расшифрованные пароли (${allPasswords.length}) сохранены в файл: ${outputPath}`);
    
    return {
      count: allPasswords.length,
      outputPath,
      profiles: profiles,
      passwords: allPasswords
    };
  } catch (error) {
    console.error('Ошибка при расшифровке паролей из всех профилей:', error.message);
    throw error;
  }
}

// Главная функция
async function main() {
  try {
    console.log('===== Расшифровка паролей Chrome из всех профилей =====');
    const result = await decryptAllProfilesPasswords();
    console.log('\n===== Расшифровка завершена =====');
    return result;
  } catch (error) {
    console.error('Критическая ошибка:', error.message);
    process.exit(1);
  }
}

// Запускаем программу
main().catch(error => {
  console.error('Необработанная ошибка:', error);
  process.exit(1);
});
