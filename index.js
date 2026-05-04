```javascript
const crypto = require('crypto');
const readline = require('readline');

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

// Character sets for password generation
const charsets = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numbers: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

class PasswordGenerator {
  constructor() {
    this.generatedPasswords = [];
  }

  // Calculate entropy in bits
  calculateEntropy(passwordLength, charsetSize) {
    if (charsetSize <= 0 || passwordLength <= 0) {
      return 0;
    }
    return Math.log2(Math.pow(charsetSize, passwordLength));
  }

  // Get entropy strength description
  getEntropyStrength(entropy) {
    if (entropy < 30) return { level: 'Very Weak', color: colors.red };
    if (entropy < 50) return { level: 'Weak', color: colors.yellow };
    if (entropy < 80) return { level: 'Fair', color: colors.yellow };
    if (entropy < 120) return { level: 'Strong', color: colors.green };
    return { level: 'Very Strong', color: colors.green };
  }

  // Build character set based on options
  buildCharset(options) {
    let charset = '';
    if (options.lowercase) charset += charsets.lowercase;
    if (options.uppercase) charset += charsets.uppercase;
    if (options.numbers) charset += charsets.numbers;
    if (options.symbols) charset += charsets.symbols;
    return charset;
  }

  // Generate cryptographically secure password
  generate(length, options = {}) {
    const defaultOptions = {
      lowercase: true,
      uppercase: true,
      numbers: true,
      symbols: false,
      excludeAmbiguous: false
    };

    const settings = { ...defaultOptions, ...options };
    const charset = this.buildCharset(settings);

    if (charset.length === 0) {
      throw new Error('At least one character set must be selected');
    }

    if (length < 1) {
      throw new Error('Password length must be at least 1');
    }

    // Exclude ambiguous characters if requested
    let finalCharset = charset;
    if (settings.excludeAmbiguous) {
      finalCharset = charset.replace(/[0OIl1]/g, '');
      if (finalCharset.length === 0) {
        throw new Error('No characters available after excluding ambiguous ones');
      }
    }

    // Generate password using crypto.getRandomValues
    const password = Array.from({ length })
      .map(() => {
        const randomIndex = crypto.randomInt(0, finalCharset.length);
        return finalCharset[randomIndex];
      })
      .join('');

    const entropy = this.calculateEntropy(length, finalCharset.length);
    const strength = this.getEntropyStrength(entropy);

    const passwordInfo = {
      password,
      length,
      entropy: entropy.toFixed(2),
      charsetSize: finalCharset.length,
      strength: strength.level,
      strengthColor: strength.color,
      timestamp: new Date().toISOString()
    };

    this.generatedPasswords.push(passwordInfo);
    return passwordInfo;
  }

  // Generate multiple passwords
  generateMultiple(count, length, options) {
    const passwords = [];
    for (let i = 0; i < count; i++) {
      passwords.push(this.generate(length, options));
    }
    return passwords;
  }

  // Analyze password strength
  analyzePassword(password) {
    let charsetSize = 0;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSymbols = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password);

    if (hasLower) charsetSize += charsets.lowercase.length;
    if (hasUpper) charsetSize += charsets.uppercase.length;
    if (hasNumbers) charsetSize += charsets.numbers.length;
    if (hasSymbols) charsetSize += charsets.symbols.length;

    const entropy = this.calculateEntropy(password.length, charsetSize);
    const strength = this.getEntropyStrength(entropy);

    return {
      password,
      length: password.length,
      entropy: entropy.toFixed(2),
      charsetSize,
      hasLowercase: hasLower,
      hasUppercase: hasUpper,
      hasNumbers,
      hasSymbols,
      strength: strength.level,
      strengthColor: strength.color
    };
  }

  // Print password info in formatted way
  printPasswordInfo(info) {
    console.log(`\n${colors.cyan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`);
    console.log(`${colors.bright}Password:${colors.reset} ${colors.bright}${info.password}${colors.reset}`);
    console.log(`${colors.cyan}Length:${colors.reset} ${info.length}`);