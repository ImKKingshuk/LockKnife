Java.perform(function () {
  function sendSafe(message) {
    try { send(message); } catch (_e) {}
  }

  function bytesToHex(bytes) {
    if (!bytes) { return null; }
    var out = [];
    for (var i = 0; i < bytes.length && i < 32; i++) {
      var v = (bytes[i] & 0xff).toString(16);
      if (v.length === 1) { v = '0' + v; }
      out.push(v);
    }
    return out.join('');
  }

  function opmodeName(value) {
    if (value === 1) { return 'ENCRYPT'; }
    if (value === 2) { return 'DECRYPT'; }
    if (value === 3) { return 'WRAP'; }
    if (value === 4) { return 'UNWRAP'; }
    return String(value);
  }

  try {
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
      sendSafe('[crypto_intercept] Cipher.init ' + this.getAlgorithm() + ' mode=' + opmodeName(mode));
      return this.init(mode, key);
    };

    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (mode, key, spec) {
      var ivHex = null;
      try {
        ivHex = bytesToHex(Java.cast(spec, IvParameterSpec).getIV());
      } catch (_e) {}
      var keyHex = null;
      try {
        keyHex = bytesToHex(Java.cast(key, SecretKeySpec).getEncoded());
      } catch (_e) {}
      sendSafe('[crypto_intercept] Cipher.init ' + this.getAlgorithm() + ' mode=' + opmodeName(mode) + ' iv=' + ivHex + ' key=' + keyHex);
      return this.init(mode, key, spec);
    };

    Cipher.doFinal.overload('[B').implementation = function (input) {
      sendSafe('[crypto_intercept] Cipher.doFinal ' + this.getAlgorithm() + ' input=' + (input ? input.length : 0));
      return this.doFinal(input);
    };
  } catch (e) {
    sendSafe('[crypto_intercept] Crypto hooks unavailable: ' + e);
  }
});