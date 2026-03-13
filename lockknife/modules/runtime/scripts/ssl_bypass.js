Java.perform(function () {
  function sendSafe(message) {
    try { send(message); } catch (_e) {}
  }

  try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
      name: 'com.lockknife.TrustManagerImpl',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function (_chain, _authType) {},
        checkServerTrusted: function (_chain, _authType) {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var TrustManagers = [TrustManager.$new()];
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
      .implementation = function (km, _tm, sr) {
        sendSafe('[ssl_bypass] SSLContext.init overridden');
        return this.init(km, TrustManagers, sr);
      };
  } catch (e) {
    sendSafe('[ssl_bypass] TrustManager hook error: ' + e);
  }

  try {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.checkTrustedRecursive.implementation = function () {
      sendSafe('[ssl_bypass] TrustManagerImpl.checkTrustedRecursive bypassed');
      return Java.use('java.util.ArrayList').$new();
    };
    TrustManagerImpl.verifyChain.implementation = function (chain) {
      sendSafe('[ssl_bypass] TrustManagerImpl.verifyChain bypassed');
      return chain;
    };
  } catch (e) {
    sendSafe('[ssl_bypass] TrustManagerImpl not available: ' + e);
  }

  try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    var overloads = CertificatePinner.check.overloads;
    for (var i = 0; i < overloads.length; i++) {
      overloads[i].implementation = function () {
        sendSafe('[ssl_bypass] OkHttp CertificatePinner.check bypassed');
        return;
      };
    }
  } catch (e) {
    sendSafe('[ssl_bypass] OkHttp not available: ' + e);
  }

  try {
    var WebViewClient = Java.use('android.webkit.WebViewClient');
    WebViewClient.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError')
      .implementation = function (_view, handler, error) {
        sendSafe('[ssl_bypass] WebViewClient SSL error bypassed: ' + error);
        handler.proceed();
      };
  } catch (e) {
    sendSafe('[ssl_bypass] WebViewClient not available: ' + e);
  }

  try {
    var FlutterPinning = Java.use('diefferson.http_certificate_pinning.HttpCertificatePinning');
    FlutterPinning.checkConnexion.implementation = function () {
      sendSafe('[ssl_bypass] Flutter pinning bypassed');
      return true;
    };
  } catch (e) {
    sendSafe('[ssl_bypass] Flutter plugin not available: ' + e);
  }
});