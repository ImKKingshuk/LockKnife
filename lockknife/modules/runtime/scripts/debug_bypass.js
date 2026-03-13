Java.perform(function () {
  function sendSafe(message) {
    try { send(message); } catch (_e) {}
  }

  try {
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () {
      sendSafe('[debug_bypass] Debug.isDebuggerConnected -> false');
      return false;
    };
    Debug.waitingForDebugger.implementation = function () {
      sendSafe('[debug_bypass] Debug.waitingForDebugger -> false');
      return false;
    };
  } catch (e) {
    sendSafe('[debug_bypass] Android Debug hooks unavailable: ' + e);
  }

  try {
    var SystemProperties = Java.use('android.os.SystemProperties');
    SystemProperties.get.overload('java.lang.String').implementation = function (name) {
      if (name === 'ro.debuggable') {
        sendSafe('[debug_bypass] ro.debuggable -> 0');
        return '0';
      }
      return this.get(name);
    };
  } catch (e) {
    sendSafe('[debug_bypass] SystemProperties hook error: ' + e);
  }
});

try {
  var ptrace = Module.findExportByName(null, 'ptrace');
  if (ptrace) {
    Interceptor.replace(ptrace, new NativeCallback(function () {
      send('[debug_bypass] ptrace blocked');
      return 0;
    }, 'int', ['int', 'int', 'pointer', 'pointer']));
  }
} catch (e) {
  send('[debug_bypass] Native ptrace hook unavailable: ' + e);
}