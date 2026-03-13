Java.perform(function () {
  function sendSafe(message) {
    try { send(message); } catch (_e) {}
  }

  var suspiciousFiles = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/system/app/Superuser.apk', '/system/bin/busybox', '/system/xbin/busybox', '/sbin/magisk'];
  var suspiciousPackages = ['com.noshufou.android.su', 'com.thirdparty.superuser', 'eu.chainfire.supersu', 'com.topjohnwu.magisk'];
  var suspiciousCommands = ['su', 'which su', 'busybox', 'magisk', 'getprop ro.debuggable', 'getprop ro.secure'];

  try {
    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
      var path = this.getAbsolutePath();
      if (suspiciousFiles.indexOf(path) !== -1) {
        sendSafe('[root_bypass] Hiding file ' + path);
        return false;
      }
      return this.exists();
    };
  } catch (e) {
    sendSafe('[root_bypass] File hook error: ' + e);
  }

  try {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      var lowered = String(cmd).toLowerCase();
      for (var i = 0; i < suspiciousCommands.length; i++) {
        if (lowered.indexOf(suspiciousCommands[i]) !== -1) {
          sendSafe('[root_bypass] Blocking command ' + cmd);
          return this.exec('echo');
        }
      }
      return this.exec(cmd);
    };
  } catch (e) {
    sendSafe('[root_bypass] Runtime.exec hook error: ' + e);
  }

  try {
    var PackageManager = Java.use('android.app.ApplicationPackageManager');
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (name, flags) {
      if (suspiciousPackages.indexOf(String(name)) !== -1) {
        sendSafe('[root_bypass] Hiding package ' + name);
        throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(name);
      }
      return this.getPackageInfo(name, flags);
    };
  } catch (e) {
    sendSafe('[root_bypass] PackageManager hook error: ' + e);
  }

  try {
    var SystemProperties = Java.use('android.os.SystemProperties');
    SystemProperties.get.overload('java.lang.String').implementation = function (name) {
      if (name === 'ro.build.tags') { return 'release-keys'; }
      if (name === 'ro.debuggable') { return '0'; }
      if (name === 'ro.secure') { return '1'; }
      return this.get(name);
    };
  } catch (e) {
    sendSafe('[root_bypass] SystemProperties hook error: ' + e);
  }
});