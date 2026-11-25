# Reforge Android Companion (early scaffold)

This app is a remote control and status viewer for a Reforge server running on a computer. It does not perform reverse engineering on the phone itself.

## Build

Requirements: Android Studio with Android SDK 35 and a JDK compatible with Android Gradle Plugin 8.6.1.

Open this `apps/android` directory in Android Studio and build the `app` debug variant, or use an installed Gradle 8.7+ distribution:

```bash
gradle :app:assembleDebug
```

The APK is normally written to `app/build/outputs/apk/debug/app-debug.apk`.

## Connect

1. On the computer, start the API with an allowed workspace folder:

   ```bash
   unirep serve --host 0.0.0.0 --port 8765 --root /path/to/workspace
   ```

2. Keep the computer and phone on the same trusted Wi-Fi network.
3. Enter the computer's LAN IP and the bearer token printed by the server.
4. Browse only the configured allowed folders, choose a file/folder, select engines and start an analysis.

The server defaults to localhost if no host is supplied. LAN mode uses plain HTTP and is intended only for trusted local networks behind a firewall. Never expose this API directly to the public internet. The token is not persisted by the current Android scaffold.

## Current limitations

- This is a first companion scaffold, not a release-ready Android app.
- It controls a computer-hosted Reforge engine; it does not install analysis tools or run heavy jobs on Android.
- The UI does not yet include QR pairing, encrypted token storage, offline history, notifications or APK packaging/signing automation.
