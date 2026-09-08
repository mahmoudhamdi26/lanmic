# LanMic

Use an Android phone as a wireless microphone for Ubuntu (PipeWire) over Wi-Fi. No ads, no time limits, no Google Play billing.

## Parts

- `lanmic.py` — Ubuntu receiver. Creates a PipeWire input named **LanMic**.
- `android/` — Android app that captures the phone mic and streams it to the PC.
- `web/` — Browser fallback if you do not want the APK.

## Easy install (Ubuntu)

```bash
curl -fsSL https://raw.githubusercontent.com/mahmoudhamdi26/lanmic/main/install.sh | bash
```

That creates a virtualenv, installs Python deps, and enables a systemd user service so LanMic starts at login.

```bash
systemctl --user status lanmic
systemctl --user restart lanmic
# remove the service only:
# ~/.local/share/lanmic/install.sh --uninstall
```

## Ubuntu receiver (manual)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python lanmic.py --default --http-port 8767
```

Then pick **LanMic** as the input in Settings → Sound (and in Discord/OBS).

The phone app uses:

- `ws://PC_IP:8767/ws` for control
- HTTPS on port `8766` for the browser page

## Android app

Open `android/` in Android Studio, or build a debug APK:

```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export ANDROID_HOME="$HOME/Android/Sdk"
cd android
# use your Gradle 8.11+ binary
gradle assembleDebug
```

Sideload the APK. In the app, set the PC IP (for example `192.168.8.81`) and port `8767`, then tap Start.

## License

Use and modify freely for personal use.
