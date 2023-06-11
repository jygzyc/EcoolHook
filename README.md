# EcoolHook

## Preparing

```bash
pip install frida

# getFridaToolsVersion
curl -sL raw.githubusercontent.com/westinyang/codelabs/master/get-frida-tools-version.sh | bash -s <YourFridaVersion>

pip install frida-tools==<LastStepResult>

pip install objection==1.11.0
pip install hexdump

## initFridaAgent
npm install
```

## Usage 

```bash
# in Frida 15+
# Local conntection and spawn
frida -U -f com.example.app -l _agent.js -o jni.log

# remote connection
frida -H <ip:port> -f com.example.app -l _agent.js -o jni.log
```

## Thanks

- [jtrace](https://github.com/SeeFlowerX/jtrace)
- [frida-onload](https://github.com/iGio90/frida-onload)
- [frida_hook_libart](https://github.com/lasting-yang/frida_hook_libart)
- [get-frida-tools-version](raw.githubusercontent.com/westinyang/codelabs/master/get-frida-tools-version.sh)